package co.darpidev.apigatewaylostobjects.filter;

import co.darpidev.apigatewaylostobjects.security.GatewaySecurityProperties;
import co.darpidev.apigatewaylostobjects.security.JjwtTokenValidator;
import co.darpidev.apigatewaylostobjects.security.PublicPathPolicy;
import co.darpidev.apigatewaylostobjects.security.UserHeadersPropagator;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class JwtAuthenticationFilterTest {

    private static final String SECRET = "0123456789abcdef0123456789abcdef";

    private final JwtAuthenticationFilter filter = new JwtAuthenticationFilter(
            new PublicPathPolicy(new GatewaySecurityProperties(List.of("/auth/login", "/auth/register"))),
            new JjwtTokenValidator(SECRET),
            new UserHeadersPropagator());

    private final AtomicReference<ServerWebExchange> forwarded = new AtomicReference<>();
    private final GatewayFilterChain chain = exchange -> {
        forwarded.set(exchange);
        return Mono.empty();
    };

    private String validToken() {
        return Jwts.builder()
                .subject("ana@uptc.edu.co")
                .claim("userId", 7L)
                .claim("role", "STUDENT")
                .claim("campusId", 3L)
                .expiration(new Date(System.currentTimeMillis() + 60_000))
                .signWith(Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8)), Jwts.SIG.HS256)
                .compact();
    }

    @Test
    void publicRouteIsForwardedWithoutTokenAndSpoofedHeadersAreStripped() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/auth/login").header("X-User-Role", "ADMIN").build());

        filter.filter(exchange, chain).block();

        assertThat(forwarded.get()).isNotNull();
        assertThat(forwarded.get().getRequest().getHeaders().containsHeader("X-User-Role")).isFalse();
    }

    @Test
    void protectedRouteWithoutTokenIsRejectedAndNotForwarded() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/claims/1").build());

        filter.filter(exchange, chain).block();

        assertThat(forwarded.get()).isNull();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void protectedRouteWithInvalidTokenIsRejected() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/claims/1").header("Authorization", "Bearer basura").build());

        filter.filter(exchange, chain).block();

        assertThat(forwarded.get()).isNull();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void validTokenIsForwardedWithVerifiedIdentityHeadersOverridingSpoofedOnes() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/claims/1")
                        .header("Authorization", "Bearer " + validToken())
                        .header("X-User-Role", "ADMIN")
                        .build());

        filter.filter(exchange, chain).block();

        var headers = forwarded.get().getRequest().getHeaders();
        assertThat(headers.getFirst("X-User-Id")).isEqualTo("7");
        assertThat(headers.getFirst("X-User-Email")).isEqualTo("ana@uptc.edu.co");
        assertThat(headers.get("X-User-Role")).containsExactly("STUDENT");
        assertThat(headers.getFirst("X-User-CampusId")).isEqualTo("3");
    }
}
