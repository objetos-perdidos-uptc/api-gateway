package co.darpidev.apigatewaylostobjects.filter;

import co.darpidev.apigatewaylostobjects.security.AuthenticatedUser;
import co.darpidev.apigatewaylostobjects.security.BearerTokenExtractor;
import co.darpidev.apigatewaylostobjects.security.PublicPathPolicy;
import co.darpidev.apigatewaylostobjects.security.TokenValidator;
import co.darpidev.apigatewaylostobjects.security.UserHeadersPropagator;
import co.darpidev.apigatewaylostobjects.shared.AppError;
import co.darpidev.apigatewaylostobjects.shared.ErrorType;
import co.darpidev.apigatewaylostobjects.shared.Result;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

/**
 * Eslabón de la cadena de filtros del gateway (Chain of Responsibility, ya provista por Spring
 * Cloud Gateway). Solo orquesta: la política de rutas, la extracción del token, su validación y
 * la propagación de cabeceras viven en colaboradores con una única responsabilidad.
 */
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final PublicPathPolicy publicPaths;
    private final TokenValidator tokenValidator;
    private final UserHeadersPropagator headers;

    public JwtAuthenticationFilter(PublicPathPolicy publicPaths,
                                   TokenValidator tokenValidator,
                                   UserHeadersPropagator headers) {
        this.publicPaths = publicPaths;
        this.tokenValidator = tokenValidator;
        this.headers = headers;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        if (publicPaths.isPublic(request.getPath().value())) {
            return chain.filter(exchange.mutate().request(headers.strip(request)).build());
        }

        Result<AuthenticatedUser> authentication =
                BearerTokenExtractor.extract(request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
                        .bind(tokenValidator::validate);

        return authentication.match(
                user -> chain.filter(exchange.mutate().request(headers.propagate(request, user)).build()),
                error -> reject(exchange, error));
    }

    private Mono<Void> reject(ServerWebExchange exchange, AppError error) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(toStatus(error.type()));
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        response.getHeaders().set(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        byte[] body = ("{\"code\":\"" + error.code() + "\",\"message\":\"" + error.message() + "\"}")
                .getBytes(StandardCharsets.UTF_8);
        return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
    }

    private static HttpStatus toStatus(ErrorType type) {
        return switch (type) {
            case UNAUTHORIZED -> HttpStatus.UNAUTHORIZED;
            case NONE -> HttpStatus.INTERNAL_SERVER_ERROR;
        };
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
