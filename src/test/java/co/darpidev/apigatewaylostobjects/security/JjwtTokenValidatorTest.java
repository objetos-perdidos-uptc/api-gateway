package co.darpidev.apigatewaylostobjects.security;

import co.darpidev.apigatewaylostobjects.shared.Result;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

class JjwtTokenValidatorTest {

    private static final String SECRET = "0123456789abcdef0123456789abcdef";
    private static final String OTHER_SECRET = "fedcba9876543210fedcba9876543210";

    private final JjwtTokenValidator validator = new JjwtTokenValidator(SECRET);

    private String token(String secret, long expiresInMillis) {
        return Jwts.builder()
                .subject("ana@uptc.edu.co")
                .claim("userId", 7L)
                .claim("role", "STUDENT")
                .claim("campusId", 3L)
                .expiration(new Date(System.currentTimeMillis() + expiresInMillis))
                .signWith(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)), Jwts.SIG.HS256)
                .compact();
    }

    @Test
    void validTokenYieldsAuthenticatedUser() {
        Result<AuthenticatedUser> result = validator.validate(token(SECRET, 60_000));

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getValue()).isEqualTo(new AuthenticatedUser("7", "ana@uptc.edu.co", "STUDENT", "3"));
    }

    @Test
    void tokenSignedWithAnotherKeyIsRejected() {
        assertThat(validator.validate(token(OTHER_SECRET, 60_000)).getError()).isEqualTo(AuthErrors.invalidToken());
    }

    @Test
    void expiredTokenIsRejected() {
        assertThat(validator.validate(token(SECRET, -60_000)).getError()).isEqualTo(AuthErrors.invalidToken());
    }

    @Test
    void garbageIsRejectedWithoutThrowing() {
        assertThat(validator.validate("esto-no-es-un-jwt").getError()).isEqualTo(AuthErrors.invalidToken());
    }
}
