package co.darpidev.apigatewaylostobjects.security;

import co.darpidev.apigatewaylostobjects.shared.Result;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

/**
 * Adapter: encapsula la librería JJWT detrás de {@link TokenValidator}. La clave y el parser
 * se construyen una sola vez al arrancar (antes se recreaban en cada petición); si el secreto
 * es demasiado corto el servicio falla al iniciar en lugar de rechazar todo el tráfico.
 */
@Component
public class JjwtTokenValidator implements TokenValidator {

    private final JwtParser parser;

    public JjwtTokenValidator(@Value("${jwt.secret}") String secret) {
        this.parser = Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)))
                .build();
    }

    @Override
    public Result<AuthenticatedUser> validate(String token) {
        try {
            Claims claims = parser.parseSignedClaims(token).getPayload();
            return Result.success(new AuthenticatedUser(
                    String.valueOf(claims.get("userId")),
                    claims.getSubject(),
                    String.valueOf(claims.get("role")),
                    String.valueOf(claims.get("campusId"))));
        } catch (JwtException | IllegalArgumentException e) {
            return Result.failure(AuthErrors.invalidToken());
        }
    }
}
