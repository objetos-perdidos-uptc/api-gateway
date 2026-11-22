package co.darpidev.apigatewaylostobjects.security;

import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.List;

/** Política de acceso: decide si una ruta puede atravesar el gateway sin autenticación. */
@Component
public class PublicPathPolicy {

    private final List<String> patterns;
    private final AntPathMatcher matcher = new AntPathMatcher();

    public PublicPathPolicy(GatewaySecurityProperties properties) {
        this.patterns = properties.publicPaths();
    }

    public boolean isPublic(String path) {
        String normalized = path.length() > 1 && path.endsWith("/")
                ? path.substring(0, path.length() - 1)
                : path;
        return patterns.stream().anyMatch(pattern -> matcher.match(pattern, normalized));
    }
}
