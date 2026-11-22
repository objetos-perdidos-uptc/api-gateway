package co.darpidev.apigatewaylostobjects.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/** Rutas públicas configurables (gateway.security.public-paths): abrir una ruta ya no requiere recompilar. */
@ConfigurationProperties(prefix = "gateway.security")
public record GatewaySecurityProperties(List<String> publicPaths) {

    public GatewaySecurityProperties {
        publicPaths = publicPaths == null ? List.of() : List.copyOf(publicPaths);
    }
}
