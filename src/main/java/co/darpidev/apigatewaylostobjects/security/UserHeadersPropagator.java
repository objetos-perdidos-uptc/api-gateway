package co.darpidev.apigatewaylostobjects.security;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

/**
 * Construye la petición que se reenvía a los microservicios. Siempre elimina las cabeceras
 * X-User-* que venga del cliente, para que nadie pueda suplantar su identidad.
 */
@Component
public class UserHeadersPropagator {

    static final String USER_ID = "X-User-Id";
    static final String USER_EMAIL = "X-User-Email";
    static final String USER_ROLE = "X-User-Role";
    static final String USER_CAMPUS_ID = "X-User-CampusId";

    /** Petición autenticada: limpia las cabeceras del cliente y añade las del usuario verificado. */
    public ServerHttpRequest propagate(ServerHttpRequest request, AuthenticatedUser user) {
        return request.mutate()
                .headers(this::removeIdentityHeaders)
                .header(USER_ID, user.userId())
                .header(USER_EMAIL, user.email())
                .header(USER_ROLE, user.role())
                .header(USER_CAMPUS_ID, user.campusId())
                .build();
    }

    /** Petición pública: solo limpia cabeceras de identidad que el cliente intente inyectar. */
    public ServerHttpRequest strip(ServerHttpRequest request) {
        return request.mutate().headers(this::removeIdentityHeaders).build();
    }

    private void removeIdentityHeaders(org.springframework.http.HttpHeaders headers) {
        headers.remove(USER_ID);
        headers.remove(USER_EMAIL);
        headers.remove(USER_ROLE);
        headers.remove(USER_CAMPUS_ID);
    }
}
