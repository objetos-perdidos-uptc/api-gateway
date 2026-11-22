package co.darpidev.apigatewaylostobjects.security;

/** Identidad extraída del JWT que se propaga a los microservicios como cabeceras X-User-*. */
public record AuthenticatedUser(String userId, String email, String role, String campusId) {
}
