package co.darpidev.apigatewaylostobjects.security;

import co.darpidev.apigatewaylostobjects.shared.Result;

/**
 * Strategy: la forma de validar un token es intercambiable (JWT HS256 hoy; RS256 con JWKS,
 * introspección OAuth2, etc. mañana) sin tocar el filtro.
 */
public interface TokenValidator {

    Result<AuthenticatedUser> validate(String token);
}
