package co.darpidev.apigatewaylostobjects.security;

import co.darpidev.apigatewaylostobjects.shared.Result;

/** Extrae el token de la cabecera Authorization: Bearer ... */
public final class BearerTokenExtractor {

    private static final String PREFIX = "Bearer ";

    private BearerTokenExtractor() {
    }

    public static Result<String> extract(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith(PREFIX)) {
            return Result.failure(AuthErrors.missingToken());
        }
        String token = authorizationHeader.substring(PREFIX.length()).trim();
        return token.isEmpty() ? Result.failure(AuthErrors.missingToken()) : Result.success(token);
    }
}
