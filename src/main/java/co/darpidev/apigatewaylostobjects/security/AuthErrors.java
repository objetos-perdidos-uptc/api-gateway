package co.darpidev.apigatewaylostobjects.security;

import co.darpidev.apigatewaylostobjects.shared.AppError;
import co.darpidev.apigatewaylostobjects.shared.ErrorType;

/** Catálogo de errores de autenticación del gateway (mensajes sin comillas: se escriben en JSON). */
public final class AuthErrors {

    private AuthErrors() {
    }

    public static AppError missingToken() {
        return new AppError("Auth.MissingToken", "Falta el token de autenticación", ErrorType.UNAUTHORIZED);
    }

    public static AppError invalidToken() {
        return new AppError("Auth.InvalidToken", "Token inválido o expirado", ErrorType.UNAUTHORIZED);
    }
}
