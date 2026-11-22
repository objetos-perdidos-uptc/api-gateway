package co.darpidev.apigatewaylostobjects.shared;

/** Error estructurado: código estable, mensaje y tipo (el filtro lo traduce a HTTP). */
public record AppError(String code, String message, ErrorType type) {

    public static final AppError NONE = new AppError("", "", ErrorType.NONE);
}
