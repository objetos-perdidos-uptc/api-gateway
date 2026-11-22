package co.darpidev.apigatewaylostobjects.shared;

import java.util.Objects;
import java.util.function.Function;

/**
 * Patrón Result: un token ausente o inválido es un resultado esperado, no una excepción.
 * (Misma implementación que en auth-service; cada servicio es independiente, sin librería compartida.)
 */
public final class Result<T> {

    private final T value;
    private final AppError error;

    private Result(T value, AppError error) {
        this.value = value;
        this.error = error;
    }

    public static <T> Result<T> success(T value) {
        return new Result<>(value, AppError.NONE);
    }

    public static <T> Result<T> failure(AppError error) {
        Objects.requireNonNull(error, "error");
        if (error == AppError.NONE || error.type() == ErrorType.NONE) {
            throw new IllegalArgumentException("Un fallo requiere un error distinto de NONE");
        }
        return new Result<>(null, error);
    }

    public boolean isSuccess() {
        return error == AppError.NONE;
    }

    public boolean isFailure() {
        return !isSuccess();
    }

    public T getValue() {
        if (isFailure()) {
            throw new IllegalStateException("No se puede leer el valor de un Result fallido: " + error.code());
        }
        return value;
    }

    public AppError getError() {
        return error;
    }

    public <R> Result<R> map(Function<? super T, ? extends R> mapper) {
        return isSuccess() ? Result.success(mapper.apply(value)) : Result.failure(error);
    }

    public <R> Result<R> bind(Function<? super T, Result<R>> next) {
        return isSuccess() ? next.apply(value) : Result.failure(error);
    }

    public <R> R match(Function<? super T, ? extends R> onSuccess,
                       Function<AppError, ? extends R> onFailure) {
        return isSuccess() ? onSuccess.apply(value) : onFailure.apply(error);
    }
}
