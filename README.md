# api-gateway

Punto de entrada único (Server-Side) de *Lost Objects*. Valida el JWT, propaga la identidad a los microservicios y los localiza por Eureka (`lb://NOMBRE`) con balanceo Round Robin.

## Estructura del filtro de seguridad

| Pieza | Patrón | Responsabilidad |
|---|---|---|
| `JwtAuthenticationFilter` | Chain of Responsibility (cadena de filtros de Spring Cloud Gateway) | Orquesta; no contiene lógica de JWT |
| `TokenValidator` / `JjwtTokenValidator` | Strategy + Adapter | Valida el token; JJWT queda aislado |
| `BearerTokenExtractor` | — | Lee `Authorization: Bearer …` |
| `PublicPathPolicy` + `gateway.security.public-paths` | Strategy (política configurable) | Rutas que no requieren token |
| `UserHeadersPropagator` | — | Limpia/propaga `X-User-*` |
| `Result` / `AppError` | Result (ROP) | Token ausente o inválido sin excepciones |

## Configuración

- `JWT_SECRET` (mínimo 32 bytes), `EUREKA_URL`.
- Rutas públicas: `gateway.security.public-paths` en `application.yaml`.
- Reintentos: solo `GET`, 2 veces, ante 502/503/504 (pasa a otra instancia).
