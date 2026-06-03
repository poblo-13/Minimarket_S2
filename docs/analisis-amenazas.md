# Análisis de amenazas de seguridad — MiniMarket Plus (Backend)

> Asignatura: Desarrollo Backend II (PBY2202) · Semana 3 · RA1
> Contexto: API REST stateless (Spring Boot 3.4.1, Java 17, JWT HS256, BCrypt, H2).
> Roles del dominio: **CLIENTE**, **EMPLEADO**, **GERENTE**.

El backend de MiniMarket Plus gestiona datos sensibles: cuentas de usuario y sus
hashes de contraseña, catálogo de productos, inventario por sucursal, carritos,
ventas y detalle de ventas. Varios de estos datos son **datos personales** sujetos
a la **Ley 19.628** (Protección de la Vida Privada) y a su reforma por la
**Ley 21.719** (2024), que endurece el tratamiento de datos personales en Chile y
crea la Agencia de Protección de Datos. Una brecha implica impacto legal
(sanciones), reputacional y económico.

## Tabla de amenazas → componente → impacto → mitigación

| # | Amenaza | Componente de MiniMarket afectado | Impacto (incl. legal) | Mitigación implementada |
|---|---------|-----------------------------------|-----------------------|--------------------------|
| 1 | **SQL Injection** | `POST /auth/login`, `/api/usuarios`, `/api/productos` (cualquier consulta por dato del usuario) | Robo/alteración/borrado de datos de clientes y ventas. Infracción Ley 19.628/21.719 por exposición de datos personales | Spring Data JPA con consultas **parametrizadas** (`findByUsername`), sin concatenación de strings SQL |
| 2 | **XSS almacenado** | Campos de texto persistidos vía `POST/PUT` (p. ej. `nombre` de Producto/Categoria) | Si un cliente web renderiza el dato sin escapar, robo de sesión del consumidor | API responde **siempre `application/json`** (el navegador no ejecuta `<script>` en JSON) + **validación de entrada** `@Valid` (longitud + rechazo de `<`/`>`) + cabecera **CSP `default-src 'self'`** como defensa en profundidad |
| 3 | **CSRF** | Operaciones de escritura `/api/**` | Ejecución de acciones no autorizadas en nombre del usuario | API **stateless**: el token JWT viaja en el header `Authorization`, **no en cookie de sesión**, por lo que un sitio externo no puede forzar la credencial. `csrf.disable()` queda **justificado por diseño** |
| 4 | **Acceso no autorizado entre roles** (escalamiento de privilegios) | Todos los `/api/**` (p. ej. un CLIENTE accediendo a `/api/usuarios` o `/api/ventas`) | Fuga de datos personales/financieros, escalamiento de privilegios. Infracción Ley 19.628/21.719 | **Doble candado**: filtro de URL por rol/método en `SecurityConfig` + `@PreAuthorize` en cada controlador + handlers **401/403 JSON**. `hasAuthority`/`hasAnyAuthority` coherentes con las authorities sin prefijo |
| 5 | **Robo / manipulación del token JWT** | Login y cada petición autenticada | Suplantación de identidad de cualquier rol | Firma **HS256** con `signWith(secretKey, Jwts.SIG.HS256)`, verificación con `verifyWith`, **expiración** configurable; un token alterado falla la firma → 401 |
| 6 | **Secreto JWT débil / quemado en código** | `JwtUtil` (clave de firma) | Falsificación masiva de tokens si la clave es adivinable o pública | Secreto leído de **variable de entorno (`.env`)**, **validado al arrancar** (`>= 32 bytes`, si no lanza `IllegalStateException`); `.env` **no versionado** |
| 7 | **Fuga de credenciales / hash de contraseña** | Login/registro, logs, DTOs de respuesta | Robo de contraseñas, infracción de la Ley de Datos | **BCrypt** en runtime (nunca texto plano ni hash quemado), DTOs que **no exponen** el hash, **eliminado** el `println` que filtraba el hash de debug |
| 8 | **Fuerza bruta / actividad sospechosa** | `POST /auth/login` | Compromiso de cuentas por prueba masiva de contraseñas | **Monitoreo `SecurityAuditLogger`**: registra logins fallidos, tokens inválidos y accesos 403 a nivel WARN; **contador por IP** que alerta `POSIBLE_FUERZA_BRUTA` al superar el umbral |
| 9 | **Exposición de la consola H2** | `/h2-console` (acceso directo a la BD) | Lectura/escritura directa de toda la base de datos, evadiendo la lógica de negocio | **Deshabilitada por defecto** (`spring.h2.console.enabled=false`); solo se reactiva bajo el **perfil `dev`** con una `SecurityFilterChain` separada limitada a `/h2-console/**` |

## Notas de cumplimiento legal (Ley 19.628 / 21.719)

- **Minimización de datos**: los DTOs (`UsuarioDTO`, `AuthResponse`) exponen solo lo
  necesario; nunca el hash de la contraseña.
- **Seguridad de los datos tratados**: hash BCrypt, control de acceso por rol, secreto
  en variable de entorno y monitoreo de accesos sospechosos.
- **Trazabilidad**: el logger `SECURITY_AUDIT` deja registro de eventos de seguridad
  (sin volcar contraseñas ni el token completo), insumo para responder ante incidentes.
