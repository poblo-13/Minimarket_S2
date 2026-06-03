# Pruebas de seguridad — MiniMarket Plus (Backend)

> Asignatura: Desarrollo Backend II (PBY2202) · Semana 3 · RA1

Pruebas que demuestran la protección frente a amenazas comunes. Las pruebas
**T1–T7** son manuales (curl) y se complementan con la batería **automatizada**
`SecurityRulesTest` (18 tests verdes, ver al final), que es evidencia ejecutada de
la matriz rol×endpoint.

Prerrequisito para las pruebas manuales: levantar la app en Docker JDK17 y obtener
tokens por rol.

```bash
# Levantar (perfil por defecto = JWT)
docker run --rm -p 8080:8080 -v "$PWD":/app -v "$HOME/.m2":/root/.m2 \
  -w /app maven:3.9-eclipse-temurin-17 mvn -q spring-boot:run

# Tokens por rol (login devuelve {"token":...})
TGER=$(curl -s -X POST localhost:8080/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"12345"}'    | sed 's/.*"token":"\([^"]*\)".*/\1/')
TEMP=$(curl -s -X POST localhost:8080/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"empleado","password":"12345"}' | sed 's/.*"token":"\([^"]*\)".*/\1/')
TCLI=$(curl -s -X POST localhost:8080/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"cliente","password":"12345"}'  | sed 's/.*"token":"\([^"]*\)".*/\1/')
```

## Tabla de pruebas T1–T7

| # | Amenaza | Ataque (comando) | Resultado esperado (protegido) |
|---|---------|------------------|--------------------------------|
| **T1** | SQL Injection | `curl -i -X POST localhost:8080/auth/login -H 'Content-Type: application/json' -d '{"username":"admin'"'"' OR '"'"'1'"'"'='"'"'1","password":"x"}'` | **401** — JPA parametriza, no hay bypass de autenticación |
| **T2** | XSS almacenado | `curl -i -X POST localhost:8080/api/categorias -H "Authorization: Bearer $TGER" -H 'Content-Type: application/json' -d '{"nombre":"<script>alert(1)</script>"}'` | **400** (la validación `@Pattern` rechaza `<`/`>`). Las respuestas son `Content-Type: application/json` y la cabecera `Content-Security-Policy: default-src 'self'` está presente: el navegador no ejecuta scripts en JSON. Mitigación = contrato JSON + validación de entrada + CSP |
| **T3** | CSRF | `curl -i -X POST localhost:8080/api/categorias -H 'Content-Type: application/json' -d '{"nombre":"x"}'` (sin token, simulando otro origen) | **401** — no hay cookie de sesión; la credencial va en el header `Authorization`. `csrf.disable()` justificado por diseño stateless |
| **T4** | Acceso sin token | `curl -i localhost:8080/api/usuarios` | **401 JSON** `{"status":401,"error":"No autenticado",...}` (RestAuthEntryPoint) |
| **T5** | Token inválido/manipulado | `curl -i localhost:8080/api/usuarios -H 'Authorization: Bearer xxx.invalido.yyy'` | **401** — el filtro rechaza la firma inválida y no autentica; queda WARN `TOKEN_INVALIDO` en el log de auditoría |
| **T6** | Cabeceras de seguridad | `curl -I localhost:8080/public/hola` | Cabeceras `Content-Security-Policy: default-src 'self'` y `X-Frame-Options: DENY` presentes |
| **T7** | Monitoreo de actividad sospechosa | 5+ logins fallidos seguidos + 1 acceso 403 | Entradas WARN en el log `SECURITY_AUDIT`: `LOGIN_FALLIDO`, `POSIBLE_FUERZA_BRUTA` (al 5º intento), `ACCESO_DENEGADO` con IP/path/usuario intentado |

### Control de acceso por rol (resumen, coherente con T4 y la matriz)

```bash
# CLIENTE lee catálogo (200) pero no accede a ventas/usuarios (403)
curl -i localhost:8080/api/productos -H "Authorization: Bearer $TCLI"   # 200
curl -i localhost:8080/api/ventas    -H "Authorization: Bearer $TCLI"   # 403
curl -i localhost:8080/api/usuarios  -H "Authorization: Bearer $TCLI"   # 403
# CLIENTE no escribe catálogo (403); GERENTE sí (200)
curl -i -X POST localhost:8080/api/categorias -H "Authorization: Bearer $TCLI" \
  -H 'Content-Type: application/json' -d '{"nombre":"Bebidas"}'         # 403
curl -i -X POST localhost:8080/api/categorias -H "Authorization: Bearer $TGER" \
  -H 'Content-Type: application/json' -d '{"nombre":"Bebidas"}'         # 200
# EMPLEADO opera ventas/inventario (200) pero no escribe catálogo (403)
curl -i localhost:8080/api/ventas -H "Authorization: Bearer $TEMP"      # 200
```

## Evidencia automatizada: `SecurityRulesTest`

`src/test/java/com/minimarket/security/SecurityRulesTest.java` ejecuta la matriz
con `@WithMockUser(authorities=...)` y MockMvc. Resultado real en Docker JDK17:

```
[INFO] Tests run: 17, Failures: 0, Errors: 0, Skipped: 0 -- in com.minimarket.security.SecurityRulesTest
[INFO] Tests run: 18, Failures: 0, Errors: 0, Skipped: 0
[INFO] BUILD SUCCESS
```

Casos cubiertos: sin token → 401; CLIENTE lee catálogo/carrito → 200, escribe
catálogo / ventas / usuarios / inventario → 403; EMPLEADO ventas/inventario/lee
catálogo → 200, escribe catálogo / usuarios → 403; GERENTE usuarios/inventario y
escritura de catálogo → 200; endpoint público `/public/hola` sin token → 200.
