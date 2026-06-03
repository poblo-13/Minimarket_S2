# MiniMarket Plus — Backend con seguridad integrada (JWT + Spring Security)

API REST para la gestión de un minimarket (productos, categorías, inventario,
carrito, ventas y usuarios) con **autenticación JWT** y **autorización por roles**
sobre **Spring Security**. Sumativa S3 — Desarrollo Backend II (PBY2202).

Repositorio: <https://github.com/poblo-13/Minimarket_S2>

## Integrantes

> Completar antes de la entrega (modalidad grupal 2–3 integrantes):
> - Nombre Apellido — usuario GitHub
> - Nombre Apellido — usuario GitHub
> - Nombre Apellido — usuario GitHub

## Stack

- **Spring Boot 3.4.1**, **Java 17**
- **Spring Security** (stateless, `SecurityFilterChain`, `@EnableMethodSecurity`)
- **JWT** con **jjwt 0.12.5**, firma **HS256** explícita, `verifyWith`, expiración
- **BCrypt** para el hash de contraseñas
- **H2** en memoria (consola deshabilitada por defecto)
- **spring-security-test** para las pruebas de seguridad

## Cómo ejecutar

> El host de desarrollo usa JDK26, que rompe Spring Boot 3. Compilar y ejecutar
> en **Docker JDK17**.

1. Copiar el archivo de entorno y completar la clave secreta (mínimo 32 caracteres):

   ```bash
   cp .env.example .env
   # editar .env y poner un JWT_SECRET largo (>= 32 bytes); .env NO se versiona
   ```

2. Compilar y testear:

   ```bash
   docker run --rm -v "$PWD":/app -v "$HOME/.m2":/root/.m2 \
     -w /app maven:3.9-eclipse-temurin-17 mvn -B clean test
   ```

3. Levantar la API:

   ```bash
   docker run --rm -p 8080:8080 -v "$PWD":/app -v "$HOME/.m2":/root/.m2 \
     -w /app maven:3.9-eclipse-temurin-17 mvn -q spring-boot:run
   ```

4. (Solo desarrollo) Habilitar la consola H2 con el perfil `dev`:

   ```bash
   ... mvn -q spring-boot:run -Dspring-boot.run.profiles=dev   # consola en /h2-console
   ```

## Usuarios sembrados (DataSeeder, BCrypt en runtime)

| Usuario   | Rol      | Contraseña (por defecto, desde `.env`) |
|-----------|----------|----------------------------------------|
| `admin`   | GERENTE  | `12345` |
| `empleado`| EMPLEADO | `12345` |
| `cliente` | CLIENTE  | `12345` |

## Autenticación

```bash
# Login -> devuelve {"token":"<jwt>"}
curl -X POST localhost:8080/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"12345"}'
# Usar el token en las llamadas protegidas
curl localhost:8080/api/usuarios -H "Authorization: Bearer <jwt>"
```

`POST /auth/register` crea un usuario nuevo con rol **CLIENTE** por defecto.

## Matriz de roles × endpoints

> Regla única, replicada en el **filtro de URL** (`SecurityConfig`), en las
> anotaciones **`@PreAuthorize`** de cada controlador y en las **pruebas**.
> El catálogo es de **lectura para cualquier autenticado** (el caso exige que el
> cliente consulte productos); la **escritura del catálogo es solo de GERENTE**.

| Recurso | Método | CLIENTE | EMPLEADO | GERENTE | Sin token |
|---------|--------|:-------:|:--------:|:-------:|:---------:|
| `/auth/**`, `/public/**` | * | público | público | público | **200** |
| `/api/productos`, `/api/categorias` | GET | **200** | 200 | 200 | 401 |
| `/api/productos`, `/api/categorias` | POST/PUT/DELETE | 403 | 403 | **200** | 401 |
| `/api/inventario` | * | 403 | **200** | 200 | 401 |
| `/api/carrito` | * | **200** | 200 | 200 | 401 |
| `/api/ventas`, `/api/detalle-ventas` | * | 403 | **200** | 200 | 401 |
| `/api/usuarios` | * | 403 | 403 | **200** | 401 |

## Seguridad implementada

- **JWT stateless**: token firmado HS256, secreto `>= 32 bytes` validado al
  arrancar y leído de `.env` (nunca quemado en el código).
- **Doble candado de autorización**: reglas por rol/método en `SecurityConfig`
  + `@PreAuthorize` en cada controlador. Authorities **sin prefijo `ROLE_`**, por
  lo que se usa **`hasAuthority` / `hasAnyAuthority`** de forma consistente
  (nunca `hasRole`, que añadiría `ROLE_` y rompería el control en silencio).
- **Handlers JSON**: `RestAuthEntryPoint` (401) y `RestAccessDeniedHandler` (403).
- **BCrypt** en el seeder y el registro; los DTOs nunca exponen el hash.
- **Cabeceras**: `Content-Security-Policy: default-src 'self'`, `X-Frame-Options: DENY`.
- **Validación de entrada** (`@Valid` + `@Pattern`/`@Size`) como defensa frente a
  XSS almacenado.
- **Monitoreo** (`SecurityAuditLogger`): logins fallidos, tokens inválidos y
  accesos 403 a nivel WARN, con contador por IP para detectar fuerza bruta.
- **Consola H2 deshabilitada** por defecto (solo bajo el perfil `dev`).

Detalle de amenazas: [`docs/analisis-amenazas.md`](docs/analisis-amenazas.md).
Pruebas de seguridad: [`docs/pruebas-seguridad.md`](docs/pruebas-seguridad.md).

## Estructura

```
src/main/java/com/minimarket
├── controller/        # endpoints REST (anotados con @PreAuthorize)
├── entity/            # entidades JPA (Usuario, Rol, Producto, ...)
├── repository/        # Spring Data JPA (consultas parametrizadas)
├── service/           # lógica de negocio
├── dto/               # DTOs de entrada/salida (sin exponer el hash)
├── config/            # DataSeeder (usuarios/roles iniciales con BCrypt)
└── security/
    ├── config/        # SecurityConfig (+ DevSecurityConfig perfil dev)
    ├── handler/       # RestAuthEntryPoint (401), RestAccessDeniedHandler (403)
    ├── audit/         # SecurityAuditLogger (monitoreo)
    ├── service/       # CustomUserDetailsService
    ├── model/         # CustomUserDetails
    ├── util/          # JwtUtil (generación/validación del token)
    └── JwtAuthFilter  # OncePerRequestFilter que valida el JWT por petición
```
