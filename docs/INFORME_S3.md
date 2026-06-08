# Informe técnico — Integrando seguridad en aplicaciones Backend

**Formato de respuesta (Forma C) — Desarrollo Backend II (PBY2202) · Semana 3**

| **Nombre estudiante:** | _(integrante 1, integrante 2, integrante 3 — completar)_ |
|------------------------|-----------------------------------------------------------|
| **Asignatura:** Desarrollo Backend II (PBY2202) | **Carrera:** _(completar)_ |
| **Profesor:** _(completar)_ | **Fecha:** _(completar)_ |

> **Declaración de origen.** Se partió del backend oficial de "MiniMarket Plus"
> provisto por el curso (mismo paquete `com.minimarket` y mismo dominio de 8
> entidades) y se le integró/portó la capa de seguridad madura desarrollada por el
> equipo, endureciéndola para esta entrega. El proyecto entregado es
> `Minimarket_S3` (<https://github.com/poblo-13/Minimarket_S3>).

---

## Entregable 1 — Análisis y selección de la estrategia y framework de seguridad

### 1.1 Amenazas identificadas (contextualizadas a MiniMarket Plus)

MiniMarket Plus trata datos personales de clientes y empleados, además de
inventario y ventas. Estos datos están sujetos a la **Ley 19.628** y su reforma
**Ley 21.719**. Las principales amenazas son:

| Amenaza | Componente | Impacto |
|---------|-----------|---------|
| SQL Injection | login, `/api/usuarios`, `/api/productos` | Robo/alteración de datos de clientes |
| XSS almacenado | campos de texto persistidos | Robo de sesión en el consumidor web |
| CSRF | operaciones de escritura | Acciones no autorizadas |
| Acceso no autorizado entre roles | todos los `/api/**` | Escalamiento de privilegios, fuga de datos |
| Robo/manipulación del token | sesión JWT | Suplantación de identidad |
| Secreto JWT débil/quemado | `JwtUtil` | Falsificación masiva de tokens |
| Fuga de credenciales/hash | login/registro, logs | Robo de contraseñas |
| Fuerza bruta | `/auth/login` | Compromiso de cuentas |
| Exposición de la consola H2 | `/h2-console` | Acceso directo a la base de datos |

> El detalle completo (componente → impacto legal → mitigación) está en
> [`analisis-amenazas.md`](analisis-amenazas.md).

### 1.2 Roles y niveles de seguridad diferenciados

- **CLIENTE**: consulta el catálogo (productos/categorías) y opera su carrito.
- **EMPLEADO**: además, gestiona inventario, ventas y detalle de ventas.
- **GERENTE** (administrador): control total, incluida la escritura del catálogo
  y la administración de usuarios.

### 1.3 Exploración de estrategias de autenticación y por qué JWT

| Estrategia | Limitación para MiniMarket Plus |
|-----------|----------------------------------|
| En memoria | Solo sirve para pruebas; usuarios quemados, no escala |
| JDBC | Persistente, pero **con estado de sesión** en el servidor; no escala bien horizontalmente |
| LDAP | Útil con un directorio corporativo existente; agrega infraestructura y acoplamiento que el caso no requiere |
| **JWT (elegida)** | **Stateless**: el token autocontenido viaja en el header; no hay sesión en el servidor, escala horizontalmente y encaja con una arquitectura de microservicios |

**Justificación.** El cliente exige un sistema **stateless** ("Utilizar JWT para
gestionar las sesiones de los usuarios en un entorno sin estado"). JWT permite que
cualquier instancia valide el token con la clave compartida sin consultar una
sesión central, lo que habilita el escalamiento horizontal y la expansión a más
sucursales/microservicios sin un store de sesiones compartido.

---

## Entregable 2 — Guía de configuración e implementación

### 2.1 Dependencias (`pom.xml`)

`spring-boot-starter-security`, `spring-boot-starter-web`,
`spring-boot-starter-validation` y **jjwt 0.12.5** (`jjwt-api`, `jjwt-impl`,
`jjwt-jackson`). Para pruebas, `spring-security-test`.

### 2.2 Autenticación: `UserDetailsService` + BCrypt

`CustomUserDetailsService` carga el usuario desde la BD con una consulta
**parametrizada** de Spring Data JPA (`findByUsername`), y `CustomUserDetails`
expone las authorities **sin prefijo `ROLE_`**:

```java
// CustomUserDetails.java
public Collection<? extends GrantedAuthority> getAuthorities() {
    return usuario.getRoles().stream()
            .map(rol -> new SimpleGrantedAuthority(rol.getNombre())) // "GERENTE", no "ROLE_GERENTE"
            .collect(Collectors.toList());
}
```

> **Decisión clave de coherencia:** como las authorities no llevan `ROLE_`, en
> TODO el proyecto se usa `hasAuthority` / `hasAnyAuthority` y **nunca** `hasRole`
> (que añadiría `ROLE_` y rompería el control de acceso en silencio).

Las contraseñas se hashean con **BCrypt** en runtime (`DataSeeder` y registro);
nunca se versiona un hash ni se guarda texto plano:

```java
// DataSeeder.java
usuario.setPassword(passwordEncoder.encode(passwordPlano)); // BCrypt en runtime
```

### 2.3 JWT: `JwtUtil` con secreto validado y HS256 explícito

```java
// JwtUtil.java — secreto desde .env, validado al arrancar
public JwtUtil(@Value("${jwt.secret}") String secret,
               @Value("${jwt.expiration}") long expirationTime) {
    if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < 32) {
        throw new IllegalStateException("jwt.secret debe tener al menos 32 bytes (256 bits) para HS256");
    }
    this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    this.expirationTime = expirationTime;
}

// firma explícita HS256 + expiración
.signWith(secretKey, Jwts.SIG.HS256)

// validación: verifyWith comprueba la firma; si falla, isTokenValid devuelve false
Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token);
```

### 2.4 Filtro JWT (`OncePerRequestFilter`)

`JwtAuthFilter` extrae el `Bearer`, valida el token y, si es legítimo, fija la
autenticación en el contexto. Un token manipulado/expirado se registra en el
monitoreo y se deja pasar **sin** autenticar (el endpoint responderá 401):

```java
// JwtAuthFilter.java
try {
    username = jwtUtil.extractUsername(jwtToken);
} catch (Exception e) {
    auditLogger.tokenInvalido(e.getClass().getSimpleName(), request); // sin volcar el token
}
```

### 2.5 `SecurityConfig`: stateless + reglas por rol + handlers 401/403

```java
http
  .csrf(csrf -> csrf.disable())                          // stateless + JWT en header
  .headers(h -> h
      .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'"))
      .frameOptions(f -> f.deny()))
  .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
  .exceptionHandling(ex -> ex
      .authenticationEntryPoint(restAuthEntryPoint)      // 401 JSON
      .accessDeniedHandler(restAccessDeniedHandler))     // 403 JSON
  .authorizeHttpRequests(auth -> auth
      .requestMatchers("/auth/**", "/api/public/**", "/public/**", "/error").permitAll()
      .requestMatchers(HttpMethod.GET, "/api/productos/**", "/api/categorias/**")
          .hasAnyAuthority("CLIENTE", "EMPLEADO", "GERENTE")          // catálogo lectura
      .requestMatchers(HttpMethod.POST,   "/api/productos/**", "/api/categorias/**").hasAuthority("GERENTE")
      .requestMatchers(HttpMethod.PUT,    "/api/productos/**", "/api/categorias/**").hasAuthority("GERENTE")
      .requestMatchers(HttpMethod.DELETE, "/api/productos/**", "/api/categorias/**").hasAuthority("GERENTE")
      .requestMatchers("/api/inventario/**").hasAnyAuthority("EMPLEADO", "GERENTE")
      .requestMatchers("/api/carrito/**").hasAnyAuthority("CLIENTE", "EMPLEADO", "GERENTE")
      .requestMatchers("/api/ventas/**", "/api/detalle-ventas/**").hasAnyAuthority("EMPLEADO", "GERENTE")
      .requestMatchers("/api/usuarios/**").hasAuthority("GERENTE")
      .anyRequest().authenticated())
  .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
```

Los handlers devuelven JSON en lugar de la página de login HTML:

```java
// RestAuthEntryPoint (401)
response.getWriter().write("{\"status\":401,\"error\":\"No autenticado\",...}");
// RestAccessDeniedHandler (403) — además registra el intento en el monitoreo
auditLogger.accesoDenegado(username, request);
```

### 2.6 Autorización por rol con `@PreAuthorize` (doble candado)

Cada controlador replica EXACTAMENTE la regla del filtro:

```java
@RequestMapping("/api/usuarios") @PreAuthorize("hasAuthority('GERENTE')")        // UsuarioController
@RequestMapping("/api/ventas")   @PreAuthorize("hasAnyAuthority('EMPLEADO','GERENTE')") // VentaController
@RequestMapping("/api/carrito")  @PreAuthorize("hasAnyAuthority('CLIENTE','EMPLEADO','GERENTE')") // CarritoController
// ProductoController/CategoriaController: GET -> CLIENTE/EMPLEADO/GERENTE; POST/PUT/DELETE -> GERENTE
```

### 2.7 Matriz rol × endpoint (filtro = anotaciones = pruebas)

| Recurso | Método | CLIENTE | EMPLEADO | GERENTE | Sin token |
|---------|--------|:-------:|:--------:|:-------:|:---------:|
| `/auth/**`, `/public/**` | * | público | público | público | 200 |
| `/api/productos`, `/api/categorias` | GET | 200 | 200 | 200 | 401 |
| `/api/productos`, `/api/categorias` | POST/PUT/DELETE | 403 | 403 | 200 | 401 |
| `/api/inventario` | * | 403 | 200 | 200 | 401 |
| `/api/carrito` | * | 200 | 200 | 200 | 401 |
| `/api/ventas`, `/api/detalle-ventas` | * | 403 | 200 | 200 | 401 |
| `/api/usuarios` | * | 403 | 403 | 200 | 401 |

### 2.8 Monitoreo básico de actividad sospechosa

`SecurityAuditLogger` registra a nivel WARN (logger `SECURITY_AUDIT`): login
fallido, token inválido/expirado y acceso denegado 403, con un contador por IP que
alerta `POSIBLE_FUERZA_BRUTA` al superar el umbral. Nunca registra contraseñas ni
el token completo.

### 2.9 Pruebas funcionales por rol

Batería automatizada `SecurityRulesTest` (`@WithMockUser` + MockMvc) que verifica
la matriz completa. Resultado real en Docker JDK17:

```
[INFO] Tests run: 17, Failures: 0, Errors: 0, Skipped: 0 -- in com.minimarket.security.SecurityRulesTest
[INFO] Tests run:  3, Failures: 0, Errors: 0, Skipped: 0 -- in com.minimarket.SerializacionJsonTest
[INFO] Tests run:  1, Failures: 0, Errors: 0, Skipped: 0 -- in com.minimarket.MinimarketApplicationTests
[INFO] Tests run: 21, Failures: 0, Errors: 0, Skipped: 0
[INFO] BUILD SUCCESS
```

---

## Entregable 3 — Explicación técnica (cómo cada configuración protege el backend)

| Amenaza | Configuración que la mitiga | Por qué protege |
|---------|------------------------------|------------------|
| SQL Injection | Spring Data JPA parametrizado | No se concatena la entrada del usuario en el SQL; el driver la trata como parámetro, no como código |
| XSS almacenado | Contrato JSON + `@Valid`/`@Pattern` + CSP | La API responde `application/json` (el navegador no ejecuta `<script>` en JSON); la validación rechaza `<`/`>` y la CSP limita el origen de scripts |
| CSRF | Stateless + JWT en header + `csrf.disable()` | Sin cookie de sesión, un sitio externo no puede forzar la credencial; el token va explícito en `Authorization` |
| Acceso no autorizado | Filtro por rol + `@PreAuthorize` + 401/403 | Doble candado: aunque se omitiera una capa, la otra bloquea; respuestas claras 401 (sin token) / 403 (sin permisos) |
| Robo/manipulación del token | HS256 + `verifyWith` + expiración | Cualquier alteración invalida la firma; el token caduca |
| Secreto débil/quemado | Secreto en `.env` validado `>= 32 bytes` | Un secreto adivinable o público haría falsificable cualquier token; se valida al arrancar |
| Fuga de credenciales | BCrypt + DTOs sin hash + sin `println` | El hash nunca sale en respuestas ni logs; se eliminó el `println` que filtraba el hash |
| Fuerza bruta | `SecurityAuditLogger` (contador por IP) | Deja trazas de intentos y alerta ante un patrón de fuerza bruta |
| Exposición de H2 | Consola deshabilitada (solo perfil `dev`) | Se cierra el acceso directo a la BD en el perfil por defecto |

### Tabla de pruebas T1–T7

Ver [`pruebas-seguridad.md`](pruebas-seguridad.md) (SQLi, XSS, CSRF, acceso sin
token, token manipulado, cabeceras de seguridad, monitoreo) con los comandos y
resultados esperados.

---

## Anexo — Respuestas a las preguntas de apoyo

**1. ¿Cuáles son las principales amenazas y cómo impactan?**
SQLi, XSS, CSRF, acceso no autorizado entre roles, robo/manipulación de token,
secreto débil, fuga de credenciales, fuerza bruta y exposición de la consola H2.
Impactan en la confidencialidad e integridad de datos personales y de ventas
(infracción de la Ley 19.628/21.719), en la disponibilidad del servicio y en la
reputación de la cadena.

**2. ¿Qué estrategias de mitigación son más apropiadas?**
Defensa en profundidad: consultas parametrizadas (SQLi), contrato JSON +
validación de entrada + CSP (XSS), diseño stateless con JWT en header (CSRF),
doble control de acceso filtro + `@PreAuthorize` (autorización), HS256 con secreto
fuerte validado (integridad del token), BCrypt (credenciales) y monitoreo de
actividad sospechosa (fuerza bruta).

**3. ¿Qué framework se adapta mejor y por qué?**
**Spring Security + JWT.** Spring Security se integra nativamente con el stack
Spring Boot del backend provisto y ofrece filtros, `UserDetailsService`, method
security y manejo de excepciones listos. JWT aporta el modelo **stateless** que el
cliente exige, escalable horizontalmente para la expansión a más sucursales.

**4. ¿Cómo implementaste autenticación y autorización por rol con Spring Security?**
Autenticación: `CustomUserDetailsService` + BCrypt + `JwtUtil` (HS256) + un
`OncePerRequestFilter` que valida el token por petición. Autorización:
`SecurityConfig` define reglas por rol y método, replicadas con `@PreAuthorize` en
cada controlador (doble candado), usando `hasAuthority`/`hasAnyAuthority`
coherentes con authorities sin `ROLE_`. Handlers 401/403 devuelven JSON.

**5. ¿Qué medidas tomaste para cumplir la normativa de protección de datos?**
BCrypt para las contraseñas; **minimización de datos** en los DTOs (nunca se
expone el hash); secreto JWT fuera del repositorio (`.env` no versionado);
**control de acceso por rol** para limitar quién ve qué dato personal; **monitoreo**
de accesos sospechosos como trazabilidad ante incidentes; y consola H2 cerrada
para evitar el acceso directo a la base de datos. Todo alineado con la Ley 19.628
y su reforma 21.719.

---

## Repositorio GitHub

<https://github.com/poblo-13/Minimarket_S3> — incluye `README.md` técnico,
`.gitignore` (excluye `.env` y `target/`), `.env.example`, el código de seguridad y
los documentos `docs/analisis-amenazas.md` y `docs/pruebas-seguridad.md`.
