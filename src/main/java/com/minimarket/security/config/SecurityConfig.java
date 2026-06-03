package com.minimarket.security.config;

import com.minimarket.security.JwtAuthFilter;
import com.minimarket.security.handler.RestAccessDeniedHandler;
import com.minimarket.security.handler.RestAuthEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter; // seguridad JWT
    private final RestAuthEntryPoint restAuthEntryPoint;        // 401 JSON
    private final RestAccessDeniedHandler restAccessDeniedHandler; // 403 JSON

    public SecurityConfig(JwtAuthFilter jwtAuthFilter,
                          RestAuthEntryPoint restAuthEntryPoint,
                          RestAccessDeniedHandler restAccessDeniedHandler) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.restAuthEntryPoint = restAuthEntryPoint;
        this.restAccessDeniedHandler = restAccessDeniedHandler;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // en APIs REST stateless con JWT en el header no hay cookie de sesion,
            // por lo que CSRF se mitiga por diseno y se deshabilita el token CSRF
            .csrf(csrf -> csrf.disable())
            .headers(headers -> headers
                // cabeceras de seguridad: CSP como defensa en profundidad y frameOptions DENY
                .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'"))
                .frameOptions(frame -> frame.deny())
            )
            // apagamos la memoria del servidor: cada peticion se autentica por su token
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // respuestas JSON propias para 401 (sin token) y 403 (sin permisos)
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(restAuthEntryPoint)
                .accessDeniedHandler(restAccessDeniedHandler)
            )
            .authorizeHttpRequests(auth -> auth
                // 1) Publicos: login/registro, hola publico y pagina de error
                .requestMatchers("/auth/**", "/api/public/**", "/public/**", "/error").permitAll()
                // 2) Catalogo - LECTURA: cualquier usuario autenticado (el caso exige que el
                //    CLIENTE pueda consultar la disponibilidad de productos)
                .requestMatchers(HttpMethod.GET, "/api/productos/**", "/api/categorias/**")
                    .hasAnyAuthority("CLIENTE", "EMPLEADO", "GERENTE")
                // 3) Catalogo - ESCRITURA: solo GERENTE
                .requestMatchers(HttpMethod.POST,   "/api/productos/**", "/api/categorias/**").hasAuthority("GERENTE")
                .requestMatchers(HttpMethod.PUT,    "/api/productos/**", "/api/categorias/**").hasAuthority("GERENTE")
                .requestMatchers(HttpMethod.DELETE, "/api/productos/**", "/api/categorias/**").hasAuthority("GERENTE")
                // 4) Inventario: gestion interna -> EMPLEADO + GERENTE
                .requestMatchers("/api/inventario/**").hasAnyAuthority("EMPLEADO", "GERENTE")
                // 5) Carrito: del cliente (y el staff lo opera) -> CLIENTE + EMPLEADO + GERENTE
                .requestMatchers("/api/carrito/**").hasAnyAuthority("CLIENTE", "EMPLEADO", "GERENTE")
                // 6) Ventas / DetalleVenta: operacion de tienda -> EMPLEADO + GERENTE
                .requestMatchers("/api/ventas/**", "/api/detalle-ventas/**").hasAnyAuthority("EMPLEADO", "GERENTE")
                // 7) Usuarios: administracion -> solo GERENTE
                .requestMatchers("/api/usuarios/**").hasAuthority("GERENTE")
                // 8) Todo lo demas: requiere autenticacion
                .anyRequest().authenticated()
            )
            // nuestro filtro JWT corre antes del filtro de usuario/contrasena de Spring
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
