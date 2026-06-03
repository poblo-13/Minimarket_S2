package com.minimarket.security.handler;

import com.minimarket.security.audit.SecurityAuditLogger;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Devuelve 401 con cuerpo JSON cuando una peticion llega SIN autenticacion
 * valida (sin token o con token rechazado por el filtro). Reemplaza la
 * pagina de login HTML por defecto, coherente con una API REST stateless.
 */
@Component
public class RestAuthEntryPoint implements AuthenticationEntryPoint {

    private final SecurityAuditLogger auditLogger;

    public RestAuthEntryPoint(SecurityAuditLogger auditLogger) {
        this.auditLogger = auditLogger;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        auditLogger.tokenInvalido("acceso sin autenticacion valida", request);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        String path = escape(request.getRequestURI());
        response.getWriter().write(
                "{\"status\":401,\"error\":\"No autenticado\",\"message\":\"Se requiere un token JWT valido\",\"path\":\"" + path + "\"}");
    }

    private String escape(String value) {
        return value == null ? "" : value.replace("\"", "\\\"");
    }
}
