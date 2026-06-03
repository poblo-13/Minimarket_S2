package com.minimarket.security.handler;

import com.minimarket.security.audit.SecurityAuditLogger;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Devuelve 403 con cuerpo JSON cuando el usuario SI esta autenticado pero
 * NO tiene el rol/authority necesario para el endpoint. Ademas registra el
 * intento en el monitoreo de seguridad (actividad sospechosa).
 */
@Component
public class RestAccessDeniedHandler implements AccessDeniedHandler {

    private final SecurityAuditLogger auditLogger;

    public RestAccessDeniedHandler(SecurityAuditLogger auditLogger) {
        this.auditLogger = auditLogger;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = (auth != null) ? auth.getName() : "anonimo";
        auditLogger.accesoDenegado(username, request);

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        String path = escape(request.getRequestURI());
        response.getWriter().write(
                "{\"status\":403,\"error\":\"Acceso denegado\",\"message\":\"No tiene permisos para este recurso\",\"path\":\"" + path + "\"}");
    }

    private String escape(String value) {
        return value == null ? "" : value.replace("\"", "\\\"");
    }
}
