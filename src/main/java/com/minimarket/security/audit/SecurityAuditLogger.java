package com.minimarket.security.audit;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Monitoreo basico de actividades sospechosas (requisito de la pauta).
 *
 * Registra a nivel WARN, en un logger dedicado "SECURITY_AUDIT", los tres
 * eventos relevantes de seguridad: login fallido, token JWT invalido/expirado
 * y acceso denegado (403). NUNCA registra contrasenas ni el token completo.
 * Ademas mantiene un contador en memoria de fallos por IP para alertar de un
 * posible ataque de fuerza bruta al superar un umbral.
 */
@Component
public class SecurityAuditLogger {

    private static final Logger AUDIT = LoggerFactory.getLogger("SECURITY_AUDIT");
    private static final int UMBRAL_FUERZA_BRUTA = 5;

    private final java.util.concurrent.ConcurrentHashMap<String, Integer> fallosPorIp =
            new java.util.concurrent.ConcurrentHashMap<>();

    /** Login fallido: credenciales incorrectas o usuario inexistente. */
    public void loginFallido(String usernameIntentado, HttpServletRequest request) {
        String ip = ipDe(request);
        int fallos = fallosPorIp.merge(ip, 1, Integer::sum);
        AUDIT.warn("LOGIN_FALLIDO usuario='{}' ip={} path={}",
                sanitizar(usernameIntentado), ip, request.getRequestURI());
        if (fallos >= UMBRAL_FUERZA_BRUTA) {
            AUDIT.warn("POSIBLE_FUERZA_BRUTA ip={} intentos_fallidos={}", ip, fallos);
        }
    }

    /** Login correcto: reinicia el contador de fallos de esa IP. */
    public void loginExitoso(HttpServletRequest request) {
        fallosPorIp.remove(ipDe(request));
    }

    /** Token JWT invalido, manipulado o expirado presentado en una peticion. */
    public void tokenInvalido(String motivo, HttpServletRequest request) {
        AUDIT.warn("TOKEN_INVALIDO motivo='{}' ip={} path={}",
                sanitizar(motivo), ipDe(request), request.getRequestURI());
    }

    /** Acceso denegado 403: el usuario autenticado no tiene el rol requerido. */
    public void accesoDenegado(String username, HttpServletRequest request) {
        AUDIT.warn("ACCESO_DENEGADO usuario='{}' ip={} path={} metodo={}",
                sanitizar(username), ipDe(request), request.getRequestURI(), request.getMethod());
    }

    private String ipDe(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        return (forwarded != null && !forwarded.isBlank())
                ? forwarded.split(",")[0].trim()
                : request.getRemoteAddr();
    }

    /** Evita inyeccion de saltos de linea en el log (log forging). */
    private String sanitizar(String valor) {
        if (valor == null) {
            return "desconocido";
        }
        return valor.replaceAll("[\\r\\n]", "_");
    }
}
