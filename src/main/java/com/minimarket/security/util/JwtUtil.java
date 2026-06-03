package com.minimarket.security.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Set;

@Component
public class JwtUtil {

    // Logger agregado para registrar errores sin usar System.out.println
    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    // La clave secreta ahora viene del .env ya no quemada en el codigo
    private final SecretKey secretKey;

    // Tiempo de validez del Token tambien desde el .env
    private final long expirationTime;

    public JwtUtil(@Value("${jwt.secret}") String secret,
                   @Value("${jwt.expiration}") long expirationTime) {
        // HS256 exige una clave de al menos 256 bits (32 bytes).
        if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalStateException("jwt.secret debe tener al menos 32 bytes (256 bits) para HS256");
        }
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expirationTime = expirationTime;
    }

    // metodo para fabricar el token
    public String generateToken(String username, Set<String> roles) {
        return Jwts.builder()
                .subject(username)
                .claim("roles", roles)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(secretKey, Jwts.SIG.HS256)
                .compact();
    }

    // metodo para LEER a quien le pertenece un token
    public String extractUsername(String token) {
        return getClaims(token).getSubject();
    }

    // metodo interno para ABRIR y DESCIFRAR el token
    public Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // METODO ACTUALIZADO excepciones especificas y Logger estructurado
    public boolean isTokenValid(String token) {
        try {
            getClaims(token); // si logra abrirlo sin lanzar error, es valido
            return true;
        } catch (SignatureException e) {
            logger.error("Firma del token JWT inválida: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Token JWT mal formado: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("El token JWT ha expirado: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("Token JWT no soportado: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("El token JWT está vacío o es nulo: {}", e.getMessage());
        }
        return false;
    }
}