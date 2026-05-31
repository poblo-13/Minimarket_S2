package com.minimarket.security.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Set;

@Component
public class JwtUtil {

    // 1 la clave secreta ahora viene del .env, ya no quemada en el codigo
    private final SecretKey secretKey;

    // 2 tiempo de validez del Token (en milisegundos), tambien desde el .env
    private final long expirationTime;

    public JwtUtil(@Value("${jwt.secret}") String secret,
                   @Value("${jwt.expiration}") long expirationTime) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes());
        this.expirationTime = expirationTime;
    }

    // metodo para fabricar el token
    public String generateToken(String username, Set<String> roles) {
        return Jwts.builder()
                .subject(username) // a quien le pertenece el token
                .claim("roles", roles) // agregamos los roles al pase VIP
                .issuedAt(new Date()) // fecha de creacion
                .expiration(new Date(System.currentTimeMillis() + expirationTime)) // fecha de vencimiento
                .signWith(secretKey, Jwts.SIG.HS256) // firmamos explicitamente con HMAC-SHA256 (HS256)
                .compact(); // lo convertimos en un String (token final)
    }

    // metodo para LEER a quien le pertenece un token
    public String extractUsername(String token) {
        return getClaims(token).getSubject();
    }

    // metodo interno para ABRIR y DESCIFRAR el token
    public Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey) // verificamos que la firma coincida
                .build()
                .parseSignedClaims(token)
                .getPayload(); // sacamos los datos
    }

    // metodo para VALIDAR si el token es legitimo y no ha vencido
    public boolean isTokenValid(String token) {
        try {
            getClaims(token); // si logra abrirlo sin lanzar error, es valido
            return true;
        } catch (Exception e) {
            return false; // si esta manipulado o vencido, devuelve falso
        }
    }
}