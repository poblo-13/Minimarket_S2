package com.minimarket.security.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Set;

@Component
public class JwtUtil {

    // 1 la clave secreta debe ser larga y segura
    private static final String SECRET = "MinimarketPlus_ClaveSecretaSuperSegura_2026_Java17_Token";
    private final SecretKey secretKey = Keys.hmacShaKeyFor(SECRET.getBytes());

    // 2 tiempo de validez del Token (1 hora en milisegundos)
    private static final long EXPIRATION_TIME = 3600000;

    // metodo para fabricar el token
    public String generateToken(String username, Set<String> roles) {
        return Jwts.builder()
                .subject(username) // a quien le pertenece el token
                .claim("roles", roles) // agregamos los roles al pase VIP
                .issuedAt(new Date()) // fecha de creacion
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME)) // fecha de vencimiento
                .signWith(secretKey) // lo firmamos con nuestra clave secreta para que no se pueda falsificar
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