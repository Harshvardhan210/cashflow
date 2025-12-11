package com.cashflow.cashflow.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expiration;

    private SecretKey signingKey;

    @PostConstruct
    public void init() {
        if (secret == null || secret.length() < 64) {
            throw new IllegalArgumentException(
                    "JWT secret must be at least 64 characters long for HS512"
            );
        }
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes());
    }

    // ---------------------- GENERATE TOKEN ----------------------
    public String generateToken(String username, Long userId) {

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("role", "USER");

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(signingKey, SignatureAlgorithm.HS512)
                .compact();
    }

    // ---------------------- USERNAME FROM TOKEN ----------------------
    public String extractUsername(String token) {
        Claims claims = safeExtractClaims(token);
        return claims != null ? claims.getSubject() : null;
    }

    // ---------------------- CHECK EXPIRATION ----------------------
    public boolean isTokenExpired(String token) {
        Claims claims = safeExtractClaims(token);
        return claims == null || claims.getExpiration().before(new Date());
    }

    // ---------------------- VALIDATE TOKEN ----------------------
    public boolean isTokenValid(String token, UserDetails userDetails) {
        String username = extractUsername(token);
        return username != null &&
               username.equals(userDetails.getUsername()) &&
               !isTokenExpired(token);
    }

    // ---------------------- SAFE CLAIMS PARSER ----------------------
    private Claims safeExtractClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

        } catch (ExpiredJwtException e) {
            System.out.println("JWT expired: " + e.getMessage());
        } catch (JwtException e) {
            System.out.println("JWT validation error: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("Unexpected JWT error: " + e.getMessage());
        }

        return null;
    }
}
