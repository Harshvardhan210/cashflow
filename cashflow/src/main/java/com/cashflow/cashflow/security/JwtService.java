package com.cashflow.cashflow.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
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
        this.signingKey =
                Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    // ---------------------- GENERATE TOKEN ----------------------
    public String generateToken(String username, Long userId) {

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("role", "USER");

        return Jwts.builder()
                .claims(claims)
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(signingKey, Jwts.SIG.HS512)
                .compact();
    }

    // ---------------------- EXTRACT USERNAME ----------------------
    public String extractUsername(String token) {
        try {
            return parseClaims(token).getSubject();
        } catch (Exception e) {
            return null;
        }
    }

    // ---------------------- VALIDATE TOKEN (USED IN CONTROLLER) ----------------------
    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    // ---------------------- FULL VALIDATION ----------------------
    public boolean isTokenValid(String token, UserDetails userDetails) {
        String username = extractUsername(token);
        return username != null &&
               username.equals(userDetails.getUsername()) &&
               !isTokenExpired(token);
    }

    // ---------------------- CHECK EXPIRATION ----------------------
    private boolean isTokenExpired(String token) {
        return parseClaims(token)
                .getExpiration()
                .before(new Date());
    }

    // ---------------------- CLAIMS PARSER (NEW API) ----------------------
    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
