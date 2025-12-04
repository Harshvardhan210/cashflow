package com.cashflow.cashflow.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.SignatureAlgorithm;
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
                    "JWT secret must be at least 64 characters long for HS512!"
            );
        }
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes());
    }

    // ------------------ GENERATE TOKEN ------------------
    public String generateToken(String username, Long userId) {

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("role", "USER");

        return Jwts.builder()
                .claims(claims)
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(signingKey, SignatureAlgorithm.HS512)
                .compact();
    }

    // ------------------ EXTRACT USERNAME ------------------
    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    // ------------------ CHECK EXPIRATION ------------------
    public boolean isTokenExpired(String token) {
        return extractAllClaims(token).getExpiration().before(new Date());
    }

    // ------------------ VALIDATE JWT ------------------
    public boolean validateToken(String token) {
        try {
            extractAllClaims(token);
            return true;

        } catch (ExpiredJwtException e) {
            System.out.println("JWT expired: " + e.getMessage());

        } catch (UnsupportedJwtException e) {
            System.out.println("JWT unsupported: " + e.getMessage());

        } catch (MalformedJwtException e) {
            System.out.println("Invalid JWT: " + e.getMessage());

        } catch (SignatureException e) {
            System.out.println("Invalid signature: " + e.getMessage());

        } catch (Exception e) {
            System.out.println("JWT validation error: " + e.getMessage());
        }

        return false;
    }

    // ------------------ USER VALIDATION ------------------
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    // ------------------ INTERNAL CLAIMS PARSER ------------------
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
