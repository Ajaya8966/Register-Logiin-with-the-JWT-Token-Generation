package com.simple.utils;
import io.jsonwebtoken.*; 
import io.jsonwebtoken.security.Keys; 
import org.springframework.security.core.userdetails.UserDetails; 
import org.springframework.stereotype.Component;

import java.util.Date; 
import java.security.Key; 
import java.nio.charset.StandardCharsets; 

@Component 
public class JwtUtil {

    // Secret key used to sign and verify the JWT (must be at least 32 characters long for HS256)
    private static final String SECRET_KEY = "SuperSecretKeySuperSecretKeySuperSecretKey123"; 

    // Method to generate a secure signing key from the secret key
    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8)); 
    }

    @SuppressWarnings("deprecation") 
    public String generateToken(String username) { 
        return Jwts.builder()
                .setSubject(username) 
                .setIssuedAt(new Date()) 
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // Method to extract the username (subject) from a JWT token
    public String extractUsername(String token) {
        return extractClaims(token).getSubject(); 
    }

    // Method to extract all claims (payload) from a JWT token
    private Claims extractClaims(String token) {
        return Jwts.parserBuilder() 
                .setSigningKey(getSigningKey()) 
                .build()
                .parseClaimsJws(token) 
                .getBody(); 
    }

    // Method to check if a JWT token has expired
    public boolean isTokenExpired(String token) {
        return extractClaims(token).getExpiration().before(new Date()); 
    }

    // Method to validate a JWT token against user details
    public boolean validateToken(String token, UserDetails userDetails) {
        return (userDetails.getUsername().equals(extractUsername(token))
                && !isTokenExpired(token)); 
    }
}
