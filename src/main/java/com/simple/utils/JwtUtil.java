package com.simple.utils; // Package declaration for organizing code in the 'com.simple.utils' package

import io.jsonwebtoken.*; // Importing classes for handling JWTs
import io.jsonwebtoken.security.Keys; // Utility for generating secure keys
import org.springframework.security.core.userdetails.UserDetails; // Spring Security interface for user details
import org.springframework.stereotype.Component; // Marks this class as a Spring-managed component

import java.util.Date; // Importing Date class for token expiry handling
import java.security.Key; // Importing Key interface for cryptographic operations
import java.nio.charset.StandardCharsets; // Standard character encoding

@Component // Marks this class as a Spring Bean, so it can be autowired in other components
public class JwtUtil {

    // Secret key used to sign and verify the JWT (must be at least 32 characters long for HS256)
    private static final String SECRET_KEY = "SuperSecretKeySuperSecretKeySuperSecretKey123"; 

    // Method to generate a secure signing key from the secret key
    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8)); // Converts secret key to byte array and generates HMAC key
    }

    @SuppressWarnings("deprecation") // Suppressing deprecation warnings (though ideally, deprecated methods should be avoided)
    public String generateToken(String username) { // Method to generate a JWT token for a given username
        return Jwts.builder() // Starts building the JWT
                .setSubject(username) // Sets the subject (typically the username)
                .setIssuedAt(new Date()) // Sets the issued time as the current timestamp
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // Sets expiration time (1 hour from now)
                .signWith(getSigningKey(), SignatureAlgorithm.HS256) // Signs the token using HMAC SHA-256 algorithm and secret key
                .compact(); // Converts it into a compact JWT string
    }

    // Method to extract the username (subject) from a JWT token
    public String extractUsername(String token) {
        return extractClaims(token).getSubject(); // Calls extractClaims() and retrieves the 'subject' field
    }

    // Method to extract all claims (payload) from a JWT token
    private Claims extractClaims(String token) {
        return Jwts.parserBuilder() // Creates a parser for JWT
                .setSigningKey(getSigningKey()) // Sets the key to verify the signature
                .build() // Builds the parser
                .parseClaimsJws(token) // Parses the token and validates it
                .getBody(); // Extracts the claims (payload) from the token
    }

    // Method to check if a JWT token has expired
    public boolean isTokenExpired(String token) {
        return extractClaims(token).getExpiration().before(new Date()); // Compares expiration date with the current time
    }

    // Method to validate a JWT token against user details
    public boolean validateToken(String token, UserDetails userDetails) {
        return (userDetails.getUsername().equals(extractUsername(token)) // Check if username matches
                && !isTokenExpired(token)); // Ensure token is not expired
    }
}
