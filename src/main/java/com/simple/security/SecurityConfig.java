package com.simple.security; // Package declaration for organizing code in the 'com.simple.security' package

import org.springframework.context.annotation.Bean; // Import for defining Spring beans
import org.springframework.context.annotation.Configuration; // Import for marking this class as a configuration class
import org.springframework.security.authentication.AuthenticationManager; // Import for authentication manager interface
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration; // Import for authentication configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity; // Import for configuring HTTP security (access control)
import org.springframework.security.config.http.SessionCreationPolicy; // Import for session management policies
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder; // Import for BCrypt password encoder
import org.springframework.security.crypto.password.PasswordEncoder; // Import for password encoder interface
import org.springframework.security.web.SecurityFilterChain; // Import for defining a security filter chain

@Configuration // Marks this class as a configuration class to be used by Spring
public class SecurityConfig {

    // Configuring HTTP security for defining access control and authentication behavior
    @Bean 
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable()) // Disables CSRF protection (commonly disabled for stateless APIs)
            .authorizeHttpRequests(auth -> auth 
                .requestMatchers("/auth/login", "/auth/register").permitAll()  // Allows unrestricted access to login and register URLs
                .anyRequest().authenticated() // Requires authentication for any other request
            )
            .sessionManagement(session -> session 
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Ensures no session is created (stateless authentication)
            );

        return http.build(); // Builds and returns the configured security filter chain
    }

    // Bean to define the AuthenticationManager used for authenticating users
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager(); // Retrieves and returns the authentication manager from the provided configuration
    }

    // Bean to define the password encoder used for encoding passwords
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // Returns a BCryptPasswordEncoder to encode passwords securely
    }
}
