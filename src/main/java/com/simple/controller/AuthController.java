package com.simple.controller; // Package declaration for organizing the code in 'com.simple.controller' package

import com.simple.dto.AuthRequest; // Import for the AuthRequest DTO, which holds user login details
import com.simple.dto.AuthResponse; // Import for the AuthResponse DTO, which holds the JWT response
import com.simple.model.User; // Import for the User model representing the user entity
import com.simple.service.UserService; // Import for the UserService, which handles user-related logic
import com.simple.utils.JwtUtil; // Import for the JwtUtil utility class for JWT operations
import org.springframework.beans.factory.annotation.Autowired; // Import for Spring's @Autowired annotation to inject dependencies
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager; // Import for the AuthenticationManager interface
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken; // Import for the token used in authentication
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails; // Import for the UserDetails interface (Spring Security user)
import org.springframework.web.bind.annotation.*; // Import for Spring Web annotations like @RestController and @RequestMapping

@RestController // Marks this class as a RESTful controller for handling HTTP requests
@RequestMapping("/auth") // Maps all endpoints in this class to the '/auth' URL path
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager; // Autowires AuthenticationManager for handling user authentication

    @Autowired
    private JwtUtil jwtUtil; // Autowires JwtUtil to handle JWT generation and validation

    @Autowired
    private UserService userService; // Autowires UserService to handle user operations (loading, registration, etc.)

    // POST endpoint for user login at /auth/login
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest authRequest) {
        try {
            // Authenticate the user using the provided username and password from the request body
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword())
            );

            // After successful authentication, load user details from the UserService
            UserDetails userDetails = userService.loadUserByUsername(authRequest.getUsername());

            // Generate JWT token for the authenticated user
            String token = jwtUtil.generateToken(userDetails.getUsername());

            // Return the generated token wrapped in an AuthResponse object
            return ResponseEntity.ok(new AuthResponse(token));

        } catch (BadCredentialsException e) {
            // Handle invalid username/password
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                 .body("Enter the correct username and password");
        } catch (AuthenticationException e) {
            // Catch any other authentication-related errors
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                 .body("Authentication failed, please try again.");
        }
    }

    // POST endpoint for user registration at /auth/register
    @PostMapping("/register")
    public String register(@RequestBody AuthRequest authRequest) {
        // Check if the username already exists
        if (userService.usernameExists(authRequest.getUsername())) {
            return "User is already registered with the given username.";
        }

        // Register the user by calling the registerUser method in UserService
        User newUser = userService.registerUser(authRequest.getUsername(), authRequest.getPassword());

        // Return a success message with the newly registered username
        return "User registered successfully: " + newUser.getUsername();
    }

//    @PostMapping("/register")
//    public String register(@RequestBody AuthRequest authRequest) {
//        // Register the user by calling the registerUser method in UserService
//        User newUser = userService.registerUser(authRequest.getUsername(), authRequest.getPassword());
//
//        // Return a success message with the newly registered username
//        return "User registered successfully: " + newUser.getUsername();
//    }
    
    
 // Get user details (only accessible for authenticated users)
    @GetMapping("/user")
    public ResponseEntity<?> getUserDetails(@RequestHeader("Authorization") String token) {
        try {
            // Extract username from the token
            String username = jwtUtil.extractUsername(token.replace("Bearer ", ""));

            // Load the user details from the service
            UserDetails userDetails = userService.loadUserByUsername(username);

            // Return user details as a response
            return ResponseEntity.ok(userDetails);
        } catch (Exception e) {
            return ResponseEntity.status(401).body("Invalid token or authentication failed.");
        }
    }
    
    
}
