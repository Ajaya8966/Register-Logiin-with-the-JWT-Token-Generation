package com.simple.controller; 

import com.simple.dto.AuthRequest;
import com.simple.dto.AuthResponse; 
import com.simple.model.User; 
import com.simple.service.UserService;
import com.simple.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired; 
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager; 
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken; 
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails; 
import org.springframework.web.bind.annotation.*; 

@RestController 
@RequestMapping("/auth") 
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;
    
    @Autowired
    private JwtUtil jwtUtil; 
    
    @Autowired
    private UserService userService;
    
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
