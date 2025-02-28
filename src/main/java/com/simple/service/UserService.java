package com.simple.service;

import org.springframework.security.core.userdetails.UserDetails; 
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException; 
import org.springframework.security.crypto.password.PasswordEncoder; 
import org.springframework.stereotype.Service; 
import com.simple.model.User; 
import com.simple.repository.UserRepository; 
import java.util.Optional; 

@Service 
public class UserService implements UserDetailsService { 

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder; 

    // Constructor to inject dependencies into this service class (userRepository and passwordEncoder)
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // Method from UserDetailsService to load user details by username (needed for authentication)
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Fetch the user from the repository using the provided username
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found")); // Throws exception if the user is not found

        // Returns the user details object containing the username, password, and roles
        return org.springframework.security.core.userdetails.User.withUsername(user.getUsername())
                .password(user.getPassword()) 
                .roles("USER")
                .build(); 
    }

    // Method to register a new user
    public User registerUser(String username, String password) {
        // Check if the username already exists in the database
        Optional<User> existingUser = userRepository.findByUsername(username);
        if (existingUser.isPresent()) {
            throw new IllegalArgumentException("Username already exists"); 
        }

        // Creates a new user if the username is available
        User newUser = new User();
        newUser.setUsername(username); 
        newUser.setPassword(passwordEncoder.encode(password)); 

        // Saves the new user to the repository and returns the saved user
        return userRepository.save(newUser);
    }

    public boolean usernameExists(String username) {
        // Check if a user with the given username already exists in the database
        return userRepository.findByUsername(username).isPresent();
    }

}
