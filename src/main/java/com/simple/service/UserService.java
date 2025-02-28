package com.simple.service; // Package declaration for organizing the code in 'com.simple.service' package

import org.springframework.security.core.userdetails.UserDetails; // Import for UserDetails interface used by Spring Security
import org.springframework.security.core.userdetails.UserDetailsService; // Import for UserDetailsService interface for loading user data
import org.springframework.security.core.userdetails.UsernameNotFoundException; // Import for handling username not found exceptions
import org.springframework.security.crypto.password.PasswordEncoder; // Import for encoding passwords securely
import org.springframework.stereotype.Service; // Import for marking this class as a Spring service
import com.simple.model.User; // Import for the User model (entity representing the user in the system)
import com.simple.repository.UserRepository; // Import for the UserRepository (interface for data access operations)
import java.util.Optional; // Import for using Optional to handle null values safely

@Service // Marks this class as a Spring service that can be injected as a dependency
public class UserService implements UserDetailsService { // Implements UserDetailsService for loading user details based on username

    private final UserRepository userRepository; // Declaring a field for the UserRepository to interact with the database
    private final PasswordEncoder passwordEncoder; // Declaring a field for the PasswordEncoder to encode user passwords

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
                .password(user.getPassword()) // Retrieves the encoded password from the user
                .roles("USER") // Assigns a role to the user (in this case, "USER")
                .build(); // Builds and returns the UserDetails object
    }

    // Method to register a new user
    public User registerUser(String username, String password) {
        // Check if the username already exists in the database
        Optional<User> existingUser = userRepository.findByUsername(username);
        if (existingUser.isPresent()) {
            throw new IllegalArgumentException("Username already exists"); // Throws exception if the username is taken
        }

        // Creates a new user if the username is available
        User newUser = new User();
        newUser.setUsername(username); // Sets the username for the new user
        newUser.setPassword(passwordEncoder.encode(password)); // Encodes the password before saving (BCrypt or other encoding methods)

        // Saves the new user to the repository and returns the saved user
        return userRepository.save(newUser);
    }

    public boolean usernameExists(String username) {
        // Check if a user with the given username already exists in the database
        return userRepository.findByUsername(username).isPresent();
    }

}
