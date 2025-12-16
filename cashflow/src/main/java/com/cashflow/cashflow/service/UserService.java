package com.cashflow.cashflow.service;

import com.cashflow.cashflow.dto.SignupRequest;
import com.cashflow.cashflow.entity.User;
import com.cashflow.cashflow.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public User registerUser(SignupRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            throw new RuntimeException("Username already taken");
        }
        if (userRepository.existsByEmail(request.email())) {
            throw new RuntimeException("Email already registered");
        }

        User user = new User();
        user.setName(request.name());
        user.setEmail(request.email());
        user.setUsername(request.username());
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setDob(request.dob());

        // ⭐ DEFAULT VALUES (required!)
        user.setBudget(0.0);
        user.setCurrency("INR");
        user.setSymbol("₹");

        return userRepository.save(user);
    }
}
