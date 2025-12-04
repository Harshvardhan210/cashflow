package com.cashflow.cashflow.controller;

import com.cashflow.cashflow.dto.LoginRequest;
import com.cashflow.cashflow.dto.ProfileUpdateRequest;
import com.cashflow.cashflow.dto.SignupRequest;
import com.cashflow.cashflow.entity.User;
import com.cashflow.cashflow.repository.UserRepository;
import com.cashflow.cashflow.security.JwtService;
import com.cashflow.cashflow.service.UserService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;

    // ------------ COOKIE CONFIG FROM application.properties ----------
    @Value("${cookie.secure}")
    private boolean secure;

    @Value("${cookie.http-only}")
    private boolean httpOnly;

    @Value("${cookie.same-site}")
    private String sameSite;

    // ----------------------- SIGNUP -----------------------
    @PostMapping("/signup")
    public ResponseEntity<String> signup(@Valid @RequestBody SignupRequest request) {
        userService.registerUser(request);
        return ResponseEntity.ok("Signup successful! Please login.");
    }

    // ----------------------- LOGIN -----------------------
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request, HttpServletResponse response) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.username(), request.password())
            );

            User user = userService.getUserByUsername(request.username());

            String jwt = jwtService.generateToken(user.getUsername(), user.getId());

            // ---- FIX: CREATE COOKIE MANUALLY ----
            String cookieValue =
                    "jwt=" + jwt +
                            "; Path=/" +
                            "; Max-Age=" + (24 * 60 * 60) + // 1 day
                            "; HttpOnly" +
                            "; SameSite=None" +
                            "; Secure=" + secure;

            response.setHeader("Set-Cookie", cookieValue);

            return ResponseEntity.ok(new LoginSuccessResponse(true, "Login successful", user.getName()));

        } catch (Exception e) {
            return ResponseEntity.status(401).body("Wrong username or password");
        }
    }


    // ----------------------- LOGOUT -----------------------
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {

        ResponseCookie cookie = ResponseCookie.from("jwt", "")
                .httpOnly(true)
                .secure(secure)      // false in local, true in prod
                .sameSite(sameSite)  // None for cross-site cookies
                .path("/")
                .maxAge(0)           // deletes cookie
                .build();

        response.setHeader("Set-Cookie", cookie.toString());

        return ResponseEntity.ok(new ApiResponse(true, "Logged out successfully"));
    }

    record ApiResponse(boolean success, String message) {}

    // ------------------- AUTH CHECK (Used on refresh) -------------------
    @GetMapping("/me")
    public ResponseEntity<?> me(@CookieValue(value = "jwt", required = false) String token) {

        if (token == null || !jwtService.validateToken(token)) {
            return ResponseEntity.status(401).body("Not logged in");
        }

        String username = jwtService.extractUsername(token);
        User user = userService.getUserByUsername(username);

        return ResponseEntity.ok(user);
    }

    // ----------------------- UPDATE PROFILE -----------------------
    @PutMapping("/update")
    public ResponseEntity<?> updateProfile(
            @RequestBody ProfileUpdateRequest request,
            @CookieValue(value = "jwt", required = false) String token) {

        if (token == null || !jwtService.validateToken(token)) {
            return ResponseEntity.status(401).body("Unauthorized");
        }

        String username = jwtService.extractUsername(token);
        User user = userService.getUserByUsername(username);

        user.setName(request.getName());
        user.setBudget(request.getBudget() != null ? request.getBudget() : 0.0);
        user.setCurrency(request.getCurrency() != null ? request.getCurrency() : "INR");

        user.setSymbol(switch (request.getCurrency()) {
            case "USD" -> "$";
            case "EUR" -> "€";
            case "GBP" -> "£";
            default -> "₹";
        });

        userRepository.save(user);

        return ResponseEntity.ok(user);
    }

    record LoginSuccessResponse(boolean success, String message, String username) {}

}
