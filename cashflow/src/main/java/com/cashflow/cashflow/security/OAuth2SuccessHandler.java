// File: src/main/java/com/cashflow/cashflow/security/OAuth2SuccessHandler.java

package com.cashflow.cashflow.security;

import com.cashflow.cashflow.entity.User;
import com.cashflow.cashflow.repository.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");

        if (email == null || email.isBlank()) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("Email not provided");
            return;
        }

        User user = userRepository.findByEmail(email)
                .orElseGet(() -> registerNewOAuthUser(email, name));

        String token = jwtService.generateToken(user.getUsername(), user.getId());
        setJwtCookie(response, token);

        log.info("OAuth2 login successful: {}", email);

        // THIS IS THE MAGIC PART – tiny HTML page that closes popup + notifies parent
        response.setContentType("text/html");
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().write("""
        <script>
            // Send message to parent window (login.html)
            if (window.opener) {
                window.opener.postMessage({
                    success: true,
                    redirect: "/dashboard.html"
                }, "*");
            }
            // Also just redirect this popup to dashboard as fallback
            window.location.href = "/dashboard.html";
        </script>
        """);
    }

    private User registerNewOAuthUser(String email, String name) {
        log.info("Creating new user from OAuth2: {}", email);

        User newUser = new User();
        newUser.setEmail(email);
        newUser.setUsername(email.substring(0, email.indexOf('@')));
        newUser.setName(name != null ? name : "User");
        newUser.setCurrency("INR");
        newUser.setSymbol("₹");
        newUser.setBudget(0.0);
        newUser.setCreatedAt(LocalDateTime.now());
        newUser.setRole("USER");
        newUser.setPassword(passwordEncoder.encode(UUID.randomUUID().toString()));

        return userRepository.save(newUser);
    }

    private void setJwtCookie(HttpServletResponse response, String token) {
        Cookie cookie = new Cookie("jwt", token);
        cookie.setHttpOnly(true);
        cookie.setSecure(false);           // Change to true in production (HTTPS)
        cookie.setPath("/");
        cookie.setMaxAge(24 * 60 * 60);    // 24 hours
        cookie.setAttribute("SameSite", "Lax"); // or "None" if cross-site (with Secure=true)

        response.addCookie(cookie);
    }
}