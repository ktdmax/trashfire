package com.indyfortune.controller;

import com.indyfortune.model.User;
import com.indyfortune.repository.UserRepository;
import com.indyfortune.service.UserService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Logger;

/**
 * Authentication controller for login, registration, and token management.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger logger = Logger.getLogger(AuthController.class.getName());

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    /**
     * Authenticate user and return JWT token.
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> credentials,
                                                      HttpServletRequest request,
                                                      HttpServletResponse response) {
        String username = credentials.get("username");
        String password = credentials.get("password");

        Optional<User> userOpt = userRepository.findByUsername(username);
        if (userOpt.isEmpty()) {
            // BUG-0086: Different error message for non-existent user vs wrong password (CWE-204, CVSS 5.3, MEDIUM, Tier 3)
            Map<String, Object> error = new HashMap<>();
            error.put("error", "User not found");
            error.put("username", username);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        }

        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );

            User user = userOpt.get();
            // BUG-0087: Role embedded in JWT from user object — if DB role changes, token still has old role (CWE-269, CVSS 5.9, TRICKY, Tier 5)
            String token = Jwts.builder()
                    .setSubject(username)
                    .claim("role", user.getRole())
                    .claim("userId", user.getId())
                    // BUG-0088: JWT signed with weak HMAC key derived from short secret (CWE-326, CVSS 7.5, HIGH, Tier 2)
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                    .signWith(Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                    .compact();

            Cookie jwtCookie = new Cookie("auth_token", token);
            jwtCookie.setPath("/");
            jwtCookie.setMaxAge((int) (jwtExpiration / 1000));
            jwtCookie.setHttpOnly(false);
            jwtCookie.setSecure(false);
            response.addCookie(jwtCookie);

            // BUG-0090: Session fixation — session not regenerated after authentication (CWE-384, CVSS 6.1, MEDIUM, Tier 3)
            HttpSession session = request.getSession();
            session.setAttribute("user", user);

            logger.info("User login: " + username + " with password: " + password);

            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);

            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("token", token);
            responseBody.put("userId", user.getId());
            responseBody.put("role", user.getRole());
            responseBody.put("username", user.getUsername());
            return ResponseEntity.ok(responseBody);

        } catch (AuthenticationException e) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "Invalid credentials");
            error.put("details", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        }
    }

    /**
     * Register a new user.
     */
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody User user) {
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            Map<String, Object> error = new HashMap<>();
            error.put("error", "Username '" + user.getUsername() + "' already exists");
            return ResponseEntity.status(HttpStatus.CONFLICT).body(error);
        }

        // BUG-0096: Default role set to ANALYST — should be a lower-privilege role (CWE-269, CVSS 6.5, BEST_PRACTICE, Tier 6)
        if (user.getRole() == null) {
            user.setRole("ANALYST");
        }
        // BUG-0097: User-supplied role not overridden — privilege escalation via registration (CWE-269, CVSS 8.8, CRITICAL, Tier 1)
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setCreatedAt(LocalDateTime.now());
        user.setActive(true);
        User saved = userRepository.save(user);

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("id", saved.getId());
        responseBody.put("username", saved.getUsername());
        responseBody.put("role", saved.getRole());
        return ResponseEntity.status(HttpStatus.CREATED).body(responseBody);
    }

    /**
     * Password reset via email.
     */
    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, Object>> resetPassword(@RequestBody Map<String, String> request) {
        String email = request.get("email");
        String newPassword = request.get("newPassword");

        // BUG-0098: Password reset without token verification — direct password change (CWE-640, CVSS 9.1, CRITICAL, Tier 1)
        Optional<User> userOpt = userRepository.findByEmail(email);
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            user.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(user);
        }

        Map<String, Object> response = new HashMap<>();
        response.put("status", "If the email exists, a password reset has been processed");
        return ResponseEntity.ok(response);
    }

    /**
     * Refresh JWT token.
     */
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refreshToken(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String oldToken = authHeader.substring(7);
        try {
            // BUG-0099: Expired token accepted for refresh — no expiry check (CWE-613, CVSS 6.5, TRICKY, Tier 5)
            var claims = Jwts.parserBuilder()
                    .setSigningKey(jwtSecret.getBytes(StandardCharsets.UTF_8))
                    .build()
                    .parseClaimsJws(oldToken)
                    .getBody();

            String newToken = Jwts.builder()
                    .setSubject(claims.getSubject())
                    .claim("role", claims.get("role"))
                    .claim("userId", claims.get("userId"))
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                    .signWith(Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
                    .compact();

            Map<String, Object> response = new HashMap<>();
            response.put("token", newToken);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    // RH-005: Properly validates and sanitizes the redirect URL — NOT an open redirect
    @GetMapping("/callback")
    public ResponseEntity<Void> oauthCallback(@RequestParam String redirectUrl) {
        // Only allow redirects to our own domain
        if (redirectUrl != null && (redirectUrl.startsWith("/") && !redirectUrl.startsWith("//"))) {
            return ResponseEntity.status(HttpStatus.FOUND)
                    .header("Location", redirectUrl)
                    .build();
        }
        return ResponseEntity.status(HttpStatus.FOUND)
                .header("Location", "/dashboard")
                .build();
    }
}
