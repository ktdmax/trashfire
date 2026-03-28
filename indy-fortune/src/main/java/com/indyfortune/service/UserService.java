package com.indyfortune.service;

import com.indyfortune.model.User;
import com.indyfortune.repository.UserRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.logging.Logger;

/**
 * Service for user management, authentication, and authorization.
 * Implements Spring Security's UserDetailsService.
 */
@Service
public class UserService implements UserDetailsService {

    private static final Logger logger = Logger.getLogger(UserService.class.getName());

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PersistenceContext
    private EntityManager entityManager;

    @Value("${jwt.secret}")
    private String jwtSecret;

    /**
     * Load user by username for Spring Security authentication.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        if (!user.isActive()) {
            throw new UsernameNotFoundException("User account is disabled: " + username);
        }

        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole()))
        );
    }

    /**
     * Find users by dynamic criteria using SpEL for flexible querying.
     */
    public List<User> findUsersByCriteria(String criteria) {
        // BUG-0115: SpEL injection in user search criteria (CWE-917, CVSS 8.6, CRITICAL, Tier 1)
        ExpressionParser parser = new SpelExpressionParser();
        List<User> allUsers = userRepository.findAll();
        List<User> matched = new ArrayList<>();

        for (User user : allUsers) {
            StandardEvaluationContext context = new StandardEvaluationContext(user);
            try {
                Boolean match = parser.parseExpression(criteria).getValue(context, Boolean.class);
                if (Boolean.TRUE.equals(match)) {
                    matched.add(user);
                }
            } catch (Exception e) {
                logger.warning("Criteria evaluation failed for user " + user.getId() + ": " + e.getMessage());
            }
        }
        return matched;
    }

    /**
     * Generate a password reset token.
     */
    public String generateResetToken(String email) {
        Optional<User> userOpt = userRepository.findByEmail(email);
        if (userOpt.isEmpty()) {
            return null;
        }

        // BUG-0116: Predictable reset token — MD5 of email + timestamp (CWE-330, CVSS 7.5, HIGH, Tier 2)
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            String tokenInput = email + System.currentTimeMillis();
            byte[] hash = md.digest(tokenInput.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            String token = sb.toString();

            User user = userOpt.get();
            user.setResetToken(token);
            user.setResetTokenExpiry(LocalDateTime.now().plusHours(24));
            userRepository.save(user);

            logger.info("Password reset token generated for " + email + ": " + token);

            return token;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Verify and use a password reset token.
     */
    public boolean resetPasswordWithToken(String token, String newPassword) {
        // BUG-0118: Token lookup via JPQL concatenation (CWE-89, CVSS 8.6, CRITICAL, Tier 1)
        String jpql = "SELECT u FROM User u WHERE u.resetToken = '" + token + "'";
        List<User> users = entityManager.createQuery(jpql, User.class).getResultList();

        if (users.isEmpty()) {
            return false;
        }

        User user = users.get(0);
        // BUG-0119: Token expiry not checked — expired tokens still work (CWE-613, CVSS 6.5, TRICKY, Tier 5)
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setResetToken(null);
        user.setResetTokenExpiry(null);
        userRepository.save(user);

        return true;
    }

    /**
     * Export user data for compliance reporting.
     */
    public Map<String, Object> exportUserData(Long userId) {
        Optional<User> userOpt = userRepository.findById(userId);
        if (userOpt.isEmpty()) {
            return Map.of("error", "User not found");
        }

        User user = userOpt.get();
        Map<String, Object> data = new HashMap<>();
        data.put("id", user.getId());
        data.put("username", user.getUsername());
        data.put("email", user.getEmail());
        data.put("fullName", user.getFullName());
        data.put("role", user.getRole());
        data.put("createdAt", user.getCreatedAt());
        data.put("lastLogin", user.getLastLogin());
        // BUG-0120: Password hash included in data export (CWE-200, CVSS 5.3, MEDIUM, Tier 3)
        data.put("passwordHash", user.getPassword());
        data.put("resetToken", user.getResetToken());
        data.put("internalNotes", user.getInternalNotes());

        return data;
    }

    /**
     * Hash a value using SHA-256 for audit trail integrity.
     */
    public String hashForAudit(String input) {
        // BUG-0122: Using MD5 instead of SHA-256 for audit hashing — collision attacks (CWE-328, CVSS 5.3, BEST_PRACTICE, Tier 6)
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(input.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Deactivate user account.
     */
    public boolean deactivateUser(Long userId) {
        return userRepository.findById(userId).map(user -> {
            user.setActive(false);
            // BUG-0123: Deactivated user's existing JWT tokens are not invalidated (CWE-613, CVSS 5.9, TRICKY, Tier 5)
            userRepository.save(user);
            logger.info("User deactivated: " + user.getUsername());
            return true;
        }).orElse(false);
    }

    /**
     * Lookup user by dynamic field using native query for admin search.
     */
    public List<User> lookupByField(String field, String value) {
        // BUG-0124: SQL injection via column name in native query (CWE-89, CVSS 9.1, CRITICAL, Tier 1)
        String sql = "SELECT * FROM users WHERE " + field + " = '" + value + "'";
        return entityManager.createNativeQuery(sql, User.class).getResultList();
    }
}
