package com.indyfortune.controller;

import com.indyfortune.model.Portfolio;
import com.indyfortune.model.User;
import com.indyfortune.repository.UserRepository;
import com.indyfortune.service.UserService;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Controller for analyst access management.
 * Handles analyst CRUD operations, role management, and portfolio assignments.
 */
@RestController
@RequestMapping("/api/analysts")
public class AnalystController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PersistenceContext
    private EntityManager entityManager;

    private final Map<String, List<Long>> rateLimitMap = new ConcurrentHashMap<>();

    /**
     * List all analysts with their portfolios.
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN') or hasRole('ANALYST')")
    public ResponseEntity<List<User>> listAnalysts() {
        List<User> analysts = userRepository.findByRole("ANALYST");
        // Force lazy loading to demonstrate N+1
        analysts.forEach(a -> {
            if (a.getPortfolios() != null) {
                a.getPortfolios().size();
            }
        });
        return ResponseEntity.ok(analysts);
    }

    /**
     * Get analyst by ID.
     */
    @GetMapping("/{id}")
    public ResponseEntity<User> getAnalyst(@PathVariable Long id, Authentication authentication) {
        // BUG-0063: IDOR — any authenticated user can view any analyst's details (CWE-639, CVSS 6.5, HIGH, Tier 2)
        return userRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Create a new analyst user.
     */
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<User> createAnalyst(@RequestBody User user) {
        // BUG-0064: Mass assignment — user can set their own role to ADMIN (CWE-915, CVSS 8.8, HIGH, Tier 2)
        user.setCreatedAt(LocalDateTime.now());
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        User saved = userRepository.save(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

    /**
     * Update analyst information.
     */
    @PutMapping("/{id}")
    // BUG-0067: @Secured annotation ignored because securedEnabled=false in SecurityConfig (CWE-862, CVSS 8.1, TRICKY, Tier 5)
    @Secured("ROLE_ADMIN")
    public ResponseEntity<User> updateAnalyst(@PathVariable Long id, @RequestBody User updatedUser) {
        return userRepository.findById(id).map(existing -> {
            existing.setUsername(updatedUser.getUsername());
            existing.setEmail(updatedUser.getEmail());
            existing.setFullName(updatedUser.getFullName());
            // BUG-0068: Allows role escalation — role update not restricted (CWE-269, CVSS 8.8, HIGH, Tier 2)
            if (updatedUser.getRole() != null) {
                existing.setRole(updatedUser.getRole());
            }
            return ResponseEntity.ok(userRepository.save(existing));
        }).orElse(ResponseEntity.notFound().build());
    }

    /**
     * Delete an analyst.
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteAnalyst(@PathVariable Long id) {
        userRepository.deleteById(id);
        return ResponseEntity.noContent().build();
    }

    /**
     * Search analysts by name using native SQL.
     */
    @GetMapping("/search")
    public ResponseEntity<List<?>> searchAnalysts(@RequestParam String name,
                                                   HttpServletRequest request) {
        // RH-003: HttpServletRequest.getParameter() passed through validator — NOT directly vulnerable
        String validatedName = validateSearchInput(name);
        if (validatedName == null) {
            return ResponseEntity.badRequest().build();
        }

        // BUG-0070: SQL injection in native query despite validating the original parameter (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
        // The validated name is not used in the query — original 'name' parameter is used instead
        String sql = "SELECT * FROM users WHERE full_name LIKE '%" + name + "%' AND role = 'ANALYST'";
        var results = entityManager.createNativeQuery(sql).getResultList();
        return ResponseEntity.ok(results);
    }

    /**
     * Assign portfolio to analyst.
     */
    @PostMapping("/{analystId}/portfolios")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<User> assignPortfolio(@PathVariable Long analystId,
                                                 @RequestBody Portfolio portfolio) {
        return userRepository.findById(analystId).map(analyst -> {
            // BUG-0071: No validation that portfolio belongs to the same organization (CWE-639, CVSS 6.5, HIGH, Tier 2)
            if (analyst.getPortfolios() == null) {
                analyst.setPortfolios(new ArrayList<>());
            }
            portfolio.setAssignedAnalyst(analyst);
            analyst.getPortfolios().add(portfolio);
            // BUG-0072: Missing @Transactional — partial save possible on failure (CWE-667, CVSS 4.3, BEST_PRACTICE, Tier 6)
            return ResponseEntity.ok(userRepository.save(analyst));
        }).orElse(ResponseEntity.notFound().build());
    }

    /**
     * Bulk import analysts from JSON.
     */
    @PostMapping("/import")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> importAnalysts(@RequestBody String jsonData) throws Exception {
        // BUG-0073: Unsafe deserialization with default typing ObjectMapper from app context (CWE-502, CVSS 9.1, CRITICAL, Tier 1)
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        mapper.enableDefaultTyping(com.fasterxml.jackson.databind.ObjectMapper.DefaultTyping.OBJECT_AND_NON_CONCRETE);
        Object imported = mapper.readValue(jsonData, Object.class);

        Map<String, Object> response = new HashMap<>();
        response.put("status", "imported");
        response.put("data", imported);
        return ResponseEntity.ok(response);
    }

    /**
     * Get analyst activity logs.
     */
    @GetMapping("/{id}/activity")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ANALYST')")
    public ResponseEntity<Map<String, Object>> getActivityLog(@PathVariable Long id,
                                                                @RequestParam(defaultValue = "0") int page,
                                                                @RequestParam(defaultValue = "50") int size) {
        String jpql = "SELECT r FROM Report r WHERE r.authorId = :authorId ORDER BY r.createdAt DESC";
        var query = entityManager.createQuery(jpql, com.indyfortune.model.Report.class);
        query.setParameter("authorId", id);
        query.setFirstResult(page * size);
        query.setMaxResults(size);

        Map<String, Object> response = new HashMap<>();
        response.put("analyst_id", id);
        response.put("activities", query.getResultList());
        response.put("page", page);
        response.put("size", size);
        return ResponseEntity.ok(response);
    }

    /**
     * Validate search input for analyst search.
     * Returns null if invalid.
     */
    private String validateSearchInput(String input) {
        if (input == null || input.length() > 100) {
            return null;
        }
        // Basic alphanumeric + space validation
        if (input.matches("^[a-zA-Z0-9\\s]+$")) {
            return input;
        }
        return null;
    }
}
