package com.indyfortune.repository;

import com.indyfortune.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Repository for User entity operations.
 * Provides both Spring Data derived queries and custom JPQL/native queries.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Find user by username for authentication.
     */
    Optional<User> findByUsername(String username);

    /**
     * Find user by email for password reset.
     */
    Optional<User> findByEmail(String email);

    /**
     * Find all users with a given role.
     */
    List<User> findByRole(String role);

    /**
     * Find active users by role.
     */
    List<User> findByRoleAndActiveTrue(String role);

    /**
     * Find users created within a date range.
     */
    List<User> findByCreatedAtBetween(LocalDateTime start, LocalDateTime end);

    // RH-002 contd: Properly parameterized @Query — NOT vulnerable to injection
    @Query("SELECT u FROM User u WHERE u.department = :dept AND u.active = true")
    List<User> findActiveByDepartment(@Param("dept") String department);

    /**
     * Count users by role for dashboard statistics.
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.role = :role AND u.active = true")
    long countActiveByRole(@Param("role") String role);

    /**
     * Find users who haven't logged in recently.
     */
    @Query("SELECT u FROM User u WHERE u.lastLogin < :cutoff OR u.lastLogin IS NULL")
    List<User> findInactiveUsers(@Param("cutoff") LocalDateTime cutoff);

    /**
     * Bulk update user roles.
     */
    @Modifying
    @Query("UPDATE User u SET u.role = :newRole WHERE u.department = :dept")
    int updateRoleByDepartment(@Param("newRole") String newRole, @Param("dept") String department);

    /**
     * Find users by reset token.
     */
    Optional<User> findByResetToken(String resetToken);

    /**
     * Search users by name pattern.
     */
    @Query("SELECT u FROM User u WHERE LOWER(u.fullName) LIKE LOWER(CONCAT('%', :name, '%'))")
    List<User> searchByName(@Param("name") String name);
}
