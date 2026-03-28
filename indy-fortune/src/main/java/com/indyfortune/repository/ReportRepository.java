package com.indyfortune.repository;

import com.indyfortune.model.Report;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Repository for Report entity operations.
 * Provides both Spring Data derived queries and custom JPQL/native queries.
 */
@Repository
public interface ReportRepository extends JpaRepository<Report, Long> {

    /**
     * Find reports by quarter (properly parameterized).
     */
    // RH-002 contd: @Query with proper parameterized binding — NOT vulnerable
    @Query("SELECT r FROM Report r WHERE r.quarter = :quarter ORDER BY r.createdAt DESC")
    List<Report> findByQuarter(@Param("quarter") String quarter);

    /**
     * Find reports by author.
     */
    List<Report> findByAuthorId(Long authorId);

    /**
     * Find approved reports for public display.
     */
    List<Report> findByApprovedTrue();

    /**
     * Find reports created before a given date (for archival).
     */
    List<Report> findByCreatedAtBefore(LocalDateTime cutoff);

    /**
     * Find reports created after a given date (for weekly summaries).
     */
    List<Report> findByCreatedAtAfter(LocalDateTime cutoff);

    /**
     * Find reports by confidentiality level.
     */
    List<Report> findByConfidentialityLevel(String level);

    /**
     * Search reports by title pattern.
     */
    @Query("SELECT r FROM Report r WHERE LOWER(r.title) LIKE LOWER(CONCAT('%', :title, '%'))")
    List<Report> searchByTitle(@Param("title") String title);

    /**
     * Count reports by quarter for statistics.
     */
    @Query("SELECT COUNT(r) FROM Report r WHERE r.quarter = :quarter")
    long countByQuarter(@Param("quarter") String quarter);

    /**
     * Find reports with revenue above threshold.
     */
    @Query("SELECT r FROM Report r WHERE r.revenue > :threshold ORDER BY r.revenue DESC")
    List<Report> findHighRevenueReports(@Param("threshold") Double threshold);

    /**
     * Aggregate revenue by quarter.
     */
    @Query("SELECT r.quarter, SUM(r.revenue), SUM(r.netIncome) FROM Report r " +
           "WHERE r.approved = true GROUP BY r.quarter ORDER BY r.quarter")
    List<Object[]> aggregateByQuarter();

    /**
     * Bulk approve reports by author.
     */
    @Modifying
    @Query("UPDATE Report r SET r.approved = true WHERE r.authorId = :authorId AND r.approved = false")
    int approveAllByAuthor(@Param("authorId") Long authorId);

    /**
     * Find unapproved reports older than specified date.
     */
    @Query("SELECT r FROM Report r WHERE r.approved = false AND r.createdAt < :cutoff")
    List<Report> findStaleUnapproved(@Param("cutoff") LocalDateTime cutoff);
}
