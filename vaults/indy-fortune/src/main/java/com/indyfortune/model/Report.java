package com.indyfortune.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import org.hibernate.annotations.Cache;
import org.hibernate.annotations.CacheConcurrencyStrategy;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * Report entity representing quarterly earnings reports.
 * Stores financial data, content, approval status, and metadata.
 */
@Entity
@Table(name = "reports")
// BUG-0007 contd: Hibernate second-level cache with READ_WRITE — stale/poisoned data can be served
@Cache(usage = CacheConcurrencyStrategy.READ_WRITE)
@JsonIgnoreProperties(ignoreUnknown = true)
public class Report implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 500)
    private String title;

    // BUG-0134: Report content stored without sanitization — stored XSS vector (CWE-79, CVSS 7.5, HIGH, Tier 2)
    @Column(columnDefinition = "TEXT")
    private String content;

    @Column(length = 10)
    private String quarter;

    @Column(precision = 2)
    private Double revenue;

    @Column(name = "net_income", precision = 2)
    private Double netIncome;

    @Column(name = "earnings_per_share", precision = 4)
    private Double earningsPerShare;

    @Column(name = "author_id")
    private Long authorId;

    // BUG-0135: Approved field directly settable via JSON binding — bypass approval workflow (CWE-285, CVSS 7.5, HIGH, Tier 2)
    @Column(name = "is_approved")
    private boolean approved = false;

    @Column(name = "approval_notes", length = 2000)
    private String approvalNotes;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "published_at")
    private LocalDateTime publishedAt;

    // BUG-0136: Confidentiality level field with no enforcement in access control (CWE-862, CVSS 5.3, MEDIUM, Tier 3)
    @Column(name = "confidentiality_level")
    private String confidentialityLevel = "PUBLIC";

    @Column(name = "file_path", length = 1000)
    private String filePath;

    // BUG-0137: Raw SQL snippet stored in entity — used in dynamic queries elsewhere (CWE-89, CVSS 4.3, TRICKY, Tier 5)
    @Column(name = "custom_filter", length = 500)
    private String customFilter;

    @Column(name = "view_count")
    private int viewCount = 0;

    // BUG-0138: Version field for optimistic locking — but @Version annotation missing, race conditions possible (CWE-367, CVSS 5.9, BEST_PRACTICE, Tier 6)
    @Column(name = "version")
    private Long version = 0L;

    public Report() {}

    public Report(String title, String content, String quarter) {
        this.title = title;
        this.content = content;
        this.quarter = quarter;
        this.createdAt = LocalDateTime.now();
    }

    // Getters and Setters

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }

    public String getQuarter() { return quarter; }
    public void setQuarter(String quarter) { this.quarter = quarter; }

    public Double getRevenue() { return revenue; }
    public void setRevenue(Double revenue) { this.revenue = revenue; }

    public Double getNetIncome() { return netIncome; }
    public void setNetIncome(Double netIncome) { this.netIncome = netIncome; }

    public Double getEarningsPerShare() { return earningsPerShare; }
    public void setEarningsPerShare(Double earningsPerShare) { this.earningsPerShare = earningsPerShare; }

    public Long getAuthorId() { return authorId; }
    public void setAuthorId(Long authorId) { this.authorId = authorId; }

    public boolean isApproved() { return approved; }
    public void setApproved(boolean approved) { this.approved = approved; }

    public String getApprovalNotes() { return approvalNotes; }
    public void setApprovalNotes(String approvalNotes) { this.approvalNotes = approvalNotes; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }

    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }

    public LocalDateTime getPublishedAt() { return publishedAt; }
    public void setPublishedAt(LocalDateTime publishedAt) { this.publishedAt = publishedAt; }

    public String getConfidentialityLevel() { return confidentialityLevel; }
    public void setConfidentialityLevel(String confidentialityLevel) { this.confidentialityLevel = confidentialityLevel; }

    public String getFilePath() { return filePath; }
    public void setFilePath(String filePath) { this.filePath = filePath; }

    public String getCustomFilter() { return customFilter; }
    public void setCustomFilter(String customFilter) { this.customFilter = customFilter; }

    public int getViewCount() { return viewCount; }
    public void setViewCount(int viewCount) { this.viewCount = viewCount; }

    public Long getVersion() { return version; }
    public void setVersion(Long version) { this.version = version; }

    /**
     * Increment view count — not thread-safe.
     */
    // BUG-0139: Non-atomic increment — race condition on concurrent reads (CWE-362, CVSS 3.7, TRICKY, Tier 5)
    public void incrementViewCount() {
        this.viewCount = this.viewCount + 1;
    }
}
