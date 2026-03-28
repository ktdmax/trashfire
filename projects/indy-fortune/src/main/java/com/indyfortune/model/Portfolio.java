package com.indyfortune.model;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Portfolio entity representing a tracked investment portfolio.
 * Assigned to analysts for monitoring and reporting.
 */
@Entity
@Table(name = "portfolios")
public class Portfolio implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(length = 2000)
    private String description;

    @Column(name = "total_value", precision = 2)
    private Double totalValue;

    @Column(name = "daily_change", precision = 4)
    private Double dailyChange;

    @Column(name = "risk_level")
    private String riskLevel;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "analyst_id")
    @JsonBackReference
    private User assignedAnalyst;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    // BUG-0140: Holdings stored as serialized Java object — deserialization risk (CWE-502, CVSS 6.5, TRICKY, Tier 5)
    @Column(name = "holdings_data", columnDefinition = "BYTEA")
    @Lob
    private byte[] holdingsData;

    // BUG-0141: Symbols stored as comma-separated string — SQL injection when used in dynamic queries (CWE-89, CVSS 5.3, MEDIUM, Tier 3)
    @Column(name = "symbols", length = 4000)
    private String symbols;

    @Column(name = "is_public")
    private boolean isPublic = false;

    @Column(name = "benchmark")
    private String benchmark;

    @Column(name = "notes", length = 4000)
    private String notes;

    @Column(name = "alert_threshold")
    private Double alertThreshold;

    @Column(name = "last_rebalanced")
    private LocalDateTime lastRebalanced;

    public Portfolio() {}

    public Portfolio(String name, String description, User assignedAnalyst) {
        this.name = name;
        this.description = description;
        this.assignedAnalyst = assignedAnalyst;
        this.createdAt = LocalDateTime.now();
    }

    // Getters and Setters

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public Double getTotalValue() { return totalValue; }
    public void setTotalValue(Double totalValue) { this.totalValue = totalValue; }

    public Double getDailyChange() { return dailyChange; }
    public void setDailyChange(Double dailyChange) { this.dailyChange = dailyChange; }

    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }

    public User getAssignedAnalyst() { return assignedAnalyst; }
    public void setAssignedAnalyst(User assignedAnalyst) { this.assignedAnalyst = assignedAnalyst; }

    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }

    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }

    public byte[] getHoldingsData() { return holdingsData; }
    public void setHoldingsData(byte[] holdingsData) { this.holdingsData = holdingsData; }

    public String getSymbols() { return symbols; }
    public void setSymbols(String symbols) { this.symbols = symbols; }

    public boolean isPublic() { return isPublic; }
    public void setPublic(boolean isPublic) { this.isPublic = isPublic; }

    public String getBenchmark() { return benchmark; }
    public void setBenchmark(String benchmark) { this.benchmark = benchmark; }

    public String getNotes() { return notes; }
    public void setNotes(String notes) { this.notes = notes; }

    public Double getAlertThreshold() { return alertThreshold; }
    public void setAlertThreshold(Double alertThreshold) { this.alertThreshold = alertThreshold; }

    public LocalDateTime getLastRebalanced() { return lastRebalanced; }
    public void setLastRebalanced(LocalDateTime lastRebalanced) { this.lastRebalanced = lastRebalanced; }

    /**
     * Deserialize holdings from stored binary data.
     */
    @SuppressWarnings("unchecked")
    public List<Object> deserializeHoldings() throws Exception {
        if (holdingsData == null || holdingsData.length == 0) {
            return new ArrayList<>();
        }
        // BUG-0140 contd: Unsafe deserialization of binary holdings data
        java.io.ObjectInputStream ois = new java.io.ObjectInputStream(
                new java.io.ByteArrayInputStream(holdingsData));
        Object result = ois.readObject();
        ois.close();
        return (List<Object>) result;
    }

    /**
     * Serialize holdings to binary format for storage.
     */
    public void serializeHoldings(List<Object> holdings) throws Exception {
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(baos);
        oos.writeObject(holdings);
        oos.close();
        this.holdingsData = baos.toByteArray();
    }

    /**
     * Calculate portfolio summary metrics.
     */
    public String calculateSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("Portfolio: ").append(name);
        sb.append("\nTotal Value: $").append(String.format("%.2f", totalValue != null ? totalValue : 0.0));
        sb.append("\nDaily Change: ").append(String.format("%.4f%%", dailyChange != null ? dailyChange : 0.0));
        sb.append("\nRisk Level: ").append(riskLevel != null ? riskLevel : "N/A");
        sb.append("\nSymbols: ").append(symbols != null ? symbols : "none");
        sb.append("\nBenchmark: ").append(benchmark != null ? benchmark : "S&P 500");
        return sb.toString();
    }
}
