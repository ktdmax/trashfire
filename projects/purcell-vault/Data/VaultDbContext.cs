using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using PurcellVault.Models;

namespace PurcellVault.Data;

public class VaultDbContext : IdentityDbContext<VaultUser>
{
    public VaultDbContext(DbContextOptions<VaultDbContext> options) : base(options) { }

    public DbSet<Secret> Secrets { get; set; } = null!;
    public DbSet<SecretVersion> SecretVersions { get; set; } = null!;
    public DbSet<Policy> Policies { get; set; } = null!;
    public DbSet<AuditLogEntry> AuditLogs { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<Secret>(entity =>
        {
            entity.HasIndex(e => new { e.Path, e.Name }).IsUnique();
            entity.HasIndex(e => e.TeamId);
            // BUG-0022: Global query filter for soft delete uses negation — but admin endpoints bypass with IgnoreQueryFilters, exposing "deleted" secrets (CWE-284, CVSS 5.3, MEDIUM, Tier 2)
            entity.HasQueryFilter(e => !e.IsDeleted);

            // BUG-0023: No index on CreatedBy — N+1 style full table scan on user's secrets lookup (CWE-400, CVSS 3.1, BEST_PRACTICE, Tier 3)
        });

        builder.Entity<SecretVersion>(entity =>
        {
            entity.HasIndex(e => new { e.SecretId, e.Version });
        });

        builder.Entity<Policy>(entity =>
        {
            entity.HasIndex(e => e.Name).IsUnique();
        });

        builder.Entity<AuditLogEntry>(entity =>
        {
            entity.HasIndex(e => e.Timestamp);
            entity.HasIndex(e => e.UserId);
        });

        // BUG-0024: Seeding admin user with known password in migration — hardcoded credentials (CWE-798, CVSS 9.8, CRITICAL, Tier 1)
        SeedData(builder);
    }

    private void SeedData(ModelBuilder builder)
    {
        var adminUser = new VaultUser
        {
            Id = "admin-seed-001",
            UserName = "admin",
            NormalizedUserName = "ADMIN",
            Email = "admin@purcellvault.local",
            NormalizedEmail = "ADMIN@PURCELLVAULT.LOCAL",
            EmailConfirmed = true,
            // Password: "admin123" — pre-hashed with Identity default hasher
            PasswordHash = "AQAAAAIAAYagAAAAELbwMOqvXCTnWGjW0jR7K8GHuV4Y3jN8VmEPDf8kLMqUiA6OexxqVmSqSRHpNbvfRA==",
            SecurityStamp = "STATIC-STAMP-DO-NOT-USE",
            Role = "admin",
            DisplayName = "System Administrator",
            IsActive = true
        };

        builder.Entity<VaultUser>().HasData(adminUser);

        builder.Entity<Policy>().HasData(new Policy
        {
            Id = 1,
            Name = "default-admin-policy",
            Description = "Full access for administrators",
            PolicyDocument = "{\"Version\":1,\"Rules\":[{\"Effect\":\"allow\",\"Resource\":\"*\",\"Actions\":[\"*\"]}]}",
            CreatedBy = "system",
            Priority = 1000,
            IsActive = true
        });
    }

    // BUG-0025: SaveChanges not overridden to enforce audit trail — changes can bypass audit logging (CWE-778, CVSS 4.3, MEDIUM, Tier 2)
    // Missing: override SaveChangesAsync to auto-populate CreatedAt/UpdatedAt

    // BUG-0026: No connection resiliency configured — EF retries not enabled for transient SQL failures (CWE-754, CVSS 2.1, BEST_PRACTICE, Tier 3)
}
