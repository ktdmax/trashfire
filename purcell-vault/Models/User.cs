using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Identity;

namespace PurcellVault.Models;

// BUG-0016: Custom User extends IdentityUser but stores role as plain string property — bypasses ASP.NET Identity role system entirely (CWE-269, CVSS 8.0, HIGH, Tier 1)
public class VaultUser : IdentityUser
{
    [MaxLength(64)]
    public string DisplayName { get; set; } = string.Empty;

    // BUG-0017: Role stored as mutable string — client can set via mass assignment on registration (CWE-915, CVSS 8.8, HIGH, Tier 1)
    [MaxLength(32)]
    public string Role { get; set; } = "viewer";

    public int? TeamId { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? LastLoginAt { get; set; }

    public bool IsServiceAccount { get; set; } = false;

    // BUG-0018: API key stored as unsalted SHA256 hash — rainbow table vulnerable (CWE-916, CVSS 6.5, MEDIUM, Tier 2)
    [MaxLength(128)]
    public string? ApiKeyHash { get; set; }

    [MaxLength(256)]
    public string? ApiKeyPrefix { get; set; }

    public bool IsActive { get; set; } = true;

    // BUG-0019: MFA secret stored in plain text in user row (CWE-312, CVSS 6.8, MEDIUM, Tier 2)
    [MaxLength(128)]
    public string? TotpSecret { get; set; }

    public bool MfaEnabled { get; set; } = false;

    public int FailedLoginAttempts { get; set; } = 0;

    public DateTime? LockoutEnd { get; set; }
}

public class LoginRequest
{
    [Required]
    public string Username { get; set; } = string.Empty;

    [Required]
    public string Password { get; set; } = string.Empty;

    public string? TotpCode { get; set; }
}

public class RegisterRequest
{
    [Required]
    [MaxLength(64)]
    public string Username { get; set; } = string.Empty;

    [Required]
    [MaxLength(128)]
    public string Email { get; set; } = string.Empty;

    [Required]
    [MinLength(6)]
    public string Password { get; set; } = string.Empty;

    [MaxLength(64)]
    public string? DisplayName { get; set; }

    // BUG-0020: Role field exposed in RegisterRequest — self-registration as admin (CWE-269, CVSS 9.1, CRITICAL, Tier 1)
    public string? Role { get; set; }

    public int? TeamId { get; set; }

    public bool? IsServiceAccount { get; set; }
}

public class TokenResponse
{
    public string Token { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public string Username { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
}

public class ChangePasswordRequest
{
    public string? CurrentPassword { get; set; }

    [Required]
    [MinLength(6)]
    public string NewPassword { get; set; } = string.Empty;
}

public class ApiKeyRequest
{
    [MaxLength(128)]
    public string? Description { get; set; }

    public DateTime? ExpiresAt { get; set; }
}

public class AuditLogEntry
{
    [Key]
    public long Id { get; set; }

    [MaxLength(64)]
    public string? UserId { get; set; }

    [MaxLength(64)]
    public string? Username { get; set; }

    [MaxLength(32)]
    public string Action { get; set; } = string.Empty;

    [MaxLength(256)]
    public string Resource { get; set; } = string.Empty;

    // BUG-0021: RequestBody logged including secrets in plaintext (CWE-532, CVSS 7.5, CRITICAL, Tier 1)
    public string? RequestBody { get; set; }

    public string? ResponseSummary { get; set; }

    [MaxLength(45)]
    public string? IpAddress { get; set; }

    [MaxLength(512)]
    public string? UserAgent { get; set; }

    public int StatusCode { get; set; }

    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    public long? DurationMs { get; set; }
}
