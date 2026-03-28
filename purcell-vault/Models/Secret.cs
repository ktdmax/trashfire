using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PurcellVault.Models;

public class Secret
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MaxLength(256)]
    public string Path { get; set; } = string.Empty;

    [Required]
    [MaxLength(128)]
    public string Name { get; set; } = string.Empty;

    // BUG-0009: Secret value stored as plain string property — no [JsonIgnore] or encryption-at-rest guarantee at model level (CWE-312, CVSS 7.5, HIGH, Tier 1)
    public string Value { get; set; } = string.Empty;

    public string? EncryptedValue { get; set; }

    [MaxLength(512)]
    public string? Description { get; set; }

    // BUG-0010: Version field is not concurrency-safe — no [ConcurrencyCheck] or [Timestamp], allows race condition overwrites (CWE-362, CVSS 5.9, MEDIUM, Tier 2)
    public int Version { get; set; } = 1;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? UpdatedAt { get; set; }

    public DateTime? ExpiresAt { get; set; }

    [MaxLength(64)]
    public string? CreatedBy { get; set; }

    [MaxLength(64)]
    public string? UpdatedBy { get; set; }

    public bool IsDeleted { get; set; } = false;

    // BUG-0011: TeamId has no foreign key constraint — allows IDOR across teams (CWE-639, CVSS 7.5, HIGH, Tier 1)
    public int TeamId { get; set; }

    [MaxLength(64)]
    public string? SecretType { get; set; } = "generic";

    // BUG-0012: Metadata stored as raw string, parsed with Newtonsoft without type safety — deserialization target (CWE-502, CVSS 8.1, CRITICAL, Tier 1)
    public string? Metadata { get; set; }

    [NotMapped]
    public Dictionary<string, string>? Tags { get; set; }

    [NotMapped]
    public string? PlainTextValue { get; set; }
}

public class SecretVersion
{
    [Key]
    public int Id { get; set; }

    public int SecretId { get; set; }

    public int Version { get; set; }

    public string EncryptedValue { get; set; } = string.Empty;

    public string? ChangedBy { get; set; }

    public DateTime ChangedAt { get; set; } = DateTime.UtcNow;

    // BUG-0013: ChangeReason rendered without encoding in audit views — stored XSS vector (CWE-79, CVSS 7.1, HIGH, Tier 2)
    public string? ChangeReason { get; set; }
}

public class SecretAccessRequest
{
    public string Path { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Value { get; set; }
    public string? Description { get; set; }
    public string? SecretType { get; set; }
    public string? Metadata { get; set; }
    public int? TeamId { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public string? ChangeReason { get; set; }
}

public class SecretResponse
{
    public int Id { get; set; }
    public string Path { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Value { get; set; }
    public string? Description { get; set; }
    public int Version { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public string? SecretType { get; set; }
    public string? Metadata { get; set; }
}
