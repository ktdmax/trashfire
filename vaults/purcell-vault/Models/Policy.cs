using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PurcellVault.Models;

public class Policy
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MaxLength(128)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(512)]
    public string? Description { get; set; }

    // BUG-0014: PolicyDocument stored as JSON string, deserialized with TypeNameHandling — RCE via polymorphic deserialization (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
    [Required]
    public string PolicyDocument { get; set; } = "{}";

    [MaxLength(64)]
    public string? CreatedBy { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? UpdatedAt { get; set; }

    public bool IsActive { get; set; } = true;

    // BUG-0015: Priority as int with no bounds check — negative priority can override deny rules (CWE-269, CVSS 7.2, HIGH, Tier 2)
    public int Priority { get; set; } = 0;

    public int? TeamId { get; set; }
}

public class PolicyRule
{
    public string Effect { get; set; } = "deny"; // "allow" or "deny"

    [MaxLength(256)]
    public string Resource { get; set; } = string.Empty;

    public List<string> Actions { get; set; } = new();

    public List<string>? Principals { get; set; }

    public Dictionary<string, string>? Conditions { get; set; }
}

public class PolicyDocument
{
    public int Version { get; set; } = 1;

    public List<PolicyRule> Rules { get; set; } = new();
}

public class PolicyCreateRequest
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string PolicyDocument { get; set; } = "{}";
    public int Priority { get; set; } = 0;
    public int? TeamId { get; set; }
}

public class PolicyUpdateRequest
{
    public string? Name { get; set; }
    public string? Description { get; set; }
    public string? PolicyDocument { get; set; }
    public int? Priority { get; set; }
    public bool? IsActive { get; set; }
}
