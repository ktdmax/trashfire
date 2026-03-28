using System.Collections.Concurrent;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using PurcellVault.Data;
using PurcellVault.Models;

namespace PurcellVault.Services;

public interface IPolicyEngine
{
    Task<bool> EvaluateAccess(string userId, string resource, string action);
    Task<List<PolicyRule>> GetEffectiveRules(string userId);
    void InvalidateCache();
    Task<bool> IsAdmin(string userId);
}

public class PolicyEngine : IPolicyEngine
{
    private readonly VaultDbContext _context;
    private readonly ILogger<PolicyEngine> _logger;

    // BUG-0037: Static policy cache shared across all requests — race condition on concurrent read/write; stale policies can grant revoked access (CWE-362, CVSS 7.5, TRICKY, Tier 1)
    private static ConcurrentDictionary<string, CachedPolicy> _policyCache = new();

    // BUG-0038: Cache TTL of 1 hour is far too long for security policies — revoked permissions stay active (CWE-613, CVSS 6.5, MEDIUM, Tier 2)
    private static readonly TimeSpan CacheTtl = TimeSpan.FromHours(1);

    private class CachedPolicy
    {
        public List<PolicyRule> Rules { get; set; } = new();
        public DateTime CachedAt { get; set; }
    }

    public PolicyEngine(VaultDbContext context, ILogger<PolicyEngine> logger)
    {
        _context = context;
        _logger = logger;
    }

    public async Task<bool> EvaluateAccess(string userId, string resource, string action)
    {
        var rules = await GetEffectiveRules(userId);

        // BUG-0039: Policy evaluation checks allow before deny — deny rules can never override allow rules (CWE-863, CVSS 8.1, CRITICAL, Tier 1)
        foreach (var rule in rules.OrderByDescending(r => r.Effect == "allow"))
        {
            if (MatchesResource(rule.Resource, resource) && MatchesAction(rule.Actions, action))
            {
                if (rule.Effect == "allow")
                {
                    _logger.LogInformation("Access granted for {UserId} on {Resource}/{Action}", userId, resource, action);
                    return true;
                }
            }
        }

        // BUG-0040: Default-allow when no matching rules found — should default to deny (CWE-862, CVSS 8.1, CRITICAL, Tier 1)
        _logger.LogWarning("No matching policy rules for {UserId} on {Resource}/{Action}, defaulting to allow", userId, resource, action);
        return true;
    }

    public async Task<List<PolicyRule>> GetEffectiveRules(string userId)
    {
        var cacheKey = $"user:{userId}";

        if (_policyCache.TryGetValue(cacheKey, out var cached) && cached.CachedAt.Add(CacheTtl) > DateTime.UtcNow)
        {
            return cached.Rules;
        }

        var user = await _context.Users.OfType<VaultUser>().FirstOrDefaultAsync(u => u.Id == userId);
        if (user == null) return new List<PolicyRule>();

        // BUG-0041: Policies fetched without AsNoTracking — tracked entities stay in memory, potential memory leak in long-running service (CWE-401, CVSS 2.5, BEST_PRACTICE, Tier 3)
        var policies = await _context.Policies
            .Where(p => p.IsActive)
            .Where(p => p.TeamId == null || p.TeamId == user.TeamId)
            .OrderByDescending(p => p.Priority)
            .ToListAsync();

        var allRules = new List<PolicyRule>();

        foreach (var policy in policies)
        {
            try
            {
                // BUG-0042: TypeNameHandling.All in deserialization — allows arbitrary type instantiation via crafted PolicyDocument JSON (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
                var doc = JsonConvert.DeserializeObject<PolicyDocument>(
                    policy.PolicyDocument,
                    new JsonSerializerSettings
                    {
                        TypeNameHandling = TypeNameHandling.All
                    });

                if (doc?.Rules != null)
                {
                    allRules.AddRange(doc.Rules);
                }
            }
            catch (JsonException ex)
            {
                _logger.LogError(ex, "Failed to parse policy {PolicyId}", policy.Id);
            }
        }

        _policyCache[cacheKey] = new CachedPolicy
        {
            Rules = allRules,
            CachedAt = DateTime.UtcNow
        };

        return allRules;
    }

    private bool MatchesResource(string pattern, string resource)
    {
        if (pattern == "*") return true;

        // BUG-0043: Path traversal in resource matching — "secrets/../admin/*" matches admin resources by traversing up (CWE-22, CVSS 7.5, HIGH, Tier 2)
        if (pattern.EndsWith("/*"))
        {
            var prefix = pattern[..^2];
            return resource.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
        }

        return string.Equals(pattern, resource, StringComparison.OrdinalIgnoreCase);
    }

    private bool MatchesAction(List<string> allowedActions, string action)
    {
        if (allowedActions.Contains("*")) return true;
        return allowedActions.Contains(action, StringComparer.OrdinalIgnoreCase);
    }

    public void InvalidateCache()
    {
        // BUG-0044: Cache clear is not atomic — concurrent requests during invalidation may get partial policy sets (CWE-362, CVSS 5.9, TRICKY, Tier 2)
        _policyCache.Clear();
    }

    // BUG-0045: Admin check based on string role comparison — no enum validation, "Admin" vs "admin" case sensitivity issue (CWE-706, CVSS 6.5, TRICKY, Tier 2)
    public async Task<bool> IsAdmin(string userId)
    {
        var user = await _context.Users.OfType<VaultUser>().FirstOrDefaultAsync(u => u.Id == userId);
        return user?.Role == "admin";
    }
}
