using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using PurcellVault.Data;
using PurcellVault.Models;

namespace PurcellVault.Services;

public interface ISecretStore
{
    Task<Secret?> GetSecret(int id, int? teamId = null);
    Task<Secret?> GetSecretByPath(string path, string name);
    Task<List<Secret>> ListSecrets(int? teamId, string? pathPrefix, string? search);
    Task<Secret> CreateSecret(Secret secret, string userId);
    Task<Secret> UpdateSecret(int id, SecretAccessRequest request, string userId);
    Task<bool> DeleteSecret(int id, string userId);
    Task<List<SecretVersion>> GetVersionHistory(int secretId);
    Task<List<Secret>> SearchSecrets(string query, int? teamId);
    Task<Secret?> GetSecretIncludingDeleted(int id);
    Task BulkImport(IEnumerable<Secret> secrets, string userId);
}

public class SecretStore : ISecretStore
{
    private readonly VaultDbContext _context;
    private readonly IEncryptionService _encryption;
    private readonly ILogger<SecretStore> _logger;

    public SecretStore(VaultDbContext context, IEncryptionService encryption, ILogger<SecretStore> logger)
    {
        _context = context;
        _encryption = encryption;
        _logger = logger;
    }

    public async Task<Secret?> GetSecret(int id, int? teamId = null)
    {
        // BUG-0046: No team-scoping when teamId is null — any user can read any secret by ID (IDOR) (CWE-639, CVSS 7.5, HIGH, Tier 1)
        var query = _context.Secrets.AsQueryable();
        if (teamId.HasValue)
        {
            query = query.Where(s => s.TeamId == teamId.Value);
        }

        var secret = await query.FirstOrDefaultAsync(s => s.Id == id);
        if (secret != null && secret.EncryptedValue != null)
        {
            secret.PlainTextValue = _encryption.Decrypt(secret.EncryptedValue);
        }

        return secret;
    }

    public async Task<Secret?> GetSecretByPath(string path, string name)
    {
        // BUG-0047: Path not sanitized — allows path traversal via "../" sequences (CWE-22, CVSS 7.5, HIGH, Tier 2)
        var secret = await _context.Secrets
            .FirstOrDefaultAsync(s => s.Path == path && s.Name == name);

        if (secret != null && secret.EncryptedValue != null)
        {
            secret.PlainTextValue = _encryption.Decrypt(secret.EncryptedValue);
        }

        return secret;
    }

    public async Task<List<Secret>> ListSecrets(int? teamId, string? pathPrefix, string? search)
    {
        var query = _context.Secrets.AsQueryable();

        if (teamId.HasValue)
        {
            query = query.Where(s => s.TeamId == teamId.Value);
        }

        if (!string.IsNullOrEmpty(pathPrefix))
        {
            query = query.Where(s => s.Path.StartsWith(pathPrefix));
        }

        if (!string.IsNullOrEmpty(search))
        {
            // BUG-0048: String interpolation in FromSqlRaw — LINQ injection / SQL injection via search parameter (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
            query = _context.Secrets.FromSqlRaw(
                $"SELECT * FROM Secrets WHERE Name LIKE '%{search}%' OR Description LIKE '%{search}%' OR Path LIKE '%{search}%'");
        }

        // BUG-0049: No pagination — returns all secrets, potential DoS on large datasets (CWE-400, CVSS 3.1, LOW, Tier 3)
        return await query.ToListAsync();
    }

    // RH-002: This looks like SQL injection but FromSqlInterpolated safely parameterizes the interpolated string (Safe: EF Core parameterizes automatically)
    public async Task<List<Secret>> SafeSearchSecrets(string query)
    {
        return await _context.Secrets
            .FromSqlInterpolated($"SELECT * FROM Secrets WHERE Name LIKE {'%' + query + '%'}")
            .ToListAsync();
    }

    public async Task<Secret> CreateSecret(Secret secret, string userId)
    {
        // BUG-0050: Value stored in both plain and encrypted columns — plaintext remains in DB (CWE-312, CVSS 7.5, HIGH, Tier 1)
        secret.EncryptedValue = _encryption.Encrypt(secret.Value);
        // NOTE: secret.Value is NOT cleared here — it persists in the DB row

        secret.CreatedBy = userId;
        secret.CreatedAt = DateTime.UtcNow;
        secret.Version = 1;

        _context.Secrets.Add(secret);

        // BUG-0051: Logging the secret path and name at Info level — information disclosure in logs (CWE-532, CVSS 4.3, LOW, Tier 3)
        _logger.LogInformation("Secret created: {Path}/{Name} by {UserId} with value length {Length}",
            secret.Path, secret.Name, userId, secret.Value?.Length);

        // BUG-0052: async void-style: not awaiting SaveChangesAsync properly in all code paths — fire-and-forget risk (CWE-367, CVSS 3.1, BEST_PRACTICE, Tier 3)
        await _context.SaveChangesAsync();

        return secret;
    }

    public async Task<Secret> UpdateSecret(int id, SecretAccessRequest request, string userId)
    {
        // BUG-0053: No team scoping on update — any authenticated user can update any secret by ID (CWE-639, CVSS 8.1, HIGH, Tier 1)
        var secret = await _context.Secrets.FindAsync(id);
        if (secret == null)
            throw new KeyNotFoundException($"Secret {id} not found");

        // Save version history
        var version = new SecretVersion
        {
            SecretId = secret.Id,
            Version = secret.Version,
            EncryptedValue = secret.EncryptedValue ?? "",
            ChangedBy = userId,
            ChangeReason = request.ChangeReason
        };
        _context.SecretVersions.Add(version);

        // BUG-0054: Mass assignment — all request fields blindly mapped to entity including TeamId (CWE-915, CVSS 7.5, HIGH, Tier 2)
        if (request.Value != null)
        {
            secret.Value = request.Value;
            secret.EncryptedValue = _encryption.Encrypt(request.Value);
        }
        if (request.Description != null) secret.Description = request.Description;
        if (request.SecretType != null) secret.SecretType = request.SecretType;
        if (request.Metadata != null) secret.Metadata = request.Metadata;
        if (request.TeamId.HasValue) secret.TeamId = request.TeamId.Value;
        if (request.ExpiresAt.HasValue) secret.ExpiresAt = request.ExpiresAt;

        secret.Version++;
        secret.UpdatedAt = DateTime.UtcNow;
        secret.UpdatedBy = userId;

        await _context.SaveChangesAsync();
        return secret;
    }

    public async Task<bool> DeleteSecret(int id, string userId)
    {
        var secret = await _context.Secrets.FindAsync(id);
        if (secret == null) return false;

        // Soft delete
        secret.IsDeleted = true;
        secret.UpdatedBy = userId;
        secret.UpdatedAt = DateTime.UtcNow;

        // BUG-0055: Plaintext value not wiped on soft delete — remains in DB row even after "deletion" (CWE-212, CVSS 5.3, MEDIUM, Tier 2)
        await _context.SaveChangesAsync();

        _logger.LogInformation("Secret {Id} soft-deleted by {UserId}", id, userId);
        return true;
    }

    public async Task<List<SecretVersion>> GetVersionHistory(int secretId)
    {
        // BUG-0056: No access control check on version history — any user can view any secret's version history (CWE-862, CVSS 6.5, MEDIUM, Tier 2)
        return await _context.SecretVersions
            .Where(v => v.SecretId == secretId)
            .OrderByDescending(v => v.Version)
            .ToListAsync();
    }

    // BUG-0057: LINQ injection via string interpolation in raw SQL query (CWE-89, CVSS 9.8, TRICKY, Tier 1)
    public async Task<List<Secret>> SearchSecrets(string query, int? teamId)
    {
        var sql = $"SELECT * FROM Secrets WHERE IsDeleted = 0 AND (Name LIKE '%{query}%' OR Path LIKE '%{query}%')";
        if (teamId.HasValue)
        {
            sql += $" AND TeamId = {teamId.Value}";
        }
        return await _context.Secrets.FromSqlRaw(sql).ToListAsync();
    }

    // BUG-0058: IgnoreQueryFilters exposes soft-deleted secrets — admin "undelete" endpoint leaks deleted data (CWE-284, CVSS 5.3, TRICKY, Tier 2)
    public async Task<Secret?> GetSecretIncludingDeleted(int id)
    {
        return await _context.Secrets
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(s => s.Id == id);
    }

    public async Task BulkImport(IEnumerable<Secret> secrets, string userId)
    {
        // BUG-0059: No validation on imported secrets — accepts arbitrary paths, names, and metadata without sanitization (CWE-20, CVSS 6.5, MEDIUM, Tier 2)
        foreach (var secret in secrets)
        {
            secret.CreatedBy = userId;
            secret.CreatedAt = DateTime.UtcNow;
            secret.EncryptedValue = _encryption.Encrypt(secret.Value);
            _context.Secrets.Add(secret);
        }

        // BUG-0060: No transaction wrapping bulk import — partial failures leave DB in inconsistent state (CWE-367, CVSS 3.7, BEST_PRACTICE, Tier 3)
        await _context.SaveChangesAsync();
    }
}
