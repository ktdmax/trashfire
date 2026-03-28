using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Html;
using Newtonsoft.Json;
using PurcellVault.Models;
using PurcellVault.Services;

namespace PurcellVault.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class SecretsController : ControllerBase
{
    private readonly ISecretStore _secretStore;
    private readonly IPolicyEngine _policyEngine;
    private readonly IEncryptionService _encryption;
    private readonly ILogger<SecretsController> _logger;

    public SecretsController(
        ISecretStore secretStore,
        IPolicyEngine policyEngine,
        IEncryptionService encryption,
        ILogger<SecretsController> logger)
    {
        _secretStore = secretStore;
        _policyEngine = policyEngine;
        _encryption = encryption;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> ListSecrets(
        [FromQuery] string? path,
        [FromQuery] string? search,
        [FromQuery] int? teamId)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier)!;

        // BUG-0080: Policy check uses user-supplied teamId, not the user's actual team — can read other team's secrets by passing different teamId (CWE-639, CVSS 7.5, HIGH, Tier 1)
        var hasAccess = await _policyEngine.EvaluateAccess(userId, $"secrets/{path ?? "*"}", "list");
        if (!hasAccess) return Forbid();

        var secrets = await _secretStore.ListSecrets(teamId, path, search);

        return Ok(secrets.Select(s => new SecretResponse
        {
            Id = s.Id,
            Path = s.Path,
            Name = s.Name,
            Description = s.Description,
            Version = s.Version,
            CreatedAt = s.CreatedAt,
            ExpiresAt = s.ExpiresAt,
            SecretType = s.SecretType,
            Metadata = s.Metadata
        }));
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> GetSecret(int id)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier)!;
        var secret = await _secretStore.GetSecret(id);

        if (secret == null) return NotFound();

        var hasAccess = await _policyEngine.EvaluateAccess(userId, $"secrets/{secret.Path}/{secret.Name}", "read");
        if (!hasAccess) return Forbid();

        // BUG-0081: Decrypted secret value returned directly in API response — should require explicit ?reveal=true parameter (CWE-200, CVSS 6.5, MEDIUM, Tier 2)
        return Ok(new SecretResponse
        {
            Id = secret.Id,
            Path = secret.Path,
            Name = secret.Name,
            Value = secret.PlainTextValue ?? secret.Value,
            Description = secret.Description,
            Version = secret.Version,
            CreatedAt = secret.CreatedAt,
            ExpiresAt = secret.ExpiresAt,
            SecretType = secret.SecretType,
            Metadata = secret.Metadata
        });
    }

    [HttpPost]
    public async Task<IActionResult> CreateSecret([FromBody] SecretAccessRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Path) || string.IsNullOrWhiteSpace(request.Name))
            return BadRequest(new { Message = "Path and Name are required" });

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier)!;
        var hasAccess = await _policyEngine.EvaluateAccess(userId, $"secrets/{request.Path}", "create");
        if (!hasAccess) return Forbid();

        var secret = new Secret
        {
            Path = request.Path,
            Name = request.Name,
            Value = request.Value ?? "",
            Description = request.Description,
            SecretType = request.SecretType,
            Metadata = request.Metadata,
            // BUG-0082: TeamId from request body, not from authenticated user's token — allows writing secrets to other teams (CWE-639, CVSS 7.5, HIGH, Tier 2)
            TeamId = request.TeamId ?? int.Parse(User.FindFirstValue("team_id") ?? "0"),
            ExpiresAt = request.ExpiresAt
        };

        var created = await _secretStore.CreateSecret(secret, userId);

        return CreatedAtAction(nameof(GetSecret), new { id = created.Id }, new SecretResponse
        {
            Id = created.Id,
            Path = created.Path,
            Name = created.Name,
            Version = created.Version,
            CreatedAt = created.CreatedAt,
            SecretType = created.SecretType
        });
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> UpdateSecret(int id, [FromBody] SecretAccessRequest request)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier)!;

        var existing = await _secretStore.GetSecret(id);
        if (existing == null) return NotFound();

        var hasAccess = await _policyEngine.EvaluateAccess(userId, $"secrets/{existing.Path}/{existing.Name}", "update");
        if (!hasAccess) return Forbid();

        var updated = await _secretStore.UpdateSecret(id, request, userId);

        return Ok(new SecretResponse
        {
            Id = updated.Id,
            Path = updated.Path,
            Name = updated.Name,
            Version = updated.Version,
            CreatedAt = updated.CreatedAt,
            SecretType = updated.SecretType
        });
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteSecret(int id)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier)!;
        var existing = await _secretStore.GetSecret(id);
        if (existing == null) return NotFound();

        var hasAccess = await _policyEngine.EvaluateAccess(userId, $"secrets/{existing.Path}/{existing.Name}", "delete");
        if (!hasAccess) return Forbid();

        await _secretStore.DeleteSecret(id, userId);
        return NoContent();
    }

    [HttpGet("{id}/versions")]
    public async Task<IActionResult> GetVersionHistory(int id)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier)!;
        var versions = await _secretStore.GetVersionHistory(id);
        return Ok(versions);
    }

    // BUG-0083: Import endpoint with no file type validation — accepts any format string for import including "binary" (BinaryFormatter RCE) (CWE-434, CVSS 9.1, CRITICAL, Tier 1)
    [HttpPost("import")]
    public async Task<IActionResult> ImportSecrets([FromBody] ImportRequest request)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier)!;

        var secrets = _encryption.ImportSecrets(request.Data, request.Format);
        await _secretStore.BulkImport(secrets, userId);

        return Ok(new { Imported = secrets.Count(), Format = request.Format });
    }

    [HttpPost("export")]
    public async Task<IActionResult> ExportSecrets([FromBody] ExportRequest request)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier)!;

        // BUG-0084: Export bypasses policy engine — any authenticated user can export all secrets (CWE-862, CVSS 8.1, HIGH, Tier 1)
        var secrets = await _secretStore.ListSecrets(request.TeamId, request.PathPrefix, null);

        // Decrypt for export
        foreach (var secret in secrets)
        {
            if (secret.EncryptedValue != null)
            {
                secret.Value = _encryption.Decrypt(secret.EncryptedValue);
            }
        }

        var exportData = _encryption.ExportSecrets(secrets, request.Format ?? "json");
        return Ok(exportData);
    }

    // BUG-0085: Search endpoint with raw query passed to FromSqlRaw — SQL injection (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    [HttpGet("search")]
    public async Task<IActionResult> SearchSecrets([FromQuery] string q, [FromQuery] int? teamId)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier)!;
        var results = await _secretStore.SearchSecrets(q, teamId);

        return Ok(results.Select(s => new SecretResponse
        {
            Id = s.Id,
            Path = s.Path,
            Name = s.Name,
            Description = s.Description,
            Version = s.Version,
            SecretType = s.SecretType
        }));
    }

    // BUG-0086: Debug endpoint exposes secret metadata and internal IDs — no authorization beyond basic auth (CWE-489, CVSS 4.3, LOW, Tier 3)
    [HttpGet("debug/stats")]
    public async Task<IActionResult> DebugStats()
    {
        var secrets = await _secretStore.ListSecrets(null, null, null);
        return Ok(new
        {
            TotalSecrets = secrets.Count,
            SecretsByType = secrets.GroupBy(s => s.SecretType).Select(g => new { Type = g.Key, Count = g.Count() }),
            SecretsByTeam = secrets.GroupBy(s => s.TeamId).Select(g => new { TeamId = g.Key, Count = g.Count() }),
            RecentSecrets = secrets.OrderByDescending(s => s.CreatedAt).Take(10).Select(s => new { s.Id, s.Path, s.Name, s.CreatedBy })
        });
    }

    // BUG-0087: SSRF via webhook URL — user-controlled URL fetched server-side (CWE-918, CVSS 7.5, HIGH, Tier 1)
    [HttpPost("webhook")]
    public async Task<IActionResult> ConfigureWebhook([FromBody] WebhookRequest request)
    {
        using var client = new HttpClient();
        // BUG-0088: No URL validation — can target internal services, cloud metadata endpoints (CWE-918, CVSS 8.6, HIGH, Tier 1)
        var response = await client.PostAsync(request.Url, new StringContent(
            JsonConvert.SerializeObject(new { Event = "test", Timestamp = DateTime.UtcNow }),
            Encoding.UTF8,
            "application/json"));

        return Ok(new { StatusCode = (int)response.StatusCode, Body = await response.Content.ReadAsStringAsync() });
    }

    // RH-004: This looks like XSS but HtmlEncoder.Default.Encode safely encodes the output (Safe: proper HTML encoding applied)
    [HttpGet("{id}/rendered")]
    public IActionResult RenderSecretDescription(int id)
    {
        var description = "<script>alert('xss')</script>test description";
        var encoded = System.Web.HttpUtility.HtmlEncode(description);
        return Content($"<html><body><p>{encoded}</p></body></html>", "text/html");
    }
}

public class ImportRequest
{
    public string Data { get; set; } = string.Empty;
    public string Format { get; set; } = "json";
}

public class ExportRequest
{
    public string? PathPrefix { get; set; }
    public int? TeamId { get; set; }
    public string? Format { get; set; }
}

public class WebhookRequest
{
    public string Url { get; set; } = string.Empty;
    public string? EventType { get; set; }
    public Dictionary<string, string>? Headers { get; set; }
}
