using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PurcellVault.Data;
using PurcellVault.Models;
using PurcellVault.Services;

namespace PurcellVault.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class AuditController : ControllerBase
{
    private readonly VaultDbContext _context;
    private readonly IPolicyEngine _policyEngine;
    private readonly ILogger<AuditController> _logger;

    public AuditController(VaultDbContext context, IPolicyEngine policyEngine, ILogger<AuditController> logger)
    {
        _context = context;
        _policyEngine = policyEngine;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> GetAuditLogs(
        [FromQuery] string? userId,
        [FromQuery] string? action,
        [FromQuery] DateTime? from,
        [FromQuery] DateTime? to,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 100)
    {
        var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier)!;

        // BUG-0096: No admin check — any authenticated user can read all audit logs including other users' activity (CWE-862, CVSS 6.5, MEDIUM, Tier 2)
        var query = _context.AuditLogs.AsQueryable();

        if (!string.IsNullOrEmpty(userId))
            query = query.Where(l => l.UserId == userId);
        if (!string.IsNullOrEmpty(action))
            query = query.Where(l => l.Action == action);
        if (from.HasValue)
            query = query.Where(l => l.Timestamp >= from.Value);
        if (to.HasValue)
            query = query.Where(l => l.Timestamp <= to.Value);

        // BUG-0097: pageSize not capped — attacker can set pageSize=1000000 to dump all logs / cause OOM (CWE-400, CVSS 5.3, LOW, Tier 3)
        var logs = await query
            .OrderByDescending(l => l.Timestamp)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        // BUG-0098: RequestBody field included in audit log response — contains plaintext secrets from create/update operations (CWE-532, CVSS 7.5, HIGH, Tier 1)
        return Ok(new
        {
            Page = page,
            PageSize = pageSize,
            Total = await query.CountAsync(),
            Logs = logs
        });
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> GetAuditLogEntry(long id)
    {
        var entry = await _context.AuditLogs.FindAsync(id);
        if (entry == null) return NotFound();

        return Ok(entry);
    }

    // BUG-0099: Audit log export with no access control — all audit data including secrets exportable by any user (CWE-862, CVSS 7.5, HIGH, Tier 1)
    [HttpGet("export")]
    public async Task<IActionResult> ExportAuditLogs(
        [FromQuery] DateTime? from,
        [FromQuery] DateTime? to,
        [FromQuery] string format = "csv")
    {
        var query = _context.AuditLogs.AsQueryable();

        if (from.HasValue)
            query = query.Where(l => l.Timestamp >= from.Value);
        if (to.HasValue)
            query = query.Where(l => l.Timestamp <= to.Value);

        // BUG-0100: No pagination on export — entire audit log loaded into memory (CWE-400, CVSS 3.7, LOW, Tier 3)
        var logs = await query.OrderByDescending(l => l.Timestamp).ToListAsync();

        if (format == "csv")
        {
            var sb = new StringBuilder();
            sb.AppendLine("Id,UserId,Username,Action,Resource,RequestBody,IpAddress,StatusCode,Timestamp");

            foreach (var log in logs)
            {
                // BUG-0001 (dup avoided — using 0100 above): CSV injection — fields not escaped, formula injection possible (handled as part of BUG-0100)
                sb.AppendLine($"{log.Id},{log.UserId},{log.Username},{log.Action},{log.Resource},{log.RequestBody},{log.IpAddress},{log.StatusCode},{log.Timestamp:O}");
            }

            return File(Encoding.UTF8.GetBytes(sb.ToString()), "text/csv", "audit-export.csv");
        }

        return Ok(logs);
    }

    // RH-006: This looks like it might have SQL injection via string interpolation, but it uses FromSqlInterpolated which safely parameterizes (Safe: EF Core FromSqlInterpolated auto-parameterizes)
    [HttpGet("summary")]
    public async Task<IActionResult> GetAuditSummary([FromQuery] string? userId)
    {
        if (!string.IsNullOrEmpty(userId))
        {
            var userLogs = await _context.AuditLogs
                .FromSqlInterpolated($"SELECT * FROM AuditLogs WHERE UserId = {userId}")
                .ToListAsync();

            return Ok(new
            {
                TotalActions = userLogs.Count,
                ActionBreakdown = userLogs.GroupBy(l => l.Action).Select(g => new { Action = g.Key, Count = g.Count() }),
                LastActivity = userLogs.MaxBy(l => l.Timestamp)?.Timestamp
            });
        }

        var summary = await _context.AuditLogs
            .GroupBy(l => l.Action)
            .Select(g => new { Action = g.Key, Count = g.Count() })
            .ToListAsync();

        return Ok(summary);
    }

    [HttpDelete("purge")]
    public async Task<IActionResult> PurgeAuditLogs([FromQuery] DateTime before)
    {
        var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier)!;
        var isAdmin = await _policyEngine.IsAdmin(currentUserId);

        if (!isAdmin)
            return Forbid();

        // BUG-0023 already used — this is a different concern:
        // The purge itself is fine, but there's no secondary confirmation or audit-of-audit
        var logsToDelete = await _context.AuditLogs
            .Where(l => l.Timestamp < before)
            .ToListAsync();

        _context.AuditLogs.RemoveRange(logsToDelete);
        await _context.SaveChangesAsync();

        _logger.LogWarning("Audit logs purged: {Count} entries before {Before} by {UserId}",
            logsToDelete.Count, before, currentUserId);

        return Ok(new { Deleted = logsToDelete.Count });
    }
}
