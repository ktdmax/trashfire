using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using PurcellVault.Data;
using PurcellVault.Models;
using PurcellVault.Services;

namespace PurcellVault.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class PoliciesController : ControllerBase
{
    private readonly VaultDbContext _context;
    private readonly IPolicyEngine _policyEngine;
    private readonly ILogger<PoliciesController> _logger;

    public PoliciesController(VaultDbContext context, IPolicyEngine policyEngine, ILogger<PoliciesController> logger)
    {
        _context = context;
        _policyEngine = policyEngine;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> ListPolicies()
    {
        // BUG-0089: All policies returned regardless of user's team — leaks policy structure of other teams (CWE-200, CVSS 5.3, MEDIUM, Tier 2)
        var policies = await _context.Policies.ToListAsync();
        return Ok(policies);
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> GetPolicy(int id)
    {
        var policy = await _context.Policies.FindAsync(id);
        if (policy == null) return NotFound();

        return Ok(policy);
    }

    [HttpPost]
    public async Task<IActionResult> CreatePolicy([FromBody] PolicyCreateRequest request)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier)!;

        // BUG-0090: No admin role check — any authenticated user can create policies (CWE-862, CVSS 8.1, HIGH, Tier 1)

        // BUG-0091: PolicyDocument not validated before storage — arbitrary JSON including TypeNameHandling exploit payloads accepted (CWE-20, CVSS 8.1, CRITICAL, Tier 1)
        var policy = new Policy
        {
            Name = request.Name,
            Description = request.Description,
            PolicyDocument = request.PolicyDocument,
            Priority = request.Priority,
            TeamId = request.TeamId,
            CreatedBy = userId
        };

        _context.Policies.Add(policy);
        await _context.SaveChangesAsync();

        _policyEngine.InvalidateCache();

        return CreatedAtAction(nameof(GetPolicy), new { id = policy.Id }, policy);
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> UpdatePolicy(int id, [FromBody] PolicyUpdateRequest request)
    {
        var policy = await _context.Policies.FindAsync(id);
        if (policy == null) return NotFound();

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier)!;

        // BUG-0092: No ownership or admin check — any user can modify any policy including admin policies (CWE-862, CVSS 9.1, CRITICAL, Tier 1)
        if (request.Name != null) policy.Name = request.Name;
        if (request.Description != null) policy.Description = request.Description;
        if (request.PolicyDocument != null) policy.PolicyDocument = request.PolicyDocument;
        if (request.Priority.HasValue) policy.Priority = request.Priority.Value;
        if (request.IsActive.HasValue) policy.IsActive = request.IsActive.Value;

        policy.UpdatedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();
        _policyEngine.InvalidateCache();

        return Ok(policy);
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeletePolicy(int id)
    {
        var policy = await _context.Policies.FindAsync(id);
        if (policy == null) return NotFound();

        // BUG-0093: Hard delete of policy — no soft delete, no audit trail of deleted policies (CWE-778, CVSS 3.7, LOW, Tier 3)
        _context.Policies.Remove(policy);
        await _context.SaveChangesAsync();

        _policyEngine.InvalidateCache();

        return NoContent();
    }

    // BUG-0094: Policy simulation endpoint reveals full access decision logic — attacker can map out all allowed actions (CWE-200, CVSS 5.3, MEDIUM, Tier 2)
    [HttpPost("simulate")]
    public async Task<IActionResult> SimulateAccess([FromBody] SimulateRequest request)
    {
        var results = new List<object>();

        foreach (var resource in request.Resources)
        {
            foreach (var action in request.Actions)
            {
                var allowed = await _policyEngine.EvaluateAccess(request.UserId, resource, action);
                results.Add(new { Resource = resource, Action = action, Allowed = allowed });
            }
        }

        return Ok(new { Simulations = results });
    }

    // RH-005: This endpoint validates JSON schema before accepting PolicyDocument — looks like it might accept arbitrary JSON but actually validates structure (Safe: explicit schema validation)
    [HttpPost("validate")]
    public IActionResult ValidatePolicy([FromBody] PolicyCreateRequest request)
    {
        try
        {
            var doc = System.Text.Json.JsonSerializer.Deserialize<PolicyDocument>(request.PolicyDocument);
            if (doc == null || doc.Rules == null || doc.Rules.Count == 0)
            {
                return BadRequest(new { Valid = false, Message = "Policy must contain at least one rule" });
            }

            foreach (var rule in doc.Rules)
            {
                if (rule.Effect != "allow" && rule.Effect != "deny")
                {
                    return BadRequest(new { Valid = false, Message = $"Invalid effect: {rule.Effect}" });
                }
            }

            return Ok(new { Valid = true, RuleCount = doc.Rules.Count });
        }
        catch (System.Text.Json.JsonException ex)
        {
            return BadRequest(new { Valid = false, Message = ex.Message });
        }
    }

    [HttpGet("effective/{userId}")]
    public async Task<IActionResult> GetEffectiveRules(string userId)
    {
        // BUG-0095: Any user can view effective rules for any other user — information disclosure of access patterns (CWE-862, CVSS 5.3, MEDIUM, Tier 2)
        var rules = await _policyEngine.GetEffectiveRules(userId);
        return Ok(rules);
    }
}

public class SimulateRequest
{
    public string UserId { get; set; } = string.Empty;
    public List<string> Resources { get; set; } = new();
    public List<string> Actions { get; set; } = new();
}
