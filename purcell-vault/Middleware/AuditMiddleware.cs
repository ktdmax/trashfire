using System.Diagnostics;
using System.Security.Claims;
using System.Text;
using Microsoft.EntityFrameworkCore;
using PurcellVault.Data;
using PurcellVault.Models;

namespace PurcellVault.Middleware;

public class AuditMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<AuditMiddleware> _logger;

    public AuditMiddleware(RequestDelegate next, ILogger<AuditMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, VaultDbContext dbContext)
    {
        var stopwatch = Stopwatch.StartNew();

        // BUG-0021 (cross-ref): Request body captured here and stored in audit log including secret values
        // Read request body for audit logging
        context.Request.EnableBuffering();
        string requestBody;
        using (var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true))
        {
            requestBody = await reader.ReadToEndAsync();
            context.Request.Body.Position = 0;
        }

        // Capture original response body
        var originalResponseBody = context.Response.Body;
        using var responseBuffer = new MemoryStream();
        context.Response.Body = responseBuffer;

        try
        {
            await _next(context);
        }
        finally
        {
            stopwatch.Stop();

            // Read response for audit
            responseBuffer.Position = 0;
            var responseBody = await new StreamReader(responseBuffer).ReadToEndAsync();
            responseBuffer.Position = 0;
            await responseBuffer.CopyToAsync(originalResponseBody);
            context.Response.Body = originalResponseBody;

            // Only audit API calls
            if (context.Request.Path.StartsWithSegments("/api"))
            {
                try
                {
                    var userId = context.User?.FindFirstValue(ClaimTypes.NameIdentifier);
                    var username = context.User?.FindFirstValue(ClaimTypes.Name);

                    var auditEntry = new AuditLogEntry
                    {
                        UserId = userId,
                        Username = username,
                        Action = $"{context.Request.Method} {context.Request.Path}",
                        Resource = context.Request.Path.Value ?? "",
                        // BUG-0021 (materialized here): Full request body including plaintext secrets stored in audit log (CWE-532, CVSS 7.5, CRITICAL, Tier 1)
                        RequestBody = requestBody,
                        // BUG-0029 (cross-ref): Response body may contain decrypted secrets
                        ResponseSummary = responseBody.Length > 1000 ? responseBody[..1000] : responseBody,
                        IpAddress = GetClientIp(context),
                        UserAgent = context.Request.Headers.UserAgent.ToString(),
                        StatusCode = context.Response.StatusCode,
                        DurationMs = stopwatch.ElapsedMilliseconds
                    };

                    dbContext.AuditLogs.Add(auditEntry);

                    // BUG-0052 (cross-ref): Fire-and-forget SaveChangesAsync — if this fails, audit entry is silently lost (CWE-778, CVSS 4.3, BEST_PRACTICE, Tier 3)
                    _ = dbContext.SaveChangesAsync();
                }
                catch (Exception ex)
                {
                    // BUG-0064 (cross-ref): Audit failure silently swallowed — attacker can cause audit failures to hide tracks
                    _logger.LogError(ex, "Failed to write audit log");
                }
            }
        }
    }

    private string GetClientIp(HttpContext context)
    {
        // BUG-0009 (numbering note — this is a separate instance):
        // Actually tracked under unique bug numbers below:

        // BUG-none (covered by design): X-Forwarded-For trusted without validation — IP spoofing possible
        var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedFor))
        {
            return forwardedFor.Split(',')[0].Trim();
        }

        return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }
}

public static class AuditMiddlewareExtensions
{
    public static IApplicationBuilder UseAuditMiddleware(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<AuditMiddleware>();
    }
}
