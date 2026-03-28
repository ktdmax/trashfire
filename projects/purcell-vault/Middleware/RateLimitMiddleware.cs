using System.Collections.Concurrent;
using System.Net;
using System.Security.Claims;

namespace PurcellVault.Middleware;

public class RateLimitMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RateLimitMiddleware> _logger;

    // BUG-none (covered by BUG-0037 pattern): Static dictionary shared across requests
    private static readonly ConcurrentDictionary<string, RateLimitEntry> _rateLimits = new();

    // BUG-0049 (cross-ref): Rate limits only applied per-IP, not per-user — authenticated user can use multiple IPs
    private const int MaxRequestsPerMinute = 1000;  // BUG: Effectively no rate limit — 1000 req/min is too permissive
    private const int MaxRequestsPerMinuteAuth = 5000;

    public RateLimitMiddleware(RequestDelegate next, ILogger<RateLimitMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // BUG-none (separate from numbered bugs — part of general weak rate limiting design):
        // Skip rate limiting for health checks and static files
        if (context.Request.Path.StartsWithSegments("/health") ||
            context.Request.Path.StartsWithSegments("/swagger"))
        {
            await _next(context);
            return;
        }

        var clientKey = GetClientKey(context);
        var now = DateTime.UtcNow;

        var entry = _rateLimits.GetOrAdd(clientKey, _ => new RateLimitEntry());

        // BUG-none: Cleanup of old entries never happens — memory leak over time
        // (covered under the general BEST_PRACTICE category)

        lock (entry)
        {
            // Reset window if expired
            if (now - entry.WindowStart > TimeSpan.FromMinutes(1))
            {
                entry.WindowStart = now;
                entry.RequestCount = 0;
            }

            entry.RequestCount++;

            var limit = context.User?.Identity?.IsAuthenticated == true
                ? MaxRequestsPerMinuteAuth
                : MaxRequestsPerMinute;

            if (entry.RequestCount > limit)
            {
                _logger.LogWarning("Rate limit exceeded for {ClientKey}: {Count} requests",
                    clientKey, entry.RequestCount);

                context.Response.StatusCode = (int)HttpStatusCode.TooManyRequests;
                context.Response.Headers.Append("Retry-After", "60");
                return;
            }
        }

        // BUG-none: Rate limit headers not set on successful requests — client can't self-throttle
        await _next(context);
    }

    private string GetClientKey(HttpContext context)
    {
        // BUG (covered by X-Forwarded-For trust pattern): Uses potentially spoofed IP
        var ip = context.Request.Headers["X-Forwarded-For"].FirstOrDefault()
            ?? context.Connection.RemoteIpAddress?.ToString()
            ?? "unknown";

        var userId = context.User?.FindFirstValue(ClaimTypes.NameIdentifier);

        return !string.IsNullOrEmpty(userId) ? $"user:{userId}" : $"ip:{ip}";
    }

    private class RateLimitEntry
    {
        public DateTime WindowStart { get; set; } = DateTime.UtcNow;
        public int RequestCount { get; set; } = 0;
    }
}

public static class RateLimitMiddlewareExtensions
{
    public static IApplicationBuilder UseRateLimiting(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<RateLimitMiddleware>();
    }
}
