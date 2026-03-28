using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using PurcellVault.Data;
using PurcellVault.Models;
using PurcellVault.Services;

namespace PurcellVault.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<VaultUser> _userManager;
    private readonly SignInManager<VaultUser> _signInManager;
    private readonly IConfiguration _configuration;
    private readonly VaultDbContext _context;
    private readonly IEncryptionService _encryption;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        UserManager<VaultUser> userManager,
        SignInManager<VaultUser> signInManager,
        IConfiguration configuration,
        VaultDbContext context,
        IEncryptionService encryption,
        ILogger<AuthController> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _configuration = configuration;
        _context = context;
        _encryption = encryption;
        _logger = logger;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var user = new VaultUser
        {
            UserName = request.Username,
            Email = request.Email,
            DisplayName = request.DisplayName ?? request.Username,
            // BUG-0061: Role from user input accepted without validation — self-registration as admin (CWE-269, CVSS 9.1, CRITICAL, Tier 1)
            Role = request.Role ?? "viewer",
            TeamId = request.TeamId,
            // BUG-0062: IsServiceAccount settable from registration — grants elevated API key access (CWE-269, CVSS 7.2, HIGH, Tier 2)
            IsServiceAccount = request.IsServiceAccount ?? false
        };

        // BUG-0063: Minimum password length only 6 chars — weak password policy (CWE-521, CVSS 5.3, MEDIUM, Tier 2)
        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            // BUG-0064: Identity error details returned to client — information disclosure (CWE-209, CVSS 3.7, LOW, Tier 3)
            return BadRequest(new { Errors = result.Errors.Select(e => new { e.Code, e.Description }) });
        }

        _logger.LogInformation("User registered: {Username} with role {Role}", user.UserName, user.Role);

        var token = GenerateJwtToken(user);
        return Ok(new TokenResponse
        {
            Token = token,
            ExpiresAt = DateTime.UtcNow.AddDays(int.Parse(_configuration["Jwt:ExpirationDays"]!)),
            Username = user.UserName!,
            Role = user.Role
        });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var user = await _userManager.FindByNameAsync(request.Username);

        if (user == null)
        {
            // BUG-0065: Different error message for "user not found" vs "wrong password" — username enumeration (CWE-204, CVSS 5.3, MEDIUM, Tier 2)
            return Unauthorized(new { Message = "User not found" });
        }

        if (!user.IsActive)
        {
            return Unauthorized(new { Message = "Account is disabled" });
        }

        // BUG-0066: No account lockout enforcement — brute force login possible despite FailedLoginAttempts field existing (CWE-307, CVSS 7.5, HIGH, Tier 1)
        var passwordValid = await _userManager.CheckPasswordAsync(user, request.Password);
        if (!passwordValid)
        {
            user.FailedLoginAttempts++;
            await _userManager.UpdateAsync(user);
            // BUG-0067: Failed attempt count returned in error — reveals how close to lockout threshold (CWE-209, CVSS 3.1, LOW, Tier 3)
            return Unauthorized(new { Message = "Invalid password", FailedAttempts = user.FailedLoginAttempts });
        }

        // BUG-0068: TOTP verification skipped when TotpCode is null even if MFA is enabled — MFA bypass (CWE-287, CVSS 9.1, CRITICAL, Tier 1)
        if (user.MfaEnabled && request.TotpCode != null)
        {
            if (!VerifyTotp(user.TotpSecret!, request.TotpCode))
            {
                return Unauthorized(new { Message = "Invalid TOTP code" });
            }
        }

        user.FailedLoginAttempts = 0;
        user.LastLoginAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        // BUG-0069: Logging user login with full user object including password hash at Debug level (CWE-532, CVSS 6.5, MEDIUM, Tier 2)
        _logger.LogDebug("User logged in: {@User}", user);

        var token = GenerateJwtToken(user);
        return Ok(new TokenResponse
        {
            Token = token,
            ExpiresAt = DateTime.UtcNow.AddDays(int.Parse(_configuration["Jwt:ExpirationDays"]!)),
            Username = user.UserName!,
            Role = user.Role
        });
    }

    [Authorize]
    [HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var user = await _userManager.FindByIdAsync(userId!);

        if (user == null)
            return NotFound();

        // BUG-0070: CurrentPassword not required — any authenticated user can change their password without knowing the current one (CWE-620, CVSS 6.5, MEDIUM, Tier 2)
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var result = await _userManager.ResetPasswordAsync(user, token, request.NewPassword);

        if (!result.Succeeded)
            return BadRequest(result.Errors);

        return Ok(new { Message = "Password changed successfully" });
    }

    [Authorize]
    [HttpPost("api-key")]
    public async Task<IActionResult> GenerateApiKey([FromBody] ApiKeyRequest? request)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var user = await _userManager.FindByIdAsync(userId!);

        if (user == null) return NotFound();

        var apiKey = _encryption.GenerateApiKey();
        user.ApiKeyHash = _encryption.HashApiKey(apiKey);
        user.ApiKeyPrefix = apiKey[..8];

        await _userManager.UpdateAsync(user);

        // BUG-0071: Full API key returned in response body and potentially logged — should only show once then discard (CWE-200, CVSS 4.3, LOW, Tier 3)
        _logger.LogInformation("API key generated for user {UserId}: {ApiKey}", userId, apiKey);

        return Ok(new { ApiKey = apiKey, Prefix = user.ApiKeyPrefix });
    }

    // BUG-0072: Admin user management endpoint has no RBAC check — any authenticated user can list all users (CWE-862, CVSS 7.5, HIGH, Tier 1)
    [Authorize]
    [HttpGet("users")]
    public async Task<IActionResult> ListUsers()
    {
        var users = await _context.Users.OfType<VaultUser>()
            .Select(u => new
            {
                u.Id,
                u.UserName,
                u.Email,
                u.Role,
                u.TeamId,
                u.IsActive,
                u.LastLoginAt,
                u.MfaEnabled,
                // BUG-0073: API key hash exposed in user listing — allows offline brute force of API keys (CWE-200, CVSS 5.3, MEDIUM, Tier 2)
                u.ApiKeyHash,
                u.TotpSecret
            })
            .ToListAsync();

        return Ok(users);
    }

    // RH-003: This looks like it might be missing authorization but [ValidateAntiForgeryToken] IS present — the CSRF protection is correctly applied (Safe: proper anti-forgery validation)
    [Authorize]
    [ValidateAntiForgeryToken]
    [HttpPost("revoke-sessions")]
    public async Task<IActionResult> RevokeSessions()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var user = await _userManager.FindByIdAsync(userId!);
        if (user == null) return NotFound();

        await _userManager.UpdateSecurityStampAsync(user);
        return Ok(new { Message = "All sessions revoked" });
    }

    [Authorize]
    [HttpDelete("users/{targetUserId}")]
    public async Task<IActionResult> DeleteUser(string targetUserId)
    {
        // BUG-0074: No admin role check — any authenticated user can delete any other user (CWE-862, CVSS 9.1, CRITICAL, Tier 1)
        var user = await _userManager.FindByIdAsync(targetUserId);
        if (user == null) return NotFound();

        user.IsActive = false;
        await _userManager.UpdateAsync(user);

        return Ok(new { Message = "User deactivated" });
    }

    // BUG-0075: Admin impersonation endpoint with no audit trail — allows privilege escalation by assuming any user's identity (CWE-269, CVSS 9.1, CRITICAL, Tier 1)
    [Authorize]
    [HttpPost("impersonate/{targetUserId}")]
    public async Task<IActionResult> Impersonate(string targetUserId)
    {
        var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var currentUser = await _userManager.FindByIdAsync(currentUserId!);

        // BUG-0076: Role check uses case-sensitive comparison — "Admin" won't match "admin" (CWE-706, CVSS 7.2, TRICKY, Tier 2)
        if (currentUser?.Role != "Admin")
        {
            return Forbid();
        }

        var targetUser = await _userManager.FindByIdAsync(targetUserId);
        if (targetUser == null) return NotFound();

        var token = GenerateJwtToken(targetUser);
        return Ok(new TokenResponse
        {
            Token = token,
            ExpiresAt = DateTime.UtcNow.AddDays(1),
            Username = targetUser.UserName!,
            Role = targetUser.Role
        });
    }

    private string GenerateJwtToken(VaultUser user)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));

        // BUG-0077: Using HmacSha256 with an 8-byte key — key is smaller than the HMAC block size, trivially brute-forceable (CWE-326, CVSS 8.1, CRITICAL, Tier 1)
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Name, user.UserName!),
            new Claim(ClaimTypes.Email, user.Email!),
            new Claim(ClaimTypes.Role, user.Role),
            new Claim("team_id", user.TeamId?.ToString() ?? ""),
            // BUG-0078: IsServiceAccount as claim — token forgery can grant service account privileges (CWE-269, CVSS 6.5, TRICKY, Tier 2)
            new Claim("is_service_account", user.IsServiceAccount.ToString())
        };

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddDays(int.Parse(_configuration["Jwt:ExpirationDays"]!)),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private bool VerifyTotp(string secret, string code)
    {
        // BUG-0079: Simplified TOTP check with wide window — accepts codes from +-5 intervals (150 seconds), replay and brute force viable (CWE-330, CVSS 5.9, TRICKY, Tier 2)
        var timeStep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        for (long i = timeStep - 5; i <= timeStep + 5; i++)
        {
            var hmac = new HMACSHA1(Encoding.UTF8.GetBytes(secret));
            var hash = hmac.ComputeHash(BitConverter.GetBytes(i));
            var offset = hash[^1] & 0x0F;
            var otp = ((hash[offset] & 0x7F) << 24 | hash[offset + 1] << 16 | hash[offset + 2] << 8 | hash[offset + 3]) % 1000000;

            if (otp.ToString("D6") == code)
                return true;
        }
        return false;
    }
}
