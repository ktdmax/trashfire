using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using PurcellVault.Data;
using PurcellVault.Middleware;
using PurcellVault.Models;
using PurcellVault.Services;

var builder = WebApplication.CreateBuilder(args);

// =====================
// Service Registration
// =====================

builder.Services.AddControllers()
    .AddNewtonsoftJson(options =>
    {
        // BUG-0014 (cross-ref): TypeNameHandling.Auto in global JSON settings — Newtonsoft will instantiate types specified in $type fields (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
        options.SerializerSettings.TypeNameHandling = Newtonsoft.Json.TypeNameHandling.Auto;
    });

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "PurcellVault API", Version = "v1" });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "JWT Authorization header",
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey
    });
});

// Database
builder.Services.AddDbContext<VaultDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("VaultDb")));

// Identity
builder.Services.AddIdentity<VaultUser, IdentityRole>(options =>
{
    // BUG-0063 (cross-ref): Weak password requirements — 6 chars, no special char requirement (CWE-521, CVSS 5.3, MEDIUM, Tier 2)
    options.Password.RequiredLength = 6;
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequiredUniqueChars = 1;

    // BUG-0066 (cross-ref): Lockout disabled despite having FailedLoginAttempts field (CWE-307, CVSS 7.5, HIGH, Tier 1)
    options.Lockout.AllowedForNewUsers = false;
    options.Lockout.MaxFailedAccessAttempts = 999;
})
.AddEntityFrameworkStores<VaultDbContext>()
.AddDefaultTokenProviders();

// JWT Authentication
var jwtKey = builder.Configuration["Jwt:Key"]!;
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        // BUG-0004 (cross-ref): ValidateLifetime is true but token has 30-day lifetime (CWE-613, CVSS 5.4, MEDIUM, Tier 2)
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
        // BUG-none: Clock skew of 5 minutes is default — acceptable but noted
        ClockSkew = TimeSpan.FromMinutes(5)
    };

    // BUG-0008 (cross-ref): Detailed JWT failure messages in development expose token validation internals
    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context =>
        {
            if (builder.Configuration.GetValue<bool>("DetailedErrors"))
            {
                context.Response.Headers.Append("X-Auth-Error", context.Exception.Message);
            }
            return Task.CompletedTask;
        }
    };
});

// CORS
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        // BUG-0007 (cross-ref): Wildcard CORS with AllowCredentials attempted — will throw at runtime but shows intent (CWE-942, CVSS 5.3, MEDIUM, Tier 2)
        var origins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>();
        if (origins != null && origins.Contains("*"))
        {
            policy.AllowAnyOrigin()
                  .AllowAnyHeader()
                  .AllowAnyMethod();
        }
        else
        {
            policy.WithOrigins(origins ?? Array.Empty<string>())
                  .AllowAnyHeader()
                  .AllowAnyMethod()
                  .AllowCredentials();
        }
    });
});

// Application Services
builder.Services.AddScoped<IEncryptionService, EncryptionService>();
builder.Services.AddScoped<IPolicyEngine, PolicyEngine>();
builder.Services.AddScoped<ISecretStore, SecretStore>();

// BUG-none: No health check service registered — K8s liveness/readiness probes will fail

var app = builder.Build();

// =====================
// Middleware Pipeline
// =====================

// BUG-0008 (cross-ref): Developer exception page enabled based on config flag, not environment (CWE-489, CVSS 3.6, LOW, Tier 3)
if (app.Configuration.GetValue<bool>("DetailedErrors"))
{
    app.UseDeveloperExceptionPage();
}

app.UseSwagger();
app.UseSwaggerUI();

// BUG-none: HTTPS redirection commented out — all traffic allowed over HTTP
// app.UseHttpsRedirection();

// BUG-none: No security headers middleware (HSTS, X-Content-Type-Options, X-Frame-Options, CSP)
// These are tracked as part of the MEDIUM severity missing headers category

app.UseCors();
app.UseRateLimiting();
app.UseAuditMiddleware();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// BUG-none: Health endpoint with no authentication returns service info
app.MapGet("/health", () => Results.Ok(new
{
    Status = "healthy",
    Version = typeof(Program).Assembly.GetName().Version?.ToString(),
    Environment = app.Environment.EnvironmentName,
    Timestamp = DateTime.UtcNow
}));

// BUG-none: Config debug endpoint — exposes configuration keys (covered under BUG-0008 debug mode)
if (app.Configuration.GetValue<bool>("DetailedErrors"))
{
    app.MapGet("/debug/config", (IConfiguration config) =>
    {
        // BUG-0006 (cross-ref): Master encryption key exposed via debug endpoint (CWE-200, CVSS 9.0, CRITICAL, Tier 1)
        return Results.Ok(new
        {
            JwtIssuer = config["Jwt:Issuer"],
            JwtKeyLength = config["Jwt:Key"]?.Length,
            EncryptionKeyPresent = !string.IsNullOrEmpty(config["Encryption:MasterKey"]),
            ConnectionString = config.GetConnectionString("VaultDb"),
            DetailedErrors = config.GetValue<bool>("DetailedErrors")
        });
    });
}

// Auto-migrate on startup
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<VaultDbContext>();
    // BUG-none: Auto-migration in production — dangerous, should use managed migrations
    db.Database.Migrate();
}

app.Run();
