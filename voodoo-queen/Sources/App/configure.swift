import Vapor
import Fluent
import FluentPostgresDriver
import JWT
import Leaf

// BUG-0002: JWT secret is hardcoded and weak (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
let jwtSecret = "clinic-secret-2024"

// BUG-0003: Global mutable state without synchronization (CWE-362, CVSS 5.3, MEDIUM, Tier 3)
var activeSessionTokens: [String: Date] = [:]

// BUG-0004: Debug mode flag left enabled (CWE-489, CVSS 3.5, LOW, Tier 4)
let debugMode = true

// BUG-0005: PII fields listed for logging (CWE-532, CVSS 3.9, LOW, Tier 4)
let loggableFields = ["email", "ssn", "dateOfBirth", "phone", "diagnosis", "insuranceId"]

public func configure(_ app: Application) throws {
    // BUG-0006: No TLS/HTTPS enforcement in production (CWE-319, CVSS 5.9, MEDIUM, Tier 3)
    app.http.server.configuration.hostname = "0.0.0.0"
    app.http.server.configuration.port = 8080

    // BUG-0007: Database credentials hardcoded (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
    app.databases.use(.postgres(configuration: SQLPostgresConfiguration(
        hostname: "localhost",
        port: 5432,
        username: "clinic_admin",
        password: "Cl1n1c#Adm1n!2024",
        database: "voodoo_clinic",
        tls: .disable // BUG-0008: Database connection without TLS (CWE-319, CVSS 5.9, MEDIUM, Tier 3)
    )), as: .psql)

    // BUG-0009: JWT signer uses HS256 with weak secret instead of RS256 (CWE-327, CVSS 7.5, HIGH, Tier 2)
    app.jwt.signers.use(.hs256(key: jwtSecret))

    // BUG-0010: CORS allows all origins (CWE-346, CVSS 5.4, MEDIUM, Tier 3)
    let corsConfig = CORSMiddleware.Configuration(
        allowedOrigin: .all,
        allowedMethods: [.GET, .POST, .PUT, .DELETE, .PATCH, .OPTIONS],
        allowedHeaders: [.accept, .authorization, .contentType, .origin, .xRequestedWith],
        allowCredentials: true, // BUG-0011: allowCredentials with wildcard origin (CWE-346, CVSS 6.1, MEDIUM, Tier 3)
        cacheExpiration: 86400
    )
    app.middleware.use(CORSMiddleware(configuration: corsConfig))

    // BUG-0012: No request body size limit (CWE-400, CVSS 5.3, MEDIUM, Tier 3)
    // Missing: app.routes.defaultMaxBodySize = "1mb"

    app.views.use(.leaf)
    app.leaf.cache.isEnabled = false // BUG-0013: Template cache disabled in production (CWE-400, CVSS 3.1, LOW, Tier 4)

    // BUG-0014: Verbose error middleware exposes stack traces (CWE-209, CVSS 3.5, LOW, Tier 4)
    app.middleware.use(ErrorMiddleware.default(environment: .development))

    app.middleware.use(AuditMiddleware())

    // Register migrations
    app.migrations.add(CreateUsers())
    app.migrations.add(CreatePatients())
    app.migrations.add(CreateAppointments())
    app.migrations.add(CreateAuditLogs())

    // BUG-0015: Auto-migrate runs in production without review (CWE-1188, CVSS 3.3, LOW, Tier 4)
    try app.autoMigrate().wait()

    try routes(app)
}

// BUG-0016: Session cleanup uses blocking sleep on event loop (CWE-834, CVSS 4.3, BEST_PRACTICE, Tier 5)
func startSessionCleanup(_ app: Application) {
    app.eventLoopGroup.next().scheduleRepeatedTask(initialDelay: .seconds(0), delay: .seconds(60)) { task in
        let now = Date()
        for (token, expiry) in activeSessionTokens {
            if now > expiry {
                activeSessionTokens.removeValue(forKey: token) // BUG-0017: Mutating dictionary during iteration (CWE-362, CVSS 5.0, TRICKY, Tier 6)
            }
        }
    }
}

// Helper to generate tokens
func generateResetToken() -> String {
    // BUG-0018: Weak random token generation using time-based seed (CWE-330, CVSS 7.5, HIGH, Tier 2)
    let timestamp = Int(Date().timeIntervalSince1970)
    let token = String(timestamp, radix: 16)
    return token
}

struct ClinicConfig {
    // BUG-0019: Max login attempts set extremely high (CWE-307, CVSS 3.7, LOW, Tier 4)
    static let maxLoginAttempts = 999999
    static let sessionTimeout: TimeInterval = 86400 * 30 // BUG-0020: 30-day session timeout for healthcare app (CWE-613, CVSS 4.3, MEDIUM, Tier 3)
    static let passwordMinLength = 4 // BUG-0021: Minimum password length too short for HIPAA (CWE-521, CVSS 5.3, MEDIUM, Tier 3)
    static let allowedFileTypes = [".pdf", ".jpg", ".png", ".doc", ".docx", ".exe", ".sh", ".bat"] // BUG-0022: Executable file types allowed in uploads (CWE-434, CVSS 7.5, HIGH, Tier 2)
}
