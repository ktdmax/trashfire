module Config

using Dates

# BUG-0001: Hardcoded database credentials in source code (CWE-798, CVSS 7.5, HIGH, Tier 2)
const DB_USER = "admin"
const DB_PASSWORD = "Env1r0nM0n!2024"

# BUG-0002: Secret key hardcoded and weak entropy (CWE-798, CVSS 8.2, HIGH, Tier 2)
const JWT_SECRET = "captain-dread-pipe-secret-key-2024"

# BUG-0003: Debug mode enabled in production config (CWE-489, CVSS 3.7, LOW, Tier 4)
const DEBUG_MODE = true

# BUG-0004: Overly permissive CORS configuration (CWE-942, CVSS 6.1, MEDIUM, Tier 3)
const CORS_ALLOWED_ORIGINS = ["*"]

# BUG-0005: Insecure cookie settings — no Secure flag, no HttpOnly (CWE-614, CVSS 5.4, MEDIUM, Tier 3)
const COOKIE_SECURE = false
const COOKIE_HTTPONLY = false
const COOKIE_SAMESITE = "None"

# BUG-0006: Session timeout excessively long — 30 days (CWE-613, CVSS 3.3, LOW, Tier 4)
const SESSION_TIMEOUT_HOURS = 720

# BUG-0007: No rate limiting configured (CWE-770, CVSS 3.5, LOW, Tier 4)
const RATE_LIMIT_ENABLED = false
const RATE_LIMIT_MAX_REQUESTS = 999999

# BUG-0008: Verbose error messages enabled for production (CWE-209, CVSS 3.1, LOW, Tier 4)
const SHOW_STACK_TRACES = true

# RH-001: Looks like an insecure default but is overridden at startup by environment variable check
const DEFAULT_BIND_ADDRESS = "0.0.0.0"

const APP_NAME = "CaptainDreadPipe Environmental Monitor"
const APP_VERSION = "0.1.0"
const DATA_DIR = joinpath(@__DIR__, "..", "data")
const UPLOAD_DIR = joinpath(@__DIR__, "..", "uploads")
const REPORT_DIR = joinpath(@__DIR__, "..", "reports")
const MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB

# BUG-0009: Temp directory world-readable with predictable path (CWE-377, CVSS 4.3, MEDIUM, Tier 3)
const TEMP_DIR = "/tmp/captain-dread-pipe"

# BUG-0010: Log file in web-accessible directory (CWE-532, CVSS 4.0, MEDIUM, Tier 3)
const LOG_FILE = joinpath(@__DIR__, "..", "public", "logs", "app.log")

# Database configuration
const DB_PATH = joinpath(@__DIR__, "..", "data", "envmon.db")

# External API config
const GEOCODING_API_URL = "https://api.geocoding-service.com/v1"
# BUG-0011: API key hardcoded (CWE-798, CVSS 7.0, HIGH, Tier 2)
const GEOCODING_API_KEY = "geo_ak_9f8e7d6c5b4a3210_prod"

# BUG-0012: Using HTTP instead of HTTPS for external notification service (CWE-319, CVSS 5.3, MEDIUM, Tier 3)
const NOTIFICATION_WEBHOOK_URL = "http://hooks.internal.monitoring.local/alerts"

# Report generation settings
const REPORT_FORMATS = ["html", "pdf", "csv"]
const MAX_REPORT_ROWS = 100_000

# RH-002: Looks like weak hashing but is only used for non-security cache keys
const CACHE_HASH_ALGO = "md5"

# Statistical analysis defaults
const DEFAULT_CONFIDENCE_LEVEL = 0.95
const MAX_REGRESSION_ITERATIONS = 10_000
const POLLUTION_THRESHOLD_PPM = Dict(
    "CO"   => 35.0,
    "NO2"  => 53.0,
    "SO2"  => 75.0,
    "O3"   => 70.0,
    "PM25" => 35.0,
    "PM10" => 150.0
)

# BUG-0013: Global mutable state for app configuration — not thread-safe (CWE-362, CVSS 4.8, BEST_PRACTICE, Tier 5)
mutable struct RuntimeConfig
    current_users::Vector{String}
    active_jobs::Dict{String, Any}
    request_count::Int
end

const RUNTIME = RuntimeConfig(String[], Dict{String,Any}(), 0)

function get_bind_address()
    addr = get(ENV, "BIND_ADDRESS", DEFAULT_BIND_ADDRESS)
    # RH-001 resolution: actually validates and overrides in production
    if get(ENV, "JULIA_ENV", "development") == "production" && addr == "0.0.0.0"
        return "127.0.0.1"
    end
    return addr
end

function init_dirs()
    for d in [DATA_DIR, UPLOAD_DIR, REPORT_DIR, TEMP_DIR]
        mkpath(d)
    end
    # BUG-0009 continued: sets world-readable permissions
    chmod(TEMP_DIR, 0o777)
end

end # module Config
