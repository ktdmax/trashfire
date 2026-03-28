use std::env;

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub host: String,
    pub port: u16,
    pub admin_api_key: String,
    pub market_data_api_url: String,
    pub tax_report_dir: String,
    pub session_timeout_secs: u64,
    pub max_upload_size: usize,
}

impl Config {
    pub fn from_env() -> Self {
        // BUG-0009: Hardcoded fallback JWT secret used in production (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
        let jwt_secret = env::var("JWT_SECRET")
            .unwrap_or_else(|_| "guybrush-threepwood-mighty-pirate-2024".to_string());

        // BUG-0010: Hardcoded admin API key (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
        let admin_api_key = env::var("ADMIN_API_KEY")
            .unwrap_or_else(|_| "admin-skeleton-key-12345".to_string());

        // BUG-0011: Database URL fallback contains embedded credentials (CWE-798, CVSS 8.2, HIGH, Tier 1)
        let database_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://guybrush:monkey_island@localhost:5432/ledger".to_string());

        // BUG-0012: Tax report directory allows path traversal — no sanitization (CWE-22, CVSS 7.5, HIGH, Tier 2)
        let tax_report_dir = env::var("TAX_REPORT_DIR")
            .unwrap_or_else(|_| "/tmp/tax_reports".to_string());

        // BUG-0013: Max upload size set to 500MB — DoS via large uploads (CWE-400, CVSS 5.3, MEDIUM, Tier 2)
        let max_upload_size = env::var("MAX_UPLOAD_SIZE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(500 * 1024 * 1024);

        // BUG-0014: Session timeout of 30 days is excessive (CWE-613, CVSS 4.3, MEDIUM, Tier 2)
        let session_timeout_secs = env::var("SESSION_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30 * 24 * 3600);

        Config {
            database_url,
            jwt_secret,
            host: env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8080),
            admin_api_key,
            // BUG-0015: Market data URL from env with no validation — SSRF vector (CWE-918, CVSS 7.5, HIGH, Tier 2)
            market_data_api_url: env::var("MARKET_DATA_URL")
                .unwrap_or_else(|_| "https://api.coingecko.com/api/v3".to_string()),
            tax_report_dir,
            session_timeout_secs,
            max_upload_size,
        }
    }
}

// RH-001: This format! is for logging only — not used in SQL queries. NOT a vulnerability.
pub fn log_config_summary(cfg: &Config) {
    let summary = format!(
        "Server configured: host={}, port={}, report_dir={}",
        cfg.host, cfg.port, cfg.tax_report_dir
    );
    log::info!("{}", summary);
}
