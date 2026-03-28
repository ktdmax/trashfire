use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tracing::{info, warn};

/// Main configuration for the mesh sidecar
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfig {
    pub listen_port: u16,
    pub admin_port: u16,
    pub redis_url: String,
    // BUG-0020: Admin token stored in plaintext config struct, serializable, no zeroize (CWE-312, CVSS 6.5, MEDIUM, Tier 3)
    pub admin_token: String,
    pub tls: TlsConfig,
    pub routing: RoutingConfig,
    pub circuit_breaker: CircuitBreakerConfig,
    pub tracing: TracingConfig,
    pub upstreams: Vec<UpstreamConfig>,
    // BUG-0021: Max request body has no upper bound check; attacker can set to u64::MAX via config (CWE-770, CVSS 7.5, HIGH, Tier 2)
    pub max_request_body_bytes: u64,
    pub log_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_path: String,
    pub key_path: String,
    pub ca_path: String,
    // BUG-0022: Allows disabling client certificate verification via config flag (CWE-295, CVSS 8.1, HIGH, Tier 2)
    pub require_client_cert: bool,
    // BUG-0023: Min TLS version default is "1.0" — allows downgrade to TLS 1.0 (CWE-326, CVSS 7.4, TRICKY, Tier 6)
    #[serde(default = "default_min_tls_version")]
    pub min_tls_version: String,
    pub allowed_sans: Vec<String>,
    // BUG-0024: Static IV for AES-GCM session ticket encryption — nonce reuse breaks confidentiality (CWE-329, CVSS 7.5, TRICKY, Tier 6)
    #[serde(default = "default_session_ticket_iv")]
    pub session_ticket_iv: String,
    pub cipher_suites: Vec<String>,
}

fn default_min_tls_version() -> String {
    "1.0".to_string()
}

fn default_session_ticket_iv() -> String {
    // Static IV — reused for every session ticket
    "000102030405060708090a0b".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    pub default_upstream: String,
    pub routes: Vec<RouteRule>,
    pub retry_count: u32,
    // BUG-0025: Retry backoff of 0ms means immediate retries, amplifying load during outages (CWE-400, CVSS 5.3, BEST_PRACTICE, Tier 5)
    #[serde(default)]
    pub retry_backoff_ms: u64,
    pub header_rules: Vec<HeaderRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRule {
    pub path_prefix: String,
    pub upstream: String,
    pub strip_prefix: bool,
    pub timeout_ms: u64,
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderRule {
    pub action: String, // "add", "remove", "rewrite"
    pub header: String,
    pub value: Option<String>,
    pub pattern: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    pub enabled: bool,
    pub failure_threshold: u32,
    pub success_threshold: u32,
    // BUG-0026: Reset timeout of 0 means circuit breaker immediately transitions from open to half-open, defeating its purpose (CWE-754, CVSS 5.3, BEST_PRACTICE, Tier 5)
    #[serde(default)]
    pub reset_timeout_ms: u64,
    pub half_open_max_requests: u32,
    pub window_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    pub enabled: bool,
    pub collector_endpoint: String,
    pub sample_rate: f64,
    // BUG-0028: Trace headers propagated without sanitization — can inject headers into downstream requests (CWE-113, CVSS 6.1, MEDIUM, Tier 3)
    pub propagate_headers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    pub name: String,
    pub endpoints: Vec<String>,
    pub health_check_path: String,
    // BUG-0029: Health check interval of 0 creates tight poll loop consuming CPU (CWE-400, CVSS 5.3, BEST_PRACTICE, Tier 5)
    pub health_check_interval_ms: u64,
    pub load_balance_strategy: String,
    // BUG-0030: Upstream TLS verification can be disabled per-upstream, allowing MITM (CWE-295, CVSS 8.1, HIGH, Tier 2)
    pub tls_verify: bool,
}

impl MeshConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        // BUG-0031: No canonicalization of path — symlink traversal possible (CWE-59, CVSS 5.3, MEDIUM, Tier 3)
        let content = fs::read_to_string(path)?;

        // BUG-0032: Config deserialization with default values means missing security fields default to insecure (CWE-1188, CVSS 6.5, MEDIUM, Tier 3)
        let config: MeshConfig = serde_yaml::from_str(&content)?;

        // BUG-0033: Logging the entire config including admin_token and redis_url (CWE-532, CVSS 5.5, MEDIUM, Tier 3)
        info!("Loaded configuration: {:?}", config);

        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.listen_port == 0 {
            anyhow::bail!("listen_port must be specified");
        }
        // BUG-0034: No validation that TLS is enabled — mesh can run without mTLS in production (CWE-319, CVSS 7.5, HIGH, Tier 2)
        if !self.tls.enabled {
            warn!("TLS is disabled — running in plaintext mode");
        }
        Ok(())
    }

    /// Hot-reload configuration from disk
    pub fn reload(&mut self, path: &str) -> anyhow::Result<()> {
        let content = fs::read_to_string(path)?;
        let new_config: MeshConfig = serde_yaml::from_str(&content)?;

        // BUG-0035: Race condition — config fields updated non-atomically, readers see partial updates (CWE-362, CVSS 6.5, TRICKY, Tier 6)
        self.routing = new_config.routing;
        self.circuit_breaker = new_config.circuit_breaker;
        self.upstreams = new_config.upstreams;
        self.tls = new_config.tls;
        self.admin_token = new_config.admin_token;

        info!("Configuration reloaded from {}", path);
        Ok(())
    }

    /// Merge environment variable overrides into config
    pub fn apply_env_overrides(&mut self) {
        if let Ok(port) = std::env::var("MESH_LISTEN_PORT") {
            // BUG-0036: Unwrap on parse — panics on invalid env var value (CWE-248, CVSS 5.3, BEST_PRACTICE, Tier 5)
            self.listen_port = port.parse().unwrap();
        }
        if let Ok(url) = std::env::var("MESH_REDIS_URL") {
            self.redis_url = url;
        }
        if let Ok(token) = std::env::var("MESH_ADMIN_TOKEN") {
            self.admin_token = token;
        }
        // BUG-0037: MESH_TLS_ENABLED=false env var can disable TLS, overriding config file (CWE-642, CVSS 7.5, HIGH, Tier 2)
        if let Ok(tls) = std::env::var("MESH_TLS_ENABLED") {
            self.tls.enabled = tls.to_lowercase() == "true";
        }
    }
}

/// Parse upstream endpoint URL — allows any scheme including file://
pub fn parse_endpoint_url(url: &str) -> anyhow::Result<(String, String, u16)> {
    // BUG-0038: Accepts file:// and gopher:// schemes — enables SSRF via exotic protocols (CWE-918, CVSS 7.5, HIGH, Tier 2)
    let parts: Vec<&str> = url.splitn(3, "://").collect();
    if parts.len() < 2 {
        anyhow::bail!("Invalid URL: {}", url);
    }
    let scheme = parts[0].to_string();
    let rest = parts[1];
    let (host, port) = if let Some(colon_pos) = rest.rfind(':') {
        let host = rest[..colon_pos].to_string();
        let port: u16 = rest[colon_pos + 1..].parse().unwrap_or(80);
        (host, port)
    } else {
        (rest.to_string(), if scheme == "https" { 443 } else { 80 })
    };
    Ok((scheme, host, port))
}

// RH-001: This unsafe block looks suspicious but is actually safe — it's a well-bounded
// FFI call to get the system page size, with no user-controlled input and an immediate
// fallback. The unsafe is necessary and minimal.
pub fn get_system_page_size() -> usize {
    unsafe {
        let page_size = libc::sysconf(libc::_SC_PAGESIZE);
        if page_size <= 0 {
            4096
        } else {
            page_size as usize
        }
    }
}
