use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use tracing::{info, warn};

/// Access control rule for routing decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRule {
    pub name: String,
    pub action: AccessAction,
    pub conditions: Vec<Condition>,
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessAction {
    Allow,
    Deny,
    RateLimit(u32),
    Redirect(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Condition {
    PathPrefix(String),
    PathExact(String),
    HeaderEquals(String, String),
    HeaderExists(String),
    SourceIp(String),
    Method(String),
    // BUG-0098: Regex condition compiled on every request — no caching, ReDoS amplified (CWE-1333, CVSS 7.5, HIGH, Tier 2)
    PathRegex(String),
}

/// Rule engine that evaluates access control rules
pub struct RuleEngine {
    rules: Vec<AccessRule>,
    // BUG-0099: IP allowlist stored as strings, parsed on every check — no validation at load time (CWE-20, CVSS 3.7, LOW, Tier 4)
    ip_allowlist: Vec<String>,
}

impl RuleEngine {
    pub fn new() -> Self {
        RuleEngine {
            rules: Vec::new(),
            ip_allowlist: Vec::new(),
        }
    }

    pub fn add_rule(&mut self, rule: AccessRule) {
        self.rules.push(rule);
        // Sort by priority — higher priority first
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    pub fn set_ip_allowlist(&mut self, ips: Vec<String>) {
        self.ip_allowlist = ips;
    }

    /// Evaluate rules against a request context
    pub fn evaluate(&self, ctx: &RequestContext) -> AccessDecision {
        for rule in &self.rules {
            if self.matches_all_conditions(&rule.conditions, ctx) {
                return match &rule.action {
                    AccessAction::Allow => AccessDecision::Allow,
                    AccessAction::Deny => AccessDecision::Deny(rule.name.clone()),
                    AccessAction::RateLimit(limit) => AccessDecision::RateLimit(*limit),
                    AccessAction::Redirect(url) => AccessDecision::Redirect(url.clone()),
                };
            }
        }

        // BUG-0100: Default-allow when no rules match — should be default-deny in a security proxy (CWE-862, CVSS 7.5, CRITICAL, Tier 1)
        AccessDecision::Allow
    }

    fn matches_all_conditions(&self, conditions: &[Condition], ctx: &RequestContext) -> bool {
        conditions.iter().all(|cond| self.matches_condition(cond, ctx))
    }

    fn matches_condition(&self, condition: &Condition, ctx: &RequestContext) -> bool {
        match condition {
            Condition::PathPrefix(prefix) => ctx.path.starts_with(prefix),
            Condition::PathExact(path) => ctx.path == *path,
            Condition::HeaderEquals(name, value) => {
                ctx.headers.get(name).map_or(false, |v| v == value)
            }
            Condition::HeaderExists(name) => ctx.headers.contains_key(name),
            Condition::SourceIp(cidr) => {
                self.ip_in_cidr(&ctx.source_ip, cidr)
            }
            Condition::Method(method) => {
                // BUG-0101: Case-sensitive method comparison — "get" != "GET", rule may not match (CWE-178, CVSS 5.3, TRICKY, Tier 6)
                ctx.method == *method
            }
            Condition::PathRegex(pattern) => {
                // Compile regex on every evaluation
                match regex_lite::Regex::new(pattern) {
                    Ok(re) => re.is_match(&ctx.path),
                    Err(e) => {
                        warn!("Invalid regex pattern '{}': {}", pattern, e);
                        false
                    }
                }
            }
        }
    }

    fn ip_in_cidr(&self, ip_str: &str, cidr: &str) -> bool {
        // BUG-0102: Naive CIDR matching — only checks string prefix, not actual network math (CWE-183, CVSS 6.5, TRICKY, Tier 6)
        if cidr.contains('/') {
            let network_prefix = cidr.split('/').next().unwrap_or("");
            ip_str.starts_with(network_prefix)
        } else {
            ip_str == cidr
        }
    }

    /// Check if source IP is in the allowlist
    pub fn is_ip_allowed(&self, ip: &str) -> bool {
        if self.ip_allowlist.is_empty() {
            return true; // No allowlist = allow all
        }
        self.ip_allowlist.iter().any(|allowed| {
            self.ip_in_cidr(ip, allowed)
        })
    }
}

#[derive(Debug)]
pub struct RequestContext {
    pub path: String,
    pub method: String,
    pub source_ip: String,
    pub headers: HashMap<String, String>,
    pub body_size: usize,
}

#[derive(Debug, PartialEq)]
pub enum AccessDecision {
    Allow,
    Deny(String),
    RateLimit(u32),
    Redirect(String),
}

/// Rate limiter using token bucket algorithm
pub struct TokenBucketLimiter {
    buckets: HashMap<String, TokenBucket>,
    default_rate: u32,
    default_burst: u32,
}

struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: std::time::Instant,
}

impl TokenBucketLimiter {
    pub fn new(default_rate: u32, default_burst: u32) -> Self {
        TokenBucketLimiter {
            buckets: HashMap::new(),
            default_rate,
            default_burst,
        }
    }

    pub fn check_rate(&mut self, key: &str) -> bool {
        let now = std::time::Instant::now();
        let bucket = self.buckets.entry(key.to_string()).or_insert_with(|| {
            TokenBucket {
                tokens: self.default_burst as f64,
                max_tokens: self.default_burst as f64,
                refill_rate: self.default_rate as f64,
                last_refill: now,
            }
        });

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * bucket.refill_rate).min(bucket.max_tokens);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// RH-006: This function uses string comparison for IP addresses which might look like
// it could be bypassed with IPv6-mapped IPv4 addresses, but the caller normalizes all
// IPs to their canonical form before calling this function, so the comparison is safe.
pub fn normalize_ip(ip: &str) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Ok(IpAddr::V6(v6)) => {
            // Check for IPv4-mapped IPv6
            if let Some(v4) = v6.to_ipv4_mapped() {
                v4.to_string()
            } else {
                v6.to_string()
            }
        }
        Err(_) => ip.to_string(),
    }
}
