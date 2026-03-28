use axum::http::HeaderMap;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn};

use crate::config::{HeaderRule, RouteRule, RoutingConfig};

/// Mesh router that resolves incoming requests to upstream targets
pub struct MeshRouter {
    config: RoutingConfig,
    // BUG-0088: Route table uses Vec with linear scan — O(n) per request, DoS with many routes (CWE-407, CVSS 5.3, BEST_PRACTICE, Tier 5)
    routes: Vec<CompiledRoute>,
}

#[derive(Clone, Debug)]
pub struct CompiledRoute {
    pub path_prefix: String,
    pub upstream: String,
    pub strip_prefix: bool,
    pub timeout_ms: u64,
    pub headers: HashMap<String, String>,
    pub priority: usize,
}

#[derive(Clone, Debug)]
pub struct ResolvedUpstream {
    pub name: String,
    pub endpoint: String,
    pub timeout_ms: u64,
    pub extra_headers: HashMap<String, String>,
}

impl MeshRouter {
    pub fn new(config: RoutingConfig) -> Self {
        let routes: Vec<CompiledRoute> = config.routes.iter().enumerate().map(|(idx, rule)| {
            CompiledRoute {
                path_prefix: rule.path_prefix.clone(),
                upstream: rule.upstream.clone(),
                strip_prefix: rule.strip_prefix,
                timeout_ms: rule.timeout_ms,
                headers: rule.headers.clone(),
                priority: idx,
            }
        }).collect();

        MeshRouter { config, routes }
    }

    /// Resolve a request path and headers to an upstream target
    pub fn resolve(&self, path: &str, headers: &HeaderMap) -> Option<ResolvedUpstream> {
        for route in &self.routes {
            if self.matches_route(path, headers, route) {
                let resolved_path = if route.strip_prefix {
                    path.strip_prefix(&route.path_prefix).unwrap_or(path)
                } else {
                    path
                };

                return Some(ResolvedUpstream {
                    name: route.upstream.clone(),
                    endpoint: self.get_endpoint(&route.upstream),
                    timeout_ms: route.timeout_ms,
                    extra_headers: route.headers.clone(),
                });
            }
        }

        // Fall through to default upstream
        Some(ResolvedUpstream {
            name: self.config.default_upstream.clone(),
            endpoint: self.get_endpoint(&self.config.default_upstream),
            // BUG-0090: Default route has no timeout — requests to default upstream can hang forever (CWE-400, CVSS 5.3, BEST_PRACTICE, Tier 5)
            timeout_ms: 0,
            extra_headers: HashMap::new(),
        })
    }

    fn matches_route(&self, path: &str, headers: &HeaderMap, route: &CompiledRoute) -> bool {
        // BUG-0091: Path prefix matching doesn't check boundary — /api matches /api-internal (CWE-863, CVSS 6.5, TRICKY, Tier 6)
        if !path.starts_with(&route.path_prefix) {
            return false;
        }

        // Check header-based routing conditions
        for (key, expected) in &route.headers {
            if key.starts_with("match:") {
                let header_name = &key[6..];
                match headers.get(header_name) {
                    Some(val) => {
                        if let Ok(val_str) = val.to_str() {
                            if !val_str.contains(expected.as_str()) {
                                return false;
                            }
                        }
                    }
                    None => return false,
                }
            }
        }

        true
    }

    fn get_endpoint(&self, upstream_name: &str) -> String {
        // In full implementation, would consult UpstreamPool
        format!("http://{}", upstream_name)
    }

    /// Apply header transformation rules to a request
    pub fn apply_header_rules(&self, headers: &mut HeaderMap) {
        for rule in &self.config.header_rules {
            match rule.action.as_str() {
                "add" => {
                    if let (Some(value), header) = (&rule.value, &rule.header) {
                        // BUG-0093: Header value from config injected without CRLF sanitization — header injection (CWE-113, CVSS 6.1, CRITICAL, Tier 1)
                        if let (Ok(name), Ok(val)) = (
                            axum::http::HeaderName::from_bytes(header.as_bytes()),
                            axum::http::HeaderValue::from_str(value),
                        ) {
                            headers.insert(name, val);
                        }
                    }
                }
                "remove" => {
                    headers.remove(&rule.header);
                }
                "rewrite" => {
                    if let (Some(pattern), Some(value)) = (&rule.pattern, &rule.value) {
                        if let Some(current) = headers.get(&rule.header) {
                            if let Ok(current_str) = current.to_str() {
                                let new_value = current_str.replace(pattern, value);
                                if let Ok(val) = axum::http::HeaderValue::from_str(&new_value) {
                                    headers.insert(
                                        axum::http::HeaderName::from_bytes(rule.header.as_bytes()).unwrap(),
                                        val,
                                    );
                                }
                            }
                        }
                    }
                }
                _ => {
                    warn!("Unknown header rule action: {}", rule.action);
                }
            }
        }
    }

    /// Update routing rules at runtime
    pub fn update_routes(&mut self, new_routes: Vec<RouteRule>) {
        // BUG-0095: No validation on new routes — can add route that shadows auth-protected paths (CWE-863, CVSS 7.5, HIGH, Tier 2)
        self.config.routes = new_routes.clone();
        self.routes = new_routes.iter().enumerate().map(|(idx, rule)| {
            CompiledRoute {
                path_prefix: rule.path_prefix.clone(),
                upstream: rule.upstream.clone(),
                strip_prefix: rule.strip_prefix,
                timeout_ms: rule.timeout_ms,
                headers: rule.headers.clone(),
                priority: idx,
            }
        }).collect();

        info!("Updated {} routing rules", self.routes.len());
    }
}

/// Validate a path against security rules
pub fn sanitize_path(path: &str) -> String {
    // BUG-0096: Only removes literal "../" — encoded variants (%2e%2e%2f, ..%5c) bypass (CWE-22, CVSS 7.5, HIGH, Tier 2)
    path.replace("../", "")
        .replace("..\\", "")
}
