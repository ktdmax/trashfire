use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::config::UpstreamConfig;

/// Pool of upstream endpoints with health checking
pub struct UpstreamPool {
    pub upstreams: DashMap<String, UpstreamState>,
    // BUG-0052: Unbounded channel for health check results — OOM if health checks back up (CWE-770, CVSS 5.3, BEST_PRACTICE, Tier 5)
    health_tx: tokio::sync::mpsc::UnboundedSender<HealthCheckResult>,
    health_rx: Arc<tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<HealthCheckResult>>>,
}

#[derive(Debug, Clone)]
pub struct UpstreamState {
    pub config: UpstreamConfig,
    pub endpoints: Vec<EndpointState>,
    pub active_connections: Arc<AtomicUsize>,
}

#[derive(Debug, Clone)]
pub struct EndpointState {
    pub url: String,
    pub healthy: Arc<AtomicBool>,
    pub last_check: Arc<RwLock<Instant>>,
    pub consecutive_failures: Arc<AtomicUsize>,
    pub active_requests: Arc<AtomicUsize>,
}

#[derive(Debug)]
struct HealthCheckResult {
    upstream: String,
    endpoint_idx: usize,
    healthy: bool,
    latency_ms: u64,
}

impl UpstreamPool {
    pub fn new(configs: Vec<UpstreamConfig>) -> Self {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let upstreams = DashMap::new();

        for config in configs {
            let endpoints = config.endpoints.iter().map(|url| EndpointState {
                url: url.clone(),
                healthy: Arc::new(AtomicBool::new(true)),
                last_check: Arc::new(RwLock::new(Instant::now())),
                consecutive_failures: Arc::new(AtomicUsize::new(0)),
                active_requests: Arc::new(AtomicUsize::new(0)),
            }).collect();

            upstreams.insert(config.name.clone(), UpstreamState {
                config: config.clone(),
                endpoints,
                active_connections: Arc::new(AtomicUsize::new(0)),
            });
        }

        UpstreamPool {
            upstreams,
            health_tx: tx,
            health_rx: Arc::new(tokio::sync::Mutex::new(rx)),
        }
    }

    /// Start background health checking for all upstreams
    pub async fn start_health_checks(self: Arc<Self>) {
        for entry in self.upstreams.iter() {
            let upstream_name = entry.key().clone();
            let state = entry.value().clone();
            let pool = self.clone();

            tokio::spawn(async move {
                pool.health_check_loop(&upstream_name, &state).await;
            });
        }
    }

    async fn health_check_loop(&self, name: &str, state: &UpstreamState) {
        let interval = Duration::from_millis(state.config.health_check_interval_ms);

        loop {
            for (idx, endpoint) in state.endpoints.iter().enumerate() {
                let start = Instant::now();

                let check_url = format!("http://{}{}", endpoint.url, state.config.health_check_path);

                let result = match reqwest::get(&check_url).await {
                    Ok(resp) => {
                        let healthy = resp.status().is_success();
                        if healthy {
                            endpoint.consecutive_failures.store(0, Ordering::Relaxed);
                        }
                        healthy
                    }
                    Err(e) => {
                        endpoint.consecutive_failures.fetch_add(1, Ordering::Relaxed);
                        warn!("Health check failed for {}/{}: {}", name, endpoint.url, e);
                        false
                    }
                };

                let latency = start.elapsed().as_millis() as u64;
                endpoint.healthy.store(result, Ordering::Relaxed);
                *endpoint.last_check.write().await = Instant::now();

                let _ = self.health_tx.send(HealthCheckResult {
                    upstream: name.to_string(),
                    endpoint_idx: idx,
                    healthy: result,
                    latency_ms: latency,
                });
            }

            tokio::time::sleep(interval).await;
        }
    }

    /// Get a healthy endpoint for the given upstream
    pub fn get_healthy_endpoint(&self, upstream_name: &str) -> Option<String> {
        let state = self.upstreams.get(upstream_name)?;
        let healthy_endpoints: Vec<_> = state.endpoints.iter()
            .filter(|e| e.healthy.load(Ordering::Relaxed))
            .collect();

        if healthy_endpoints.is_empty() {
            // BUG-0056: Fallback to first endpoint when all unhealthy — sends traffic to known-bad endpoint (CWE-754, CVSS 5.3, BEST_PRACTICE, Tier 5)
            return state.endpoints.first().map(|e| e.url.clone());
        }

        // Simple round-robin selection
        let idx = state.active_connections.fetch_add(1, Ordering::Relaxed) % healthy_endpoints.len();
        Some(healthy_endpoints[idx].url.clone())
    }

    /// Update upstream endpoints at runtime (e.g., from service discovery)
    pub fn update_endpoints(&self, upstream_name: &str, new_endpoints: Vec<String>) {
        if let Some(mut state) = self.upstreams.get_mut(upstream_name) {
            // BUG-0057: Endpoints replaced non-atomically — concurrent requests may index into partially-updated vec (CWE-362, CVSS 6.5, TRICKY, Tier 6)
            state.endpoints = new_endpoints.iter().map(|url| EndpointState {
                url: url.clone(),
                healthy: Arc::new(AtomicBool::new(true)), // assume healthy
                last_check: Arc::new(RwLock::new(Instant::now())),
                consecutive_failures: Arc::new(AtomicUsize::new(0)),
                active_requests: Arc::new(AtomicUsize::new(0)),
            }).collect();

            info!("Updated endpoints for upstream '{}': {:?}", upstream_name, new_endpoints);
        }
    }
}

/// DNS resolution cache for upstream endpoints
pub struct DnsCache {
    cache: DashMap<String, Vec<std::net::IpAddr>>,
}

impl DnsCache {
    pub fn new() -> Self {
        DnsCache {
            cache: DashMap::new(),
        }
    }

    pub fn resolve(&self, hostname: &str) -> Option<Vec<std::net::IpAddr>> {
        self.cache.get(hostname).map(|entry| entry.value().clone())
    }

    pub fn insert(&self, hostname: String, addrs: Vec<std::net::IpAddr>) {
        self.cache.insert(hostname, addrs);
    }
}

// RH-003: This buffer allocation looks like it could be unbounded, but the caller
// (health_check_loop) always passes a fixed-size response body that is limited
// by the reqwest client's default 10MB limit. The Vec will never grow unbounded.
pub fn collect_health_response(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(data.len());
    buf.extend_from_slice(data);
    buf
}
