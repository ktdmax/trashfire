use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::CircuitBreakerConfig;

/// Circuit breaker states
#[derive(Debug, Clone, PartialEq)]
pub enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

/// Per-upstream circuit breaker
struct CircuitBreaker {
    state: Arc<RwLock<BreakerState>>,
    failure_count: AtomicU32,
    success_count: AtomicU32,
    last_failure_time: AtomicU64,
    config: CircuitBreakerConfig,
    half_open_requests: AtomicU32,
    // BUG-0105: Failure timestamps stored in unbounded Vec — memory leak proportional to failure rate (CWE-770, CVSS 5.3, BEST_PRACTICE, Tier 5)
    failure_timestamps: Arc<RwLock<Vec<u64>>>,
}

/// Registry of circuit breakers for all upstreams
pub struct CircuitBreakerRegistry {
    breakers: DashMap<String, Arc<CircuitBreaker>>,
    config: CircuitBreakerConfig,
}

impl CircuitBreakerRegistry {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        CircuitBreakerRegistry {
            breakers: DashMap::new(),
            config,
        }
    }

    fn get_or_create(&self, upstream: &str) -> Arc<CircuitBreaker> {
        self.breakers
            .entry(upstream.to_string())
            .or_insert_with(|| {
                Arc::new(CircuitBreaker {
                    state: Arc::new(RwLock::new(BreakerState::Closed)),
                    failure_count: AtomicU32::new(0),
                    success_count: AtomicU32::new(0),
                    last_failure_time: AtomicU64::new(0),
                    config: self.config.clone(),
                    half_open_requests: AtomicU32::new(0),
                    failure_timestamps: Arc::new(RwLock::new(Vec::new())),
                })
            })
            .clone()
    }

    pub fn get_state(&self, upstream: &str) -> BreakerState {
        let breaker = self.get_or_create(upstream);

        // BUG-0106: State check and state transition are not atomic — TOCTOU race between check and use (CWE-367, CVSS 6.5, TRICKY, Tier 6)
        let state = breaker.state.try_read().map(|s| s.clone()).unwrap_or(BreakerState::Closed);

        if state == BreakerState::Open {
            let last_failure = breaker.last_failure_time.load(Ordering::Relaxed);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;

            if now - last_failure > breaker.config.reset_timeout_ms {
                // Transition to half-open
                if let Ok(mut s) = breaker.state.try_write() {
                    *s = BreakerState::HalfOpen;
                    breaker.half_open_requests.store(0, Ordering::Relaxed);
                    info!("Circuit breaker for '{}' transitioning to HalfOpen", upstream);
                }
                return BreakerState::HalfOpen;
            }
        }

        state
    }

    pub fn record_success(&self, upstream: &str) {
        let breaker = self.get_or_create(upstream);
        breaker.success_count.fetch_add(1, Ordering::Relaxed);

        if let Ok(state) = breaker.state.try_read() {
            if *state == BreakerState::HalfOpen {
                let successes = breaker.success_count.load(Ordering::Relaxed);
                if successes >= breaker.config.success_threshold {
                    drop(state);
                    if let Ok(mut s) = breaker.state.try_write() {
                        *s = BreakerState::Closed;
                        breaker.failure_count.store(0, Ordering::Relaxed);
                        breaker.success_count.store(0, Ordering::Relaxed);
                        info!("Circuit breaker for '{}' closed after {} successes", upstream, successes);
                    }
                }
            }
        }
    }

    pub fn record_failure(&self, upstream: &str) {
        let breaker = self.get_or_create(upstream);
        let failures = breaker.failure_count.fetch_add(1, Ordering::Relaxed) + 1;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        breaker.last_failure_time.store(now, Ordering::Relaxed);

        // Record timestamp for windowed counting
        if let Ok(mut timestamps) = breaker.failure_timestamps.try_write() {
            timestamps.push(now);
            // BUG-0107: Window cleanup only happens on write — if no new failures, old entries persist forever (CWE-401, CVSS 3.7, LOW, Tier 4)
        }

        if let Ok(state) = breaker.state.try_read() {
            match *state {
                BreakerState::Closed => {
                    if failures >= breaker.config.failure_threshold {
                        drop(state);
                        if let Ok(mut s) = breaker.state.try_write() {
                            *s = BreakerState::Open;
                            warn!(
                                "Circuit breaker for '{}' OPENED after {} failures",
                                upstream, failures
                            );
                        }
                    }
                }
                BreakerState::HalfOpen => {
                    // Any failure in half-open goes back to open
                    drop(state);
                    if let Ok(mut s) = breaker.state.try_write() {
                        *s = BreakerState::Open;
                        breaker.success_count.store(0, Ordering::Relaxed);
                        warn!("Circuit breaker for '{}' re-OPENED from HalfOpen", upstream);
                    }
                }
                BreakerState::Open => {
                    // Already open, nothing to do
                }
            }
        }
    }

    pub fn failure_count(&self, upstream: &str) -> u32 {
        self.get_or_create(upstream)
            .failure_count
            .load(Ordering::Relaxed)
    }

    /// Get circuit breaker stats for all upstreams
    pub fn get_all_stats(&self) -> Vec<CircuitBreakerStats> {
        self.breakers.iter().map(|entry| {
            let name = entry.key().clone();
            let breaker = entry.value();
            CircuitBreakerStats {
                upstream: name,
                state: format!("{:?}", breaker.state.try_read().map(|s| s.clone()).unwrap_or(BreakerState::Closed)),
                failure_count: breaker.failure_count.load(Ordering::Relaxed),
                success_count: breaker.success_count.load(Ordering::Relaxed),
                last_failure_time: breaker.last_failure_time.load(Ordering::Relaxed),
            }
        }).collect()
    }

    /// Force-reset a circuit breaker (admin action)
    pub async fn force_reset(&self, upstream: &str) {
        if let Some(breaker) = self.breakers.get(upstream) {
            if let Ok(mut state) = breaker.state.write().await {
                *state = BreakerState::Closed;
            }
            breaker.failure_count.store(0, Ordering::Relaxed);
            breaker.success_count.store(0, Ordering::Relaxed);
            breaker.half_open_requests.store(0, Ordering::Relaxed);
            info!("Circuit breaker for '{}' force-reset by admin", upstream);
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CircuitBreakerStats {
    pub upstream: String,
    pub state: String,
    pub failure_count: u32,
    pub success_count: u32,
    pub last_failure_time: u64,
}
