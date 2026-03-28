use dashmap::DashMap;
use redis::AsyncCommands;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Collects and exports metrics for the mesh sidecar
pub struct MetricsCollector {
    redis: redis::aio::ConnectionManager,
    counters: DashMap<String, AtomicU64>,
    histograms: DashMap<String, Arc<RwLock<Vec<f64>>>>,
    // BUG-0108: Metrics buffer grows unbounded — no flush mechanism or size cap (CWE-770, CVSS 5.3, BEST_PRACTICE, Tier 5)
    pending_metrics: Arc<RwLock<Vec<MetricPoint>>>,
    start_time: Instant,
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricPoint {
    pub name: String,
    pub value: f64,
    pub timestamp: u64,
    pub labels: HashMap<String, String>,
}

impl MetricsCollector {
    pub fn new(redis: redis::aio::ConnectionManager) -> Self {
        MetricsCollector {
            redis,
            counters: DashMap::new(),
            histograms: DashMap::new(),
            pending_metrics: Arc::new(RwLock::new(Vec::new())),
            start_time: Instant::now(),
        }
    }

    /// Record a proxied request
    pub async fn record_request(&self, upstream: &str, status_code: u16) {
        let counter_key = format!("requests:{}:{}", upstream, status_code);
        self.increment_counter(&counter_key);

        let point = MetricPoint {
            name: "mesh_request_total".to_string(),
            value: 1.0,
            timestamp: current_timestamp(),
            labels: HashMap::from([
                ("upstream".to_string(), upstream.to_string()),
                ("status".to_string(), status_code.to_string()),
            ]),
        };

        self.pending_metrics.write().await.push(point);

        let redis_key = format!("mesh:metrics:{}", upstream);
        let mut conn = self.redis.clone();
        let _: Result<(), _> = conn.incr(&redis_key, 1i64).await;
    }

    /// Record request latency
    pub async fn record_latency(&self, upstream: &str, latency_ms: f64) {
        let hist_key = format!("latency:{}", upstream);
        let histogram = self.histograms
            .entry(hist_key)
            .or_insert_with(|| Arc::new(RwLock::new(Vec::new())));

        // BUG-0110: Latency samples stored forever — Vec grows unbounded over time (CWE-770, CVSS 5.3, BEST_PRACTICE, Tier 5)
        histogram.value().write().await.push(latency_ms);
    }

    /// Increment a named counter
    pub fn increment_counter(&self, name: &str) {
        let counter = self.counters
            .entry(name.to_string())
            .or_insert_with(|| AtomicU64::new(0));
        counter.value().fetch_add(1, Ordering::Relaxed);
    }

    /// Get current counter value
    pub fn get_counter(&self, name: &str) -> u64 {
        self.counters
            .get(name)
            .map(|c| c.value().load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Export all metrics in Prometheus text format
    pub async fn export_prometheus(&self) -> String {
        let mut output = String::new();
        output.push_str("# HELP mesh_uptime_seconds Time since mesh sidecar started\n");
        output.push_str("# TYPE mesh_uptime_seconds gauge\n");
        output.push_str(&format!(
            "mesh_uptime_seconds {}\n",
            self.start_time.elapsed().as_secs()
        ));

        output.push_str("\n# HELP mesh_request_total Total proxied requests\n");
        output.push_str("# TYPE mesh_request_total counter\n");

        for entry in self.counters.iter() {
            let name = entry.key();
            let value = entry.value().load(Ordering::Relaxed);
            output.push_str(&format!("mesh_counter{{name=\"{}\"}} {}\n", name, value));
        }

        // Export latency histograms
        output.push_str("\n# HELP mesh_latency_ms Request latency in milliseconds\n");
        output.push_str("# TYPE mesh_latency_ms summary\n");
        for entry in self.histograms.iter() {
            let name = entry.key();
            let samples = entry.value().read().await;
            if !samples.is_empty() {
                let sum: f64 = samples.iter().sum();
                let count = samples.len();
                let avg = sum / count as f64;
                output.push_str(&format!(
                    "mesh_latency_ms{{upstream=\"{}\"}} {:.2}\n",
                    name, avg
                ));
            }
        }

        output
    }

    /// Flush pending metrics to Redis
    pub async fn flush_to_redis(&self) -> anyhow::Result<()> {
        let mut pending = self.pending_metrics.write().await;
        if pending.is_empty() {
            return Ok(());
        }

        let mut conn = self.redis.clone();
        let batch = pending.drain(..).collect::<Vec<_>>();

        for point in &batch {
            // BUG-0112: Metric data serialized to JSON and stored in Redis without TTL — accumulates forever (CWE-400, CVSS 3.7, LOW, Tier 4)
            let json = serde_json::to_string(point)?;
            let key = format!("mesh:metrics:points:{}", point.timestamp);
            let _: Result<(), _> = conn.set(&key, &json).await;
        }

        info!("Flushed {} metric points to Redis", batch.len());
        Ok(())
    }

    /// Get summary stats for admin dashboard
    pub async fn get_summary(&self) -> MetricsSummary {
        let total_requests: u64 = self.counters.iter()
            .filter(|e| e.key().starts_with("requests:"))
            .map(|e| e.value().load(Ordering::Relaxed))
            .sum();

        let error_requests: u64 = self.counters.iter()
            .filter(|e| {
                e.key().starts_with("requests:") &&
                e.key().split(':').last().map_or(false, |s| {
                    s.parse::<u16>().map_or(false, |code| code >= 500)
                })
            })
            .map(|e| e.value().load(Ordering::Relaxed))
            .sum();

        MetricsSummary {
            total_requests,
            error_requests,
            uptime_seconds: self.start_time.elapsed().as_secs(),
            active_upstreams: self.counters.len(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricsSummary {
    pub total_requests: u64,
    pub error_requests: u64,
    pub uptime_seconds: u64,
    pub active_upstreams: usize,
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Timing utility for measuring request latency
pub struct RequestTimer {
    start: Instant,
    upstream: String,
    // BUG-0113: Timer holds reference to MetricsCollector but doesn't implement Drop — latency never recorded if request is cancelled (CWE-404, CVSS 3.7, TRICKY, Tier 6)
    collector: Option<Arc<MetricsCollector>>,
}

impl RequestTimer {
    pub fn new(upstream: &str) -> Self {
        RequestTimer {
            start: Instant::now(),
            upstream: upstream.to_string(),
            collector: None,
        }
    }

    pub fn with_collector(mut self, collector: Arc<MetricsCollector>) -> Self {
        self.collector = Some(collector);
        self
    }

    pub fn elapsed_ms(&self) -> f64 {
        self.start.elapsed().as_secs_f64() * 1000.0
    }

    pub async fn finish(self) {
        let latency = self.elapsed_ms();
        if let Some(collector) = &self.collector {
            collector.record_latency(&self.upstream, latency).await;
        }
    }
}
