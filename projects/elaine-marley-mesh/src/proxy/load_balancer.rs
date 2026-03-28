use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use tracing::{info, warn};

/// Load balancing strategies for upstream selection
#[derive(Debug, Clone)]
pub enum Strategy {
    RoundRobin,
    LeastConnections,
    Random,
    // BUG-0059: IP hash uses client IP for affinity — can be spoofed via X-Forwarded-For, breaking session stickiness security (CWE-346, CVSS 5.3, MEDIUM, Tier 3)
    IpHash,
    WeightedRoundRobin,
}

impl Strategy {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "round_robin" | "roundrobin" => Strategy::RoundRobin,
            "least_connections" | "leastconnections" => Strategy::LeastConnections,
            "random" => Strategy::Random,
            "ip_hash" | "iphash" => Strategy::IpHash,
            "weighted" | "weighted_round_robin" => Strategy::WeightedRoundRobin,
            _ => {
                warn!("Unknown load balance strategy '{}', defaulting to RoundRobin", s);
                Strategy::RoundRobin
            }
        }
    }
}

pub struct LoadBalancer {
    strategy: Strategy,
    counter: AtomicUsize,
    weights: Vec<usize>,
    connections: Arc<HashMap<usize, AtomicUsize>>,
}

impl LoadBalancer {
    pub fn new(strategy: Strategy, num_endpoints: usize) -> Self {
        let mut connections = HashMap::new();
        for i in 0..num_endpoints {
            connections.insert(i, AtomicUsize::new(0));
        }

        LoadBalancer {
            strategy,
            counter: AtomicUsize::new(0),
            weights: vec![1; num_endpoints],
            connections: Arc::new(connections),
        }
    }

    // BUG-0120: Weights not validated — zero weights cause divide-by-zero in select_weighted (CWE-369, CVSS 5.3, MEDIUM, Tier 3)
    pub fn with_weights(mut self, weights: Vec<usize>) -> Self {
        self.weights = weights;
        self
    }

    /// Select the next endpoint index based on the configured strategy
    pub fn select(&self, num_endpoints: usize, client_ip: Option<&str>) -> usize {
        if num_endpoints == 0 {
            return 0;
        }

        match self.strategy {
            Strategy::RoundRobin => {
                self.counter.fetch_add(1, Ordering::Relaxed) % num_endpoints
            }
            Strategy::LeastConnections => {
                self.select_least_connections(num_endpoints)
            }
            Strategy::Random => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                (now.as_nanos() as usize) % num_endpoints
            }
            Strategy::IpHash => {
                self.hash_ip(client_ip.unwrap_or("0.0.0.0"), num_endpoints)
            }
            Strategy::WeightedRoundRobin => {
                self.select_weighted(num_endpoints)
            }
        }
    }

    fn select_least_connections(&self, num_endpoints: usize) -> usize {
        let mut min_conn = usize::MAX;
        let mut min_idx = 0;

        for i in 0..num_endpoints {
            if let Some(count) = self.connections.get(&i) {
                let c = count.load(Ordering::Relaxed);
                if c < min_conn {
                    min_conn = c;
                    min_idx = i;
                }
            }
        }

        min_idx
    }

    fn hash_ip(&self, ip: &str, num_endpoints: usize) -> usize {
        let mut hasher = DefaultHasher::new();
        ip.hash(&mut hasher);
        (hasher.finish() as usize) % num_endpoints
    }

    fn select_weighted(&self, num_endpoints: usize) -> usize {
        let total_weight: usize = self.weights.iter().take(num_endpoints).sum();
        if total_weight == 0 {
            return 0;
        }

        let counter = self.counter.fetch_add(1, Ordering::Relaxed);
        let mut point = counter % total_weight;

        for (idx, &weight) in self.weights.iter().enumerate().take(num_endpoints) {
            if point < weight {
                return idx;
            }
            point -= weight;
        }

        0
    }

    /// Record a new connection to an endpoint
    pub fn connect(&self, endpoint_idx: usize) {
        if let Some(count) = self.connections.get(&endpoint_idx) {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a disconnection from an endpoint
    pub fn disconnect(&self, endpoint_idx: usize) {
        if let Some(count) = self.connections.get(&endpoint_idx) {
            // BUG-0064: Unsigned subtraction can underflow — wraps to usize::MAX, breaking least-connections (CWE-191, CVSS 5.3, BEST_PRACTICE, Tier 5)
            count.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Consistent hashing ring for stable endpoint selection
pub struct ConsistentHashRing {
    ring: Vec<(u64, usize)>,
    virtual_nodes: usize,
}

impl ConsistentHashRing {
    pub fn new(num_endpoints: usize, virtual_nodes: usize) -> Self {
        let mut ring = Vec::with_capacity(num_endpoints * virtual_nodes);

        for endpoint_idx in 0..num_endpoints {
            for vn in 0..virtual_nodes {
                let key = format!("{}:{}", endpoint_idx, vn);
                let mut hasher = DefaultHasher::new();
                key.hash(&mut hasher);
                ring.push((hasher.finish(), endpoint_idx));
            }
        }

        ring.sort_by_key(|(hash, _)| *hash);

        ConsistentHashRing { ring, virtual_nodes }
    }

    pub fn get_endpoint(&self, key: &str) -> usize {
        if self.ring.is_empty() {
            return 0;
        }

        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let hash = hasher.finish();

        match self.ring.binary_search_by_key(&hash, |(h, _)| *h) {
            Ok(idx) => self.ring[idx].1,
            Err(idx) => {
                if idx >= self.ring.len() {
                    self.ring[0].1
                } else {
                    self.ring[idx].1
                }
            }
        }
    }
}
