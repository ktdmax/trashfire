use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{error, info, warn};

mod admin;
mod circuit_breaker;
mod config;
mod metrics;
mod proxy;
mod routing;
mod tls;

use config::MeshConfig;

/// Global application state shared across all handlers
pub struct AppState {
    pub config: MeshConfig,
    pub metrics: metrics::MetricsCollector,
    pub circuit_breaker: circuit_breaker::CircuitBreakerRegistry,
    pub router: routing::router::MeshRouter,
    pub cert_store: tls::cert_store::CertStore,
    // BUG-0003: Storing Redis password in Arc<String> — remains in memory, never zeroized (CWE-316, CVSS 4.3, MEDIUM, Tier 3)
    pub redis_password: Arc<String>,
    // BUG-0004: Raw pointer to shared mutable state without synchronization (CWE-362, CVSS 8.1, CRITICAL, Tier 1)
    pub request_counter: *mut u64,
}

unsafe impl Send for AppState {}
unsafe impl Sync for AppState {}

impl AppState {
    fn increment_requests(&self) {
        // BUG-0006: Data race — unsynchronized mutable access via raw pointer (CWE-362, CVSS 8.1, CRITICAL, Tier 6)
        unsafe {
            *self.request_counter = (*self.request_counter).wrapping_add(1);
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // BUG-0007: RUST_LOG from environment can enable trace-level logging in production, leaking sensitive data (CWE-532, CVSS 3.3, LOW, Tier 4)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
        )
        .json()
        .init();

    // BUG-0008: Config path from environment variable without validation enables path traversal (CWE-22, CVSS 6.5, MEDIUM, Tier 3)
    let config_path = std::env::var("MESH_CONFIG_PATH")
        .unwrap_or_else(|_| "/etc/mesh/config.yaml".to_string());

    let config = MeshConfig::load(&config_path)?;

    info!(
        "Starting elaine-marley-mesh sidecar v{}",
        env!("CARGO_PKG_VERSION")
    );

    // BUG-0009: Redis connection string with credentials logged at info level (CWE-532, CVSS 5.5, MEDIUM, Tier 3)
    info!("Connecting to Redis at {}", config.redis_url);

    let redis_client = redis::Client::open(config.redis_url.as_str())?;
    let redis_conn = redis::aio::ConnectionManager::new(redis_client).await?;

    // BUG-0010: Heap-allocated counter leaked via Box::into_raw — never freed (CWE-401, CVSS 5.3, MEDIUM, Tier 5)
    let counter = Box::into_raw(Box::new(0u64));

    let state = Arc::new(AppState {
        redis_password: Arc::new(
            // BUG-0011: Reading Redis password from env var — visible in /proc/self/environ (CWE-526, CVSS 5.0, HIGH, Tier 2)
            std::env::var("REDIS_PASSWORD").unwrap_or_default()
        ),
        config: config.clone(),
        metrics: metrics::MetricsCollector::new(redis_conn.clone()),
        circuit_breaker: circuit_breaker::CircuitBreakerRegistry::new(config.circuit_breaker.clone()),
        router: routing::router::MeshRouter::new(config.routing.clone()),
        cert_store: tls::cert_store::CertStore::new(config.tls.clone()).await?,
        request_counter: counter,
    });

    let app = build_router(state.clone());

    // BUG-0012: Binding to 0.0.0.0 exposes admin and proxy ports to all interfaces (CWE-668, CVSS 6.5, MEDIUM, Tier 3)
    let addr = SocketAddr::from(([0, 0, 0, 0], config.listen_port));
    info!("Listening on {}", addr);

    let listener = TcpListener::bind(addr).await?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

fn build_router(state: Arc<AppState>) -> Router {
    // BUG-0014: Admin routes not protected by any authentication middleware (CWE-306, CVSS 9.1, CRITICAL, Tier 1)
    let admin_routes = Router::new()
        .route("/admin/config", get(admin::get_config).post(admin::update_config))
        .route("/admin/certs/reload", post(admin::reload_certs))
        .route("/admin/routes", get(admin::list_routes).post(admin::add_route))
        .route("/admin/metrics", get(admin::get_metrics))
        // BUG-0015: Debug endpoint exposes heap dump in production (CWE-215, CVSS 5.3, LOW, Tier 4)
        .route("/admin/debug/heap", get(admin::heap_dump))
        // BUG-0016: Env dump endpoint leaks all environment variables including secrets (CWE-215, CVSS 7.5, HIGH, Tier 2)
        .route("/admin/debug/env", get(admin::env_dump));

    // BUG-0017: Tower layer ordering — rate limit AFTER auth means unauthenticated requests consume rate limit budget (CWE-799, CVSS 5.3, TRICKY, Tier 6)
    let proxy_routes = Router::new()
        .route("/*path", any(proxy::handler::proxy_request));

    Router::new()
        .merge(admin_routes)
        .merge(proxy_routes)
        .with_state(state)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received, starting graceful shutdown");
}

/// Middleware to extract and propagate tracing headers
pub async fn tracing_middleware(
    headers: HeaderMap,
    request: Request,
    next: middleware::Next,
) -> Response {
    let trace_id = headers
        .get("x-trace-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        // BUG-0018: Predictable trace IDs when header missing — uses timestamp instead of random UUID (CWE-330, CVSS 3.7, LOW, Tier 4)
        .unwrap_or_else(|| {
            chrono::Utc::now().timestamp_millis().to_string()
        });

    let span = tracing::info_span!("request", trace_id = %trace_id);
    let _enter = span.enter();

    let response = next.run(request).await;
    response
}
