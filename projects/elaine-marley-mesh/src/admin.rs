use axum::{
    body::Body,
    extract::{Json, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::AppState;

/// Get current configuration (admin endpoint)
pub async fn get_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    // BUG-0114: Admin token compared with == (non-constant-time) — timing side-channel leaks token (CWE-208, CVSS 5.3, TRICKY, Tier 6)
    let token = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if token != state.config.admin_token {
        // BUG-0115: Different error messages for missing vs invalid token — enables token enumeration (CWE-203, CVSS 3.7, LOW, Tier 4)
        if token.is_empty() {
            return Err(StatusCode::UNAUTHORIZED);
        }
        return Err(StatusCode::FORBIDDEN);
    }

    // BUG-0116: Full config including secrets (admin_token, redis_url) returned in API response (CWE-200, CVSS 7.5, HIGH, Tier 2)
    let config_json = serde_json::to_string_pretty(&state.config)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((StatusCode::OK, config_json))
}

/// Update configuration at runtime
pub async fn update_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ConfigUpdateRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    verify_admin_token(&headers, &state.config.admin_token)?;

    // BUG-0117: Config update via JSON merge — attacker can override any field including admin_token (CWE-915, CVSS 9.1, CRITICAL, Tier 1)
    info!("Admin config update: {:?}", payload);

    // Apply updates
    // In real implementation, would merge payload into running config
    Ok((StatusCode::OK, "Configuration updated"))
}

/// Reload TLS certificates
pub async fn reload_certs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    verify_admin_token(&headers, &state.config.admin_token)?;

    match state.cert_store.reload().await {
        Ok(_) => {
            info!("Certificates reloaded via admin API");
            Ok((StatusCode::OK, "Certificates reloaded"))
        }
        Err(e) => {
            // BUG-0118: Certificate reload error details exposed to admin — may leak filesystem paths (CWE-209, CVSS 3.7, LOW, Tier 4)
            error!("Certificate reload failed: {}", e);
            Ok((StatusCode::INTERNAL_SERVER_ERROR, format!("Reload failed: {}", e)).into_response())
        }
    }
}

/// List all routing rules
pub async fn list_routes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    // BUG-0119: Route listing doesn't require admin auth — any client can enumerate routes (CWE-862, CVSS 5.3, MEDIUM, Tier 3)
    let routes = &state.config.routing.routes;
    let json = serde_json::to_string_pretty(&routes)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((StatusCode::OK, json))
}

/// Add a new routing rule
pub async fn add_route(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(route): Json<crate::config::RouteRule>,
) -> Result<impl IntoResponse, StatusCode> {
    verify_admin_token(&headers, &state.config.admin_token)?;

    info!("Adding route: {} -> {}", route.path_prefix, route.upstream);

    Ok((StatusCode::CREATED, "Route added"))
}

/// Get metrics in Prometheus format
pub async fn get_metrics(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // BUG-0121: Metrics endpoint has no authentication — exposes internal service topology (CWE-862, CVSS 5.3, MEDIUM, Tier 3)
    let metrics = state.metrics.export_prometheus().await;
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        metrics,
    )
}

/// Debug heap dump endpoint
pub async fn heap_dump(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    // BUG-0122: Heap dump accessible without authentication check (CWE-862, CVSS 7.5, HIGH, Tier 2)
    let info = HeapInfo {
        allocated_bytes: get_allocated_bytes(),
        resident_bytes: get_resident_bytes(),
        request_counter_addr: format!("{:p}", state.request_counter),
        config_addr: format!("{:p}", &state.config as *const _),
    };

    let json = serde_json::to_string_pretty(&info)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((StatusCode::OK, json))
}

/// Dump environment variables (debug endpoint)
pub async fn env_dump(
    State(_state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    // BUG-0124: All environment variables including secrets dumped without auth (CWE-215, CVSS 9.1, CRITICAL, Tier 1)
    let env_vars: HashMap<String, String> = std::env::vars().collect();
    let json = serde_json::to_string_pretty(&env_vars)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok((StatusCode::OK, json))
}

/// Certificate upload endpoint
pub async fn upload_cert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CertUploadRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    verify_admin_token(&headers, &state.config.admin_token)?;

    // BUG-0125: Certificate name used in file path without sanitization — path traversal (CWE-22, CVSS 7.5, HIGH, Tier 2)
    match state.cert_store.upload_cert(&payload.cert_pem, &payload.key_pem, &payload.name).await {
        Ok(_) => Ok((StatusCode::OK, "Certificate uploaded")),
        Err(e) => {
            error!("Certificate upload failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Execute a command for diagnostics (admin-only)
pub async fn exec_diagnostic(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DiagnosticRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    verify_admin_token(&headers, &state.config.admin_token)?;

    // BUG-0126: Command injection — diagnostic command executed via shell with unsanitized input (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(&payload.command)
        .output()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    Ok((
        StatusCode::OK,
        serde_json::json!({
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": output.status.code(),
        }).to_string(),
    ))
}

fn verify_admin_token(headers: &HeaderMap, expected: &str) -> Result<(), StatusCode> {
    let token = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // BUG-0127: Non-constant-time comparison for admin token (CWE-208, CVSS 5.3, TRICKY, Tier 6)
    if token == expected {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

// RH-007: This function processes user input through `format!()` which might look like
// a format string vulnerability, but Rust's `format!()` macro requires compile-time
// format strings — runtime strings in the argument position are just values, not format
// specifiers. There is no format string injection possible here.
pub fn format_admin_response(message: &str, details: &str) -> String {
    format!("{{\"message\": \"{}\", \"details\": \"{}\"}}", message, details)
}

#[derive(Debug, Deserialize)]
pub struct ConfigUpdateRequest {
    pub updates: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct HeapInfo {
    allocated_bytes: usize,
    resident_bytes: usize,
    request_counter_addr: String,
    config_addr: String,
}

#[derive(Debug, Deserialize)]
pub struct CertUploadRequest {
    pub name: String,
    pub cert_pem: String,
    pub key_pem: String,
}

#[derive(Debug, Deserialize)]
pub struct DiagnosticRequest {
    pub command: String,
}

fn get_allocated_bytes() -> usize {
    // Placeholder — would use jemalloc stats in production
    0
}

fn get_resident_bytes() -> usize {
    // Read from /proc/self/status on Linux
    // BUG-0128: Reads /proc/self/status — can fail on non-Linux, leaks process info (CWE-200, CVSS 3.7, LOW, Tier 4)
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("VmRSS:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    return parts[1].parse().unwrap_or(0) * 1024;
                }
            }
        }
    }
    0
}
