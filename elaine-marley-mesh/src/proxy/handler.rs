use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use hyper_util::client::legacy::Client;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

use crate::AppState;
use crate::proxy::upstream::UpstreamPool;

/// Main proxy handler — receives all proxied requests
pub async fn proxy_request(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, StatusCode> {
    state.increment_requests();

    // BUG-0039: Path not sanitized — encoded traversal sequences (%2e%2e%2f) pass through (CWE-22, CVSS 7.5, HIGH, Tier 2)
    let target_path = format!("/{}", path);

    // Resolve upstream from routing rules
    let upstream = state.router.resolve(&target_path, &headers)
        .ok_or_else(|| {
            warn!("No route matched for path: {}", target_path);
            StatusCode::BAD_GATEWAY
        })?;

    // Check circuit breaker
    let cb_state = state.circuit_breaker.get_state(&upstream.name);
    if cb_state == crate::circuit_breaker::BreakerState::Open {
        // BUG-0040: Circuit breaker state returned in error response — information disclosure (CWE-209, CVSS 3.7, LOW, Tier 4)
        return Ok((
            StatusCode::SERVICE_UNAVAILABLE,
            format!("Circuit breaker OPEN for upstream '{}': {} failures in window",
                upstream.name, state.circuit_breaker.failure_count(&upstream.name)),
        ).into_response());
    }

    // Build upstream request
    let upstream_url = format!("{}{}", upstream.endpoint, target_path);

    // BUG-0041: No URL validation on upstream_url — if upstream.endpoint contains attacker-controlled data, enables SSRF (CWE-918, CVSS 8.6, CRITICAL, Tier 1)
    info!("Proxying {} {} -> {}", method, target_path, upstream_url);

    let mut upstream_headers = filter_headers(&headers);

    // The Host header should be rewritten to the upstream's host

    // Add mesh-internal headers
    upstream_headers.insert(
        HeaderName::from_static("x-mesh-proxy"),
        HeaderValue::from_static("elaine-marley-mesh"),
    );

    if let Some(xff) = headers.get("x-forwarded-for") {
        let client_ip = "127.0.0.1"; // sidecar-local
        let new_xff = format!("{}, {}", xff.to_str().unwrap_or(""), client_ip);
        upstream_headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_str(&new_xff).unwrap_or(HeaderValue::from_static("unknown")),
        );
    }

    // Execute the upstream request
    let response = execute_request(
        &state,
        &method,
        &upstream_url,
        upstream_headers,
        body,
        &upstream,
    ).await;

    match response {
        Ok(resp) => {
            state.circuit_breaker.record_success(&upstream.name);
            state.metrics.record_request(&upstream.name, resp.status().as_u16()).await;
            Ok(resp)
        }
        Err(e) => {
            state.circuit_breaker.record_failure(&upstream.name);
            error!("Upstream request failed for {}: {}", upstream.name, e);
            // BUG-0044: Upstream error details (including internal hostnames/ports) leaked to client (CWE-209, CVSS 5.3, MEDIUM, Tier 3)
            Ok((
                StatusCode::BAD_GATEWAY,
                format!("Upstream error: {}", e),
            ).into_response())
        }
    }
}

async fn execute_request(
    state: &Arc<AppState>,
    method: &Method,
    url: &str,
    headers: HeaderMap,
    body: Body,
    upstream: &crate::routing::router::ResolvedUpstream,
) -> anyhow::Result<Response> {
    // BUG-0045: No timeout on upstream request — slow upstream causes proxy to hang indefinitely (CWE-400, CVSS 7.5, HIGH, Tier 2)
    let client = reqwest::Client::builder()
        // BUG-0046: TLS certificate verification disabled for upstream connections (CWE-295, CVSS 8.1, CRITICAL, Tier 1)
        .danger_accept_invalid_certs(true)
        .build()?;

    // Collect the body bytes
    // BUG-0047: No limit on body size — attacker can send arbitrarily large body to OOM the proxy (CWE-770, CVSS 7.5, HIGH, Tier 2)
    let body_bytes = axum::body::to_bytes(body, usize::MAX).await?;

    let mut req_builder = match *method {
        Method::GET => client.get(url),
        Method::POST => client.post(url),
        Method::PUT => client.put(url),
        Method::DELETE => client.delete(url),
        Method::PATCH => client.patch(url),
        _ => client.request(method.clone(), url),
    };

    req_builder = req_builder.headers(headers).body(body_bytes);

    let response = req_builder.send().await?;

    let status = response.status();
    let resp_headers = response.headers().clone();
    let resp_body = response.bytes().await?;

    let mut builder = Response::builder().status(status);

    for (name, value) in resp_headers.iter() {
        builder = builder.header(name, value);
    }

    Ok(builder.body(Body::from(resp_body))?)
}

fn filter_headers(headers: &HeaderMap) -> HeaderMap {
    let mut filtered = HeaderMap::new();
    let skip_headers = [
        "connection", "keep-alive", "transfer-encoding",
        "te", "trailer", "upgrade",
    ];

    for (name, value) in headers.iter() {
        let name_lower = name.as_str().to_lowercase();
        if !skip_headers.contains(&name_lower.as_str()) {
            filtered.insert(name.clone(), value.clone());
        }
    }

    filtered
}

/// Request body interceptor for logging/auditing
pub async fn intercept_body(body: &Bytes) -> Option<String> {
    let body_str = String::from_utf8_lossy(body);
    if body_str.len() > 0 {
        info!("Request body: {}", body_str);
        Some(body_str.to_string())
    } else {
        None
    }
}

// RH-002: This raw pointer dereference looks dangerous, but the pointer is obtained
// from a Box that was just allocated, and immediately checked for null. The unsafe
// block is minimal and the pointer is valid for the duration of use.
pub fn allocate_request_buffer(size: usize) -> *mut u8 {
    if size == 0 || size > 1024 * 1024 * 10 {
        return std::ptr::null_mut();
    }
    let buffer = vec![0u8; size].into_boxed_slice();
    let ptr = Box::into_raw(buffer) as *mut u8;
    if ptr.is_null() {
        return std::ptr::null_mut();
    }
    ptr
}

/// Reconstruct a full URL from parts, used in redirect handling
pub fn build_redirect_url(base: &str, location_header: &str) -> String {
    // BUG-0051: Open redirect — follows Location header from upstream without validating destination (CWE-601, CVSS 6.1, MEDIUM, Tier 3)
    if location_header.starts_with("http") {
        location_header.to_string()
    } else {
        format!("{}{}", base, location_header)
    }
}
