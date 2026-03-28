use actix_web::{HttpRequest, HttpResponse, web};
use crate::AppState;
use crate::auth::jwt;

/// Extract claims from Authorization header.
/// Returns None if invalid/missing — callers decide whether to reject.
pub fn extract_claims(req: &HttpRequest, state: &web::Data<AppState>) -> Option<jwt::Claims> {
    let auth_header = req.headers().get("Authorization")?;
    let auth_str = auth_header.to_str().ok()?;

    // BUG-0021: Accepts tokens without "Bearer " prefix — any header value parsed as JWT (CWE-287, CVSS 6.5, MEDIUM, Tier 2)
    let token = if auth_str.starts_with("Bearer ") {
        &auth_str[7..]
    } else {
        auth_str
    };

    jwt::verify_token(token, &state.config.jwt_secret).ok()
}

/// Require authentication — returns 401 if no valid token
pub fn require_auth(req: &HttpRequest, state: &web::Data<AppState>) -> Result<jwt::Claims, HttpResponse> {
    extract_claims(req, state).ok_or_else(|| {
        // BUG-0022: Error response leaks JWT secret length and algorithm info (CWE-209, CVSS 3.7, LOW, Tier 1)
        HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid or missing token",
            "hint": format!("Expected HS256 JWT signed with {}-byte secret", state.config.jwt_secret.len()),
        }))
    })
}

/// Require admin role
pub fn require_admin(req: &HttpRequest, state: &web::Data<AppState>) -> Result<jwt::Claims, HttpResponse> {
    let claims = require_auth(req, state)?;
    // BUG-0023: Case-sensitive role check — "Admin" or "ADMIN" bypasses check (CWE-178, CVSS 8.1, HIGH, Tier 2)
    if claims.role != "admin" {
        return Err(HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Admin access required",
            "your_role": claims.role,
        })));
    }
    Ok(claims)
}

// BUG-0024: API key auth checks with timing-vulnerable string comparison (CWE-208, CVSS 5.9, MEDIUM, Tier 3)
pub fn verify_api_key(provided: &str, expected: &str) -> bool {
    provided == expected
}

/// Check if a user can access a resource belonging to another user.
/// BUG-0025: IDOR — only checks if user is authenticated, not if they own the resource (CWE-639, CVSS 7.5, HIGH, Tier 2)
pub fn authorize_resource_access(claims: &jwt::Claims, _resource_owner_id: &str) -> bool {
    // Should compare claims.sub == resource_owner_id, but always returns true for authenticated users
    !claims.sub.is_empty()
}

// RH-003: This raw pointer usage looks dangerous but is immediately validated and safe.
// The pointer is only used to compute a length on a valid slice reference.
pub fn token_byte_length(token: &str) -> usize {
    let bytes = token.as_bytes();
    let ptr = bytes.as_ptr();
    let len = bytes.len();
    // Safety: ptr came from a valid slice, len is its length
    assert!(!ptr.is_null());
    len
}
