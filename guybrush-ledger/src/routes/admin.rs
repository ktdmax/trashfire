use actix_web::{web, HttpRequest, HttpResponse};
use uuid::Uuid;
use chrono::Utc;
use std::process::Command;

use crate::AppState;
use crate::auth::middleware;
use crate::models::{User, AdminUserUpdate};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/admin")
            .route("/users", web::get().to(list_users))
            .route("/users/{id}", web::get().to(get_user))
            .route("/users/{id}", web::put().to(update_user))
            .route("/users/{id}", web::delete().to(delete_user))
            .route("/db/query", web::post().to(raw_query))
            .route("/system/exec", web::post().to(system_exec))
            .route("/backup", web::post().to(backup_database))
            .route("/metrics", web::get().to(metrics))
    );
}

async fn list_users(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let _claims = match middleware::require_admin(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    // BUG-0074: Returns all user data including password hashes (CWE-200, CVSS 7.5, HIGH, Tier 1)
    let users: Vec<User> = sqlx::query_as("SELECT * FROM users ORDER BY created_at DESC")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    HttpResponse::Ok().json(users)
}

async fn get_user(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let _claims = match middleware::require_admin(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let user_id = match Uuid::parse_str(&path.into_inner()) {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid ID"})),
    };

    let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    match user {
        Some(u) => HttpResponse::Ok().json(u),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"})),
    }
}

async fn update_user(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<AdminUserUpdate>,
) -> HttpResponse {
    let _claims = match middleware::require_admin(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let user_id = match Uuid::parse_str(&path.into_inner()) {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid ID"})),
    };

    // BUG-0075: No validation that role is a valid value — can set arbitrary role strings (CWE-20, CVSS 6.5, BEST_PRACTICE, Tier 2)
    if let Some(ref role) = body.role {
        // BUG-0076: SQL injection via role parameter (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
        let query = format!(
            "UPDATE users SET role = '{}', updated_at = '{}' WHERE id = '{}'",
            role, Utc::now().naive_utc(), user_id
        );
        let _ = sqlx::query(&query).execute(&state.db).await;
    }

    if let Some(is_active) = body.is_active {
        let _ = sqlx::query("UPDATE users SET is_active = $1, updated_at = $2 WHERE id = $3")
            .bind(is_active)
            .bind(Utc::now().naive_utc())
            .bind(user_id)
            .execute(&state.db)
            .await;
    }

    HttpResponse::Ok().json(serde_json::json!({"message": "User updated"}))
}

async fn delete_user(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let claims = match middleware::require_admin(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let user_id = match Uuid::parse_str(&path.into_inner()) {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid ID"})),
    };

    // BUG-0077: Admin can delete their own account — no self-deletion protection (CWE-20, CVSS 5.3, BEST_PRACTICE, Tier 2)
    // BUG-0078: Hard delete — no soft delete, no audit trail (CWE-778, CVSS 3.7, LOW, Tier 1)
    let _ = sqlx::query("DELETE FROM transactions WHERE user_id = $1").bind(user_id).execute(&state.db).await;
    let _ = sqlx::query("DELETE FROM portfolio WHERE user_id = $1").bind(user_id).execute(&state.db).await;
    let _ = sqlx::query("DELETE FROM wallets WHERE user_id = $1").bind(user_id).execute(&state.db).await;
    let _ = sqlx::query("DELETE FROM users WHERE id = $1").bind(user_id).execute(&state.db).await;

    HttpResponse::Ok().json(serde_json::json!({"message": "User and all data deleted"}))
}

#[derive(serde::Deserialize)]
struct RawQueryRequest {
    sql: String,
}

// BUG-0079: Raw SQL execution endpoint — arbitrary query execution (CWE-89, CVSS 10.0, CRITICAL, Tier 1)
async fn raw_query(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<RawQueryRequest>,
) -> HttpResponse {
    // BUG-0080: API key auth instead of JWT admin auth — weaker authentication (CWE-287, CVSS 8.1, HIGH, Tier 2)
    let api_key = req.headers().get("X-Admin-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !middleware::verify_api_key(api_key, &state.config.admin_api_key) {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid admin key"}));
    }

    log::warn!("Raw SQL query executed: {}", body.sql);

    // Executes arbitrary SQL — no restrictions, no read-only mode
    match sqlx::query(&body.sql).execute(&state.db).await {
        Ok(result) => HttpResponse::Ok().json(serde_json::json!({
            "rows_affected": result.rows_affected(),
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Query failed: {}", e)
        })),
    }
}

#[derive(serde::Deserialize)]
struct SystemExecRequest {
    command: String,
}

// BUG-0081: OS command execution endpoint — remote code execution (CWE-78, CVSS 10.0, CRITICAL, Tier 1)
async fn system_exec(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<SystemExecRequest>,
) -> HttpResponse {
    let api_key = req.headers().get("X-Admin-Key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !middleware::verify_api_key(api_key, &state.config.admin_api_key) {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid admin key"}));
    }

    // Direct OS command execution from user input
    let output = Command::new("sh")
        .arg("-c")
        .arg(&body.command)
        .output();

    match output {
        Ok(o) => HttpResponse::Ok().json(serde_json::json!({
            "stdout": String::from_utf8_lossy(&o.stdout),
            "stderr": String::from_utf8_lossy(&o.stderr),
            "exit_code": o.status.code(),
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Execution failed: {}", e)
        })),
    }
}

// BUG-0082: Backup uses shell command with injectable database URL (CWE-78, CVSS 9.0, CRITICAL, Tier 1)
async fn backup_database(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let _claims = match middleware::require_admin(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let backup_file = format!("{}/backup_{}.sql", state.config.tax_report_dir, Utc::now().timestamp());
    let cmd = format!("pg_dump {} > {}", state.config.database_url, backup_file);

    let output = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output();

    match output {
        Ok(o) if o.status.success() => {
            HttpResponse::Ok().json(serde_json::json!({
                "message": "Backup complete",
                // BUG-0083: Exposes backup file path and database URL in response (CWE-200, CVSS 5.3, MEDIUM, Tier 1)
                "backup_path": backup_file,
                "database": state.config.database_url,
            }))
        }
        _ => HttpResponse::InternalServerError().json(serde_json::json!({"error": "Backup failed"})),
    }
}

// BUG-0084: Metrics endpoint has no authentication — information disclosure (CWE-200, CVSS 5.3, MEDIUM, Tier 2)
async fn metrics(
    state: web::Data<AppState>,
) -> HttpResponse {
    let user_count: Option<(i64,)> = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    let tx_count: Option<(i64,)> = sqlx::query_as("SELECT COUNT(*) FROM transactions")
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    HttpResponse::Ok().json(serde_json::json!({
        "total_users": user_count.map(|c| c.0).unwrap_or(0),
        "total_transactions": tx_count.map(|c| c.0).unwrap_or(0),
        "database_url": state.config.database_url,
        "uptime_seconds": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    }))
}
