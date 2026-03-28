use actix_web::{web, HttpRequest, HttpResponse};
use uuid::Uuid;
use chrono::Utc;
use std::collections::HashMap;

use crate::AppState;
use crate::auth::middleware;
use crate::models::{Portfolio, AddWalletRequest, Wallet};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/portfolio")
            .route("", web::get().to(get_portfolio))
            .route("/wallets", web::get().to(list_wallets))
            .route("/wallets", web::post().to(add_wallet))
            .route("/wallets/{id}", web::delete().to(delete_wallet))
            .route("/summary", web::get().to(portfolio_summary))
            .route("/export", web::get().to(export_portfolio))
            .route("/value-history", web::get().to(value_history))
    );
}

async fn get_portfolio(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let claims = match middleware::require_auth(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let user_id = Uuid::parse_str(&claims.sub).unwrap();
    // BUG-0047: SQL injection via format! with user_id from JWT claims (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    let query = format!(
        "SELECT * FROM portfolio WHERE user_id = '{}'",
        user_id
    );
    let positions: Vec<Portfolio> = sqlx::query_as(&query)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    HttpResponse::Ok().json(positions)
}

async fn list_wallets(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let claims = match middleware::require_auth(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let user_id = Uuid::parse_str(&claims.sub).unwrap();
    let wallets: Vec<Wallet> = sqlx::query_as("SELECT * FROM wallets WHERE user_id = $1")
        .bind(user_id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    HttpResponse::Ok().json(wallets)
}

async fn add_wallet(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<AddWalletRequest>,
) -> HttpResponse {
    let claims = match middleware::require_auth(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    // BUG-0048: No wallet address format validation — any string accepted (CWE-20, CVSS 4.3, BEST_PRACTICE, Tier 1)
    let user_id = Uuid::parse_str(&claims.sub).unwrap();
    let wallet_id = Uuid::new_v4();
    let now = Utc::now().naive_utc();

    // BUG-0049: SQL injection in wallet insert — address from user input not parameterized (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    let query = format!(
        "INSERT INTO wallets (id, user_id, address, chain, label, created_at) VALUES ('{}', '{}', '{}', '{}', '{}', '{}')",
        wallet_id, user_id, body.address, body.chain, body.label.as_deref().unwrap_or(""), now
    );

    match sqlx::query(&query).execute(&state.db).await {
        Ok(_) => HttpResponse::Created().json(serde_json::json!({
            "wallet_id": wallet_id,
            "address": body.address,
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to add wallet: {}", e)
        })),
    }
}

async fn delete_wallet(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let claims = match middleware::require_auth(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let wallet_id_str = path.into_inner();
    // BUG-0050: IDOR — no ownership check, any authenticated user can delete any wallet (CWE-639, CVSS 7.5, HIGH, Tier 2)
    let wallet_id = match Uuid::parse_str(&wallet_id_str) {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid wallet ID"})),
    };

    // Deletes without checking user_id ownership
    let _ = sqlx::query("DELETE FROM wallets WHERE id = $1")
        .bind(wallet_id)
        .execute(&state.db)
        .await;

    HttpResponse::Ok().json(serde_json::json!({"message": "Wallet deleted"}))
}

async fn portfolio_summary(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let claims = match middleware::require_auth(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let user_id = Uuid::parse_str(&claims.sub).unwrap();
    let positions: Vec<Portfolio> = sqlx::query_as("SELECT * FROM portfolio WHERE user_id = $1")
        .bind(user_id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    // BUG-0051: Integer overflow in release mode — large portfolios can wrap around (CWE-190, CVSS 7.5, TRICKY, Tier 3)
    let mut total_value: f64 = 0.0;
    let mut total_cost: f64 = 0.0;
    let mut asset_count: u32 = 0;

    for pos in &positions {
        total_value += pos.quantity * pos.cost_basis; // naive valuation
        total_cost += pos.cost_basis;
        asset_count += 1; // can overflow with crafted data in release mode (BUG-0002)
    }

    // BUG-0052: Floating-point comparison for financial equality (CWE-681, CVSS 4.3, BEST_PRACTICE, Tier 2)
    let pnl = total_value - total_cost;
    let pnl_percent = if total_cost == 0.0 { 0.0 } else { (pnl / total_cost) * 100.0 };

    HttpResponse::Ok().json(serde_json::json!({
        "total_value": total_value,
        "total_cost_basis": total_cost,
        "pnl": pnl,
        "pnl_percent": pnl_percent,
        "asset_count": asset_count,
        "positions": positions,
    }))
}

// BUG-0053: Path traversal in export filename — user controls output path (CWE-22, CVSS 7.5, HIGH, Tier 2)
async fn export_portfolio(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let claims = match middleware::require_auth(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let format = req.query_string()
        .split('&')
        .find_map(|p| {
            let mut kv = p.splitn(2, '=');
            if kv.next()? == "filename" { kv.next().map(|v| v.to_string()) } else { None }
        })
        .unwrap_or_else(|| "portfolio.csv".to_string());

    // User-controlled filename used directly in path construction
    let export_path = std::path::Path::new(&state.config.tax_report_dir).join(&format);

    let user_id = Uuid::parse_str(&claims.sub).unwrap();
    let positions: Vec<Portfolio> = sqlx::query_as("SELECT * FROM portfolio WHERE user_id = $1")
        .bind(user_id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    let mut csv = String::from("asset,quantity,cost_basis\n");
    for pos in &positions {
        csv.push_str(&format!("{},{},{}\n", pos.asset, pos.quantity, pos.cost_basis));
    }

    // Write to user-controlled path
    match std::fs::write(&export_path, &csv) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Export complete",
            "path": export_path.to_string_lossy(),
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Export failed: {}", e)
        })),
    }
}

// RH-004: This unwrap() is on a Uuid that was already validated by parse_str above — it's safe.
async fn value_history(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let claims = match middleware::require_auth(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let user_id_str = &claims.sub;
    let _validated = Uuid::parse_str(user_id_str);
    if _validated.is_err() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid user ID"}));
    }
    let user_id = _validated.unwrap(); // RH-004: safe — error case handled above

    let history: Vec<(String, f64)> = sqlx::query_as(
        "SELECT date::text, total_value FROM portfolio_history WHERE user_id = $1 ORDER BY date"
    )
        .bind(user_id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    HttpResponse::Ok().json(history)
}
