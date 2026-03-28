use actix_web::{web, HttpRequest, HttpResponse};
use uuid::Uuid;
use chrono::{Utc, NaiveDateTime, Duration};
use std::process::Command;

use crate::AppState;
use crate::auth::middleware;
use crate::models::{Transaction, TaxReport, TaxableEvent};
use crate::services::tax_calc;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/tax")
            .route("/report/{year}", web::get().to(generate_report))
            .route("/download/{filename}", web::get().to(download_report))
            .route("/estimate", web::get().to(tax_estimate))
            .route("/export-pdf", web::post().to(export_pdf))
            .route("/wash-sale-check", web::get().to(wash_sale_check))
            .route("/cost-basis/{asset}", web::get().to(cost_basis_detail))
    );
}

async fn generate_report(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<i32>,
) -> HttpResponse {
    let claims = match middleware::require_auth(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let year = path.into_inner();
    let user_id = Uuid::parse_str(&claims.sub).unwrap();

    // BUG-0065: Year parameter not validated — can query arbitrary date ranges (CWE-20, CVSS 3.7, BEST_PRACTICE, Tier 1)
    let start_date = format!("{}-01-01 00:00:00", year);
    let end_date = format!("{}-12-31 23:59:59", year);

    let txns: Vec<Transaction> = sqlx::query_as(
        "SELECT * FROM transactions WHERE user_id = $1 AND timestamp BETWEEN $2 AND $3 ORDER BY timestamp"
    )
        .bind(user_id)
        .bind(&start_date)
        .bind(&end_date)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    let report = tax_calc::compute_tax_report(user_id, year, &txns);

    // BUG-0066: Report saved to predictable path without user isolation — other users' reports accessible (CWE-732, CVSS 6.5, MEDIUM, Tier 2)
    let report_path = format!("{}/tax_report_{}_{}.json",
        state.config.tax_report_dir, user_id, year);

    // BUG-0067: Blocking file I/O in async context (CWE-400, CVSS 4.3, BEST_PRACTICE, Tier 2)
    let report_json = serde_json::to_string_pretty(&report).unwrap();
    std::fs::write(&report_path, &report_json).unwrap_or_default();

    HttpResponse::Ok().json(report)
}

// BUG-0068: Path traversal in download — filename from URL used directly (CWE-22, CVSS 7.5, HIGH, Tier 2)
async fn download_report(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let _claims = match middleware::require_auth(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let filename = path.into_inner();
    // No sanitization of filename — "../../../etc/passwd" works
    let file_path = format!("{}/{}", state.config.tax_report_dir, filename);

    match std::fs::read_to_string(&file_path) {
        Ok(content) => HttpResponse::Ok()
            .content_type("application/json")
            .body(content),
        Err(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "Report not found"})),
    }
}

async fn tax_estimate(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let claims = match middleware::require_auth(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let user_id = Uuid::parse_str(&claims.sub).unwrap();
    let current_year = Utc::now().year();
    let start_date = format!("{}-01-01 00:00:00", current_year);

    let txns: Vec<Transaction> = sqlx::query_as(
        "SELECT * FROM transactions WHERE user_id = $1 AND timestamp >= $2 ORDER BY timestamp"
    )
        .bind(user_id)
        .bind(&start_date)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    let report = tax_calc::compute_tax_report(user_id, current_year, &txns);

    // BUG-0069: Tax rates hardcoded and wrong — short term should vary by bracket (CWE-682, CVSS 5.3, MEDIUM, Tier 2)
    let estimated_tax = report.short_term_gains * 0.15 + report.long_term_gains * 0.10;

    HttpResponse::Ok().json(serde_json::json!({
        "year": current_year,
        "estimated_short_term_gains": report.short_term_gains,
        "estimated_long_term_gains": report.long_term_gains,
        "estimated_tax_liability": estimated_tax,
        "note": "Estimate only — not tax advice",
    }))
}

use chrono::Datelike;

// BUG-0070: Command injection — user-controlled parameters passed to shell command (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
#[derive(serde::Deserialize)]
struct ExportPdfRequest {
    report_file: String,
    output_name: String,
}

async fn export_pdf(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<ExportPdfRequest>,
) -> HttpResponse {
    let _claims = match middleware::require_auth(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    // User-controlled input passed directly to shell command
    let cmd = format!(
        "wkhtmltopdf {}/{} {}/{}.pdf",
        state.config.tax_report_dir, body.report_file,
        state.config.tax_report_dir, body.output_name,
    );

    let output = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output();

    match output {
        Ok(o) => {
            if o.status.success() {
                HttpResponse::Ok().json(serde_json::json!({"message": "PDF exported"}))
            } else {
                // BUG-0071: Shell command stderr returned to client (CWE-209, CVSS 3.7, LOW, Tier 1)
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "PDF export failed",
                    "stderr": String::from_utf8_lossy(&o.stderr).to_string(),
                }))
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Command execution failed: {}", e)
        })),
    }
}

// BUG-0072: Wash sale detection uses 30-day window but doesn't account for timezone/DST shifts (CWE-682, CVSS 4.3, TRICKY, Tier 3)
async fn wash_sale_check(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let claims = match middleware::require_auth(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let user_id = Uuid::parse_str(&claims.sub).unwrap();
    let txns: Vec<Transaction> = sqlx::query_as(
        "SELECT * FROM transactions WHERE user_id = $1 ORDER BY timestamp"
    )
        .bind(user_id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    let mut wash_sales: Vec<serde_json::Value> = Vec::new();

    for (i, sell) in txns.iter().enumerate() {
        if sell.tx_type != "sell" { continue; }
        let sell_price = sell.amount * sell.price_usd;

        for buy in &txns[i+1..] {
            if buy.tx_type != "buy" || buy.asset != sell.asset { continue; }

            // 30 days = 30 * 86400 seconds, but NaiveDateTime has no timezone awareness
            let diff = buy.timestamp.signed_duration_since(sell.timestamp);
            if diff.num_days() <= 30 && diff.num_days() >= 0 {
                let buy_price = buy.amount * buy.price_usd;
                if buy_price < sell_price {
                    wash_sales.push(serde_json::json!({
                        "sell_tx": sell.id,
                        "buy_tx": buy.id,
                        "asset": sell.asset,
                        "days_apart": diff.num_days(),
                    }));
                }
            }
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "wash_sales_detected": wash_sales.len(),
        "details": wash_sales,
    }))
}

async fn cost_basis_detail(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let claims = match middleware::require_auth(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let asset = path.into_inner();
    let user_id = Uuid::parse_str(&claims.sub).unwrap();

    // BUG-0073: SQL injection via asset parameter in format! (CWE-89, CVSS 9.0, CRITICAL, Tier 1)
    let query = format!(
        "SELECT * FROM transactions WHERE user_id = '{}' AND asset = '{}' ORDER BY timestamp",
        user_id, asset
    );

    let txns: Vec<Transaction> = sqlx::query_as(&query)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    let lots = tax_calc::compute_cost_basis_lots(&txns);

    HttpResponse::Ok().json(serde_json::json!({
        "asset": asset,
        "lots": lots,
        "total_quantity": txns.iter().filter(|t| t.tx_type == "buy").map(|t| t.amount).sum::<f64>(),
    }))
}
