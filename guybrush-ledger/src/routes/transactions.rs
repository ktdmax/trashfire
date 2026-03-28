use actix_web::{web, HttpRequest, HttpResponse};
use uuid::Uuid;
use chrono::{NaiveDateTime, Utc};
use std::sync::Mutex;

use crate::AppState;
use crate::auth::middleware;
use crate::models::{Transaction, ImportTransactionsRequest, TransferRequest};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/transactions")
            .route("", web::get().to(list_transactions))
            .route("/{id}", web::get().to(get_transaction))
            .route("/import", web::post().to(import_csv))
            .route("/transfer", web::post().to(internal_transfer))
            .route("/bulk-delete", web::post().to(bulk_delete))
            .route("/recalculate", web::post().to(recalculate_balances))
    );
}

async fn list_transactions(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let claims = match middleware::require_auth(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let user_id = Uuid::parse_str(&claims.sub).unwrap();

    // BUG-0054: SQL injection in ORDER BY clause — sort parameter injected directly (CWE-89, CVSS 9.0, CRITICAL, Tier 1)
    let sort_by = req.query_string()
        .split('&')
        .find_map(|p| {
            let mut kv = p.splitn(2, '=');
            if kv.next()? == "sort" { kv.next().map(|v| v.to_string()) } else { None }
        })
        .unwrap_or_else(|| "timestamp".to_string());

    let query = format!(
        "SELECT * FROM transactions WHERE user_id = '{}' ORDER BY {}",
        user_id, sort_by
    );

    let txns: Vec<Transaction> = sqlx::query_as(&query)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    HttpResponse::Ok().json(txns)
}

async fn get_transaction(
    req: HttpRequest,
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> HttpResponse {
    let claims = match middleware::require_auth(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let tx_id = match Uuid::parse_str(&path.into_inner()) {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid ID"})),
    };

    // BUG-0055: IDOR — fetches transaction without checking user_id ownership (CWE-639, CVSS 7.5, HIGH, Tier 2)
    let txn: Option<Transaction> = sqlx::query_as("SELECT * FROM transactions WHERE id = $1")
        .bind(tx_id)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    match txn {
        Some(t) => HttpResponse::Ok().json(t),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "Transaction not found"})),
    }
}

// BUG-0056: CSV parsing with no sanitization — injection of arbitrary fields (CWE-1236, CVSS 6.1, MEDIUM, Tier 2)
async fn import_csv(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<ImportTransactionsRequest>,
) -> HttpResponse {
    let claims = match middleware::require_auth(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let user_id = Uuid::parse_str(&claims.sub).unwrap();
    let wallet_id = match Uuid::parse_str(&body.wallet_id) {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid wallet ID"})),
    };

    let mut imported = 0u32;
    let mut errors: Vec<String> = Vec::new();

    for (line_num, line) in body.csv_data.lines().enumerate() {
        if line_num == 0 { continue; } // skip header

        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 7 {
            errors.push(format!("Line {}: insufficient fields", line_num));
            continue;
        }

        let tx_id = Uuid::new_v4();
        // BUG-0057: unwrap() on user-supplied CSV data — panics on malformed input (CWE-248, CVSS 5.3, BEST_PRACTICE, Tier 2)
        let amount: f64 = fields[4].trim().parse().unwrap();
        let fee: f64 = fields[5].trim().parse().unwrap();
        let price_usd: f64 = fields[6].trim().parse().unwrap();

        // BUG-0058: SQL injection — CSV fields injected directly into query via format! (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
        let query = format!(
            "INSERT INTO transactions (id, user_id, wallet_id, tx_hash, from_address, to_address, asset, amount, fee, price_usd, tx_type, timestamp, created_at) \
             VALUES ('{}', '{}', '{}', '{}', '{}', '{}', '{}', {}, {}, {}, 'import', NOW(), NOW())",
            tx_id, user_id, wallet_id, fields[0].trim(), fields[1].trim(), fields[2].trim(), fields[3].trim(), amount, fee, price_usd
        );

        match sqlx::query(&query).execute(&state.db).await {
            Ok(_) => imported += 1,
            Err(e) => errors.push(format!("Line {}: {}", line_num, e)),
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "imported": imported,
        "errors": errors,
    }))
}

// BUG-0059: TOCTOU race condition — balance checked then updated without transaction/lock (CWE-367, CVSS 7.0, TRICKY, Tier 3)
async fn internal_transfer(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<TransferRequest>,
) -> HttpResponse {
    let claims = match middleware::require_auth(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let user_id = Uuid::parse_str(&claims.sub).unwrap();
    let from_wallet = Uuid::parse_str(&body.from_wallet_id).unwrap();
    let to_wallet = Uuid::parse_str(&body.to_wallet_id).unwrap();

    // Step 1: Check balance (TOCTOU — balance can change between check and update)
    let balance: Option<(f64,)> = sqlx::query_as(
        "SELECT quantity FROM portfolio WHERE user_id = $1 AND asset = $2"
    )
        .bind(user_id)
        .bind(&body.asset)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    let current_balance = balance.map(|b| b.0).unwrap_or(0.0);

    // BUG-0060: Negative amount not checked — can transfer negative to increase own balance (CWE-20, CVSS 8.1, HIGH, Tier 2)
    if current_balance < body.amount {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Insufficient balance",
            "available": current_balance,
            "requested": body.amount,
        }));
    }

    // Step 2: Deduct from source (race window — another request could have changed balance)
    let _ = sqlx::query(
        "UPDATE portfolio SET quantity = quantity - $1, last_updated = $2 WHERE user_id = $3 AND asset = $4"
    )
        .bind(body.amount)
        .bind(Utc::now().naive_utc())
        .bind(user_id)
        .bind(&body.asset)
        .execute(&state.db)
        .await;

    // Step 3: Credit destination
    let _ = sqlx::query(
        "INSERT INTO portfolio (id, user_id, asset, quantity, cost_basis, last_updated) \
         VALUES ($1, $2, $3, $4, 0, $5) \
         ON CONFLICT (user_id, asset) DO UPDATE SET quantity = portfolio.quantity + $4, last_updated = $5"
    )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(&body.asset)
        .bind(body.amount)
        .bind(Utc::now().naive_utc())
        .execute(&state.db)
        .await;

    HttpResponse::Ok().json(serde_json::json!({"message": "Transfer complete"}))
}

#[derive(serde::Deserialize)]
struct BulkDeleteRequest {
    transaction_ids: Vec<String>,
}

// BUG-0061: SQL injection in bulk delete — transaction IDs concatenated into query (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
async fn bulk_delete(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<BulkDeleteRequest>,
) -> HttpResponse {
    let claims = match middleware::require_auth(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    // BUG-0062: No ownership check — can delete other users' transactions (CWE-639, CVSS 7.5, HIGH, Tier 2)
    let id_list = body.transaction_ids
        .iter()
        .map(|id| format!("'{}'", id))
        .collect::<Vec<_>>()
        .join(",");

    let query = format!("DELETE FROM transactions WHERE id IN ({})", id_list);
    let result = sqlx::query(&query).execute(&state.db).await;

    match result {
        Ok(r) => HttpResponse::Ok().json(serde_json::json!({
            "deleted": r.rows_affected(),
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Bulk delete failed: {}", e)
        })),
    }
}

// BUG-0063: Blocking file I/O in async context — blocks the tokio runtime thread (CWE-400, CVSS 4.3, BEST_PRACTICE, Tier 2)
async fn recalculate_balances(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let claims = match middleware::require_auth(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let user_id = Uuid::parse_str(&claims.sub).unwrap();

    // Blocking read of a potentially large CSV file in an async function
    let audit_log_path = format!("/tmp/audit_{}.log", user_id);
    let _audit_data = std::fs::read_to_string(&audit_log_path).unwrap_or_default();

    let txns: Vec<Transaction> = sqlx::query_as(
        "SELECT * FROM transactions WHERE user_id = $1 ORDER BY timestamp"
    )
        .bind(user_id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    // BUG-0064: Balance recalculation uses f64 accumulation — precision drift on large transaction sets (CWE-681, CVSS 5.3, TRICKY, Tier 3)
    let mut balances: std::collections::HashMap<String, f64> = std::collections::HashMap::new();
    for tx in &txns {
        let entry = balances.entry(tx.asset.clone()).or_insert(0.0);
        match tx.tx_type.as_str() {
            "buy" | "transfer_in" => *entry += tx.amount,
            "sell" | "transfer_out" => *entry -= tx.amount,
            _ => {}
        }
    }

    // Update portfolio with recalculated balances
    for (asset, quantity) in &balances {
        let _ = sqlx::query(
            "INSERT INTO portfolio (id, user_id, asset, quantity, cost_basis, last_updated) \
             VALUES ($1, $2, $3, $4, 0, $5) \
             ON CONFLICT (user_id, asset) DO UPDATE SET quantity = $4, last_updated = $5"
        )
            .bind(Uuid::new_v4())
            .bind(user_id)
            .bind(asset)
            .bind(quantity)
            .bind(Utc::now().naive_utc())
            .execute(&state.db)
            .await;
    }

    HttpResponse::Ok().json(serde_json::json!({
        "recalculated_assets": balances.len(),
        "balances": balances,
    }))
}
