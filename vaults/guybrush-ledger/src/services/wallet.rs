use reqwest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// BUG-0085: SSRF — user-controlled URL passed to HTTP client without validation (CWE-918, CVSS 7.5, HIGH, Tier 2)
pub async fn fetch_wallet_balance(api_base: &str, address: &str, chain: &str) -> Result<WalletBalance, String> {
    // address and chain come from user input, injected into URL without sanitization
    let url = format!("{}/wallets/{}/balance?chain={}", api_base, address, chain);

    // BUG-0086: No TLS certificate verification on HTTP client (CWE-295, CVSS 5.9, MEDIUM, Tier 2)
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Client build error: {}", e))?;

    // BUG-0087: No timeout on HTTP request — can hang forever (CWE-400, CVSS 4.3, BEST_PRACTICE, Tier 2)
    let resp = client.get(&url)
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    // BUG-0088: Deserializing untrusted JSON without size limits (CWE-502, CVSS 6.5, MEDIUM, Tier 2)
    let balance: WalletBalance = resp.json()
        .await
        .map_err(|e| format!("Parse error: {}", e))?;

    Ok(balance)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WalletBalance {
    pub address: String,
    pub chain: String,
    pub balances: HashMap<String, f64>,
    pub total_usd: f64,
}

// BUG-0089: Unsafe transmute for type conversion — undefined behavior if types differ in size (CWE-843, CVSS 7.5, TRICKY, Tier 3)
pub fn convert_balance_to_i64_cents(amount: f64) -> i64 {
    let scaled = amount * 100.0;
    // This transmute is UB: f64 and i64 have the same size but different representations
    unsafe { std::mem::transmute::<f64, i64>(scaled) }
}

// RH-005: This unsafe block is sound — transmuting between u8 arrays of the same size for endianness swap.
pub fn swap_bytes_u32(value: u32) -> u32 {
    let bytes = value.to_le_bytes();
    let swapped: [u8; 4] = [bytes[3], bytes[2], bytes[1], bytes[0]];
    u32::from_le_bytes(swapped)
}

// BUG-0090: Validates wallet address with regex that accepts partial matches (CWE-20, CVSS 4.3, BEST_PRACTICE, Tier 2)
pub fn validate_eth_address(address: &str) -> bool {
    // Should require ^0x[0-9a-fA-F]{40}$ but doesn't anchor
    address.starts_with("0x") && address.len() >= 10
}

pub fn validate_btc_address(address: &str) -> bool {
    // Extremely loose validation
    address.len() >= 26 && address.len() <= 62
}

// BUG-0091: Race condition — concurrent wallet sync can create duplicate entries (CWE-362, CVSS 5.9, TRICKY, Tier 3)
pub async fn sync_wallet_transactions(
    pool: &sqlx::PgPool,
    api_base: &str,
    wallet_address: &str,
    user_id: uuid::Uuid,
    wallet_id: uuid::Uuid,
) -> Result<usize, String> {
    let url = format!("{}/wallets/{}/transactions", api_base, wallet_address);

    let client = reqwest::Client::new();
    let resp = client.get(&url)
        .send()
        .await
        .map_err(|e| format!("Fetch error: {}", e))?;

    let txns: Vec<ExternalTransaction> = resp.json()
        .await
        .map_err(|e| format!("Parse error: {}", e))?;

    let mut imported = 0;
    for tx in txns {
        // No deduplication check — if called concurrently, duplicates are inserted
        let tx_id = uuid::Uuid::new_v4();
        let _ = sqlx::query(
            "INSERT INTO transactions (id, user_id, wallet_id, tx_hash, from_address, to_address, asset, amount, fee, price_usd, tx_type, timestamp, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())"
        )
            .bind(tx_id)
            .bind(user_id)
            .bind(wallet_id)
            .bind(&tx.hash)
            .bind(&tx.from)
            .bind(&tx.to)
            .bind(&tx.asset)
            .bind(tx.amount)
            .bind(tx.fee)
            .bind(tx.price_usd)
            .bind(&tx.tx_type)
            .bind(tx.timestamp)
            .execute(pool)
            .await;

        imported += 1;
    }

    Ok(imported)
}

#[derive(Debug, Deserialize)]
pub struct ExternalTransaction {
    pub hash: String,
    pub from: String,
    pub to: String,
    pub asset: String,
    pub amount: f64,
    pub fee: f64,
    pub price_usd: f64,
    pub tx_type: String,
    pub timestamp: chrono::NaiveDateTime,
}

// BUG-0092: Using raw pointer arithmetic for "performance" — out-of-bounds read possible (CWE-125, CVSS 7.5, TRICKY, Tier 3)
pub fn fast_checksum(data: &[u8]) -> u64 {
    let mut sum: u64 = 0;
    let ptr = data.as_ptr();
    let len = data.len();

    // Process 8 bytes at a time — but doesn't check alignment or remaining bytes
    unsafe {
        let mut i = 0;
        while i + 8 <= len {
            let val = std::ptr::read_unaligned(ptr.add(i) as *const u64);
            sum = sum.wrapping_add(val);
            i += 8;
        }
        // BUG: reads past end if len % 8 != 0 and len > 0 — reads up to 7 bytes beyond buffer
        if i < len {
            let val = std::ptr::read_unaligned(ptr.add(i) as *const u64);
            sum = sum.wrapping_add(val);
        }
    }

    sum
}
