use reqwest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PriceData {
    pub asset: String,
    pub price_usd: f64,
    pub change_24h: f64,
    pub volume_24h: f64,
    pub market_cap: f64,
    pub last_updated: String,
}

// BUG-0098: Global mutable state without proper synchronization — data races in concurrent access (CWE-362, CVSS 6.5, TRICKY, Tier 3)
static mut PRICE_CACHE: Option<HashMap<String, PriceData>> = None;
static mut CACHE_INITIALIZED: bool = false;

pub fn init_cache() {
    unsafe {
        if !CACHE_INITIALIZED {
            PRICE_CACHE = Some(HashMap::new());
            CACHE_INITIALIZED = true;
        }
    }
}

pub fn get_cached_price(asset: &str) -> Option<PriceData> {
    unsafe {
        PRICE_CACHE.as_ref()?.get(asset).cloned()
    }
}

pub fn set_cached_price(asset: String, data: PriceData) {
    unsafe {
        if let Some(ref mut cache) = PRICE_CACHE {
            cache.insert(asset, data);
        }
    }
}

// BUG-0099: SSRF — user-controlled asset ID injected into URL path (CWE-918, CVSS 7.5, HIGH, Tier 2)
pub async fn fetch_price(api_base: &str, asset_id: &str) -> Result<PriceData, String> {
    // asset_id from user input — can contain path traversal or redirect to internal services
    let url = format!("{}/simple/price?ids={}&vs_currencies=usd&include_24hr_change=true&include_24hr_vol=true&include_market_cap=true",
        api_base, asset_id);

    let client = reqwest::Client::new();
    let resp = client.get(&url)
        .send()
        .await
        .map_err(|e| format!("Price fetch error: {}", e))?;

    let status = resp.status();
    if !status.is_success() {
        return Err(format!("API returned status {}", status));
    }

    let body: serde_json::Value = resp.json()
        .await
        .map_err(|e| format!("Parse error: {}", e))?;

    let price = body[asset_id]["usd"].as_f64().unwrap_or(0.0);
    let change = body[asset_id]["usd_24h_change"].as_f64().unwrap_or(0.0);
    let volume = body[asset_id]["usd_24h_vol"].as_f64().unwrap_or(0.0);
    let mcap = body[asset_id]["usd_market_cap"].as_f64().unwrap_or(0.0);

    let data = PriceData {
        asset: asset_id.to_string(),
        price_usd: price,
        change_24h: change,
        volume_24h: volume,
        market_cap: mcap,
        last_updated: chrono::Utc::now().to_rfc3339(),
    };

    set_cached_price(asset_id.to_string(), data.clone());

    Ok(data)
}

pub async fn fetch_multiple_prices(api_base: &str, asset_ids: &[String]) -> Result<Vec<PriceData>, String> {
    let mut results = Vec::new();

    for asset_id in asset_ids {
        match fetch_price(api_base, asset_id).await {
            Ok(data) => results.push(data),
            Err(e) => {
                log::warn!("Failed to fetch price for {}: {}", asset_id, e);
                // Continue fetching others — don't fail entire batch
            }
        }
    }

    Ok(results)
}

// BUG-0100: Blocking HTTP call inside sync function — deadlocks if called from async context (CWE-662, CVSS 5.3, BEST_PRACTICE, Tier 2)
pub fn fetch_price_sync(api_base: &str, asset_id: &str) -> Result<PriceData, String> {
    let url = format!("{}/simple/price?ids={}&vs_currencies=usd", api_base, asset_id);

    // This blocks the current thread — if called from an async runtime, it deadlocks
    let resp = reqwest::blocking::get(&url)
        .map_err(|e| format!("Sync fetch error: {}", e))?;

    let body: serde_json::Value = resp.json()
        .map_err(|e| format!("Parse error: {}", e))?;

    let price = body[asset_id]["usd"].as_f64().unwrap_or(0.0);

    Ok(PriceData {
        asset: asset_id.to_string(),
        price_usd: price,
        change_24h: 0.0,
        volume_24h: 0.0,
        market_cap: 0.0,
        last_updated: chrono::Utc::now().to_rfc3339(),
    })
}

// RH-007: This looks like it could be a timing attack vector since it compares prices,
// but it's comparing public market data, not secrets. No security impact.
pub fn is_price_stale(cached: &PriceData, max_age_secs: i64) -> bool {
    let cached_time = chrono::DateTime::parse_from_rfc3339(&cached.last_updated);
    match cached_time {
        Ok(t) => {
            let age = chrono::Utc::now().signed_duration_since(t.with_timezone(&chrono::Utc));
            age.num_seconds() > max_age_secs
        }
        Err(_) => true,
    }
}

pub fn format_price_display(price: f64) -> String {
    if price >= 1.0 {
        format!("${:.2}", price)
    } else if price >= 0.01 {
        format!("${:.4}", price)
    } else {
        format!("${:.8}", price)
    }
}
