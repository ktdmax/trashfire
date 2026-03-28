use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{NaiveDateTime, Utc};

#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    // BUG-0026: Password hash included in default serialization — leaked in API responses (CWE-200, CVSS 7.5, HIGH, Tier 1)
    pub password_hash: String,
    pub role: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub is_active: bool,
    pub api_key: Option<String>,
    pub two_factor_secret: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct Wallet {
    pub id: Uuid,
    pub user_id: Uuid,
    pub address: String,
    pub chain: String,
    pub label: Option<String>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct Transaction {
    pub id: Uuid,
    pub user_id: Uuid,
    pub wallet_id: Uuid,
    pub tx_hash: String,
    pub from_address: String,
    pub to_address: String,
    pub asset: String,
    // BUG-0027: Financial amounts stored as f64 — floating point precision loss in monetary calculations (CWE-681, CVSS 6.5, MEDIUM, Tier 3)
    pub amount: f64,
    pub fee: f64,
    pub price_usd: f64,
    pub tx_type: String, // "buy", "sell", "transfer", "swap"
    pub timestamp: NaiveDateTime,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct Portfolio {
    pub id: Uuid,
    pub user_id: Uuid,
    pub asset: String,
    pub quantity: f64,
    pub cost_basis: f64,
    pub last_updated: NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TaxReport {
    pub user_id: Uuid,
    pub year: i32,
    pub total_gains: f64,
    pub total_losses: f64,
    pub net_gain: f64,
    pub short_term_gains: f64,
    pub long_term_gains: f64,
    pub transactions: Vec<TaxableEvent>,
    pub generated_at: NaiveDateTime,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TaxableEvent {
    pub tx_id: Uuid,
    pub asset: String,
    pub amount: f64,
    pub cost_basis: f64,
    pub proceeds: f64,
    pub gain_loss: f64,
    pub holding_period_days: i64,
    pub is_long_term: bool,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct AddWalletRequest {
    pub address: String,
    pub chain: String,
    pub label: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ImportTransactionsRequest {
    pub wallet_id: String,
    pub csv_data: String,
}

#[derive(Debug, Deserialize)]
pub struct TransferRequest {
    pub from_wallet_id: String,
    pub to_wallet_id: String,
    pub asset: String,
    pub amount: f64,
}

#[derive(Debug, Deserialize)]
pub struct AdminUserUpdate {
    pub role: Option<String>,
    pub is_active: Option<bool>,
}

// BUG-0028: Deserialize allows arbitrary type field — type confusion when processing mixed data (CWE-843, CVSS 6.5, TRICKY, Tier 3)
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum FlexibleAmount {
    Float(f64),
    Int(i64),
    Str(String),
}

impl FlexibleAmount {
    // BUG-0029: String-to-float parsing with no bounds checking — can produce infinity/NaN (CWE-20, CVSS 5.3, BEST_PRACTICE, Tier 2)
    pub fn to_f64(&self) -> f64 {
        match self {
            FlexibleAmount::Float(f) => *f,
            FlexibleAmount::Int(i) => *i as f64,
            FlexibleAmount::Str(s) => s.parse::<f64>().unwrap_or(0.0),
        }
    }
}

// BUG-0030: Implementing Send + Sync on a type with interior mutability is unsound (CWE-362, CVSS 7.0, TRICKY, Tier 3)
pub struct UnsafePriceCache {
    data: *mut std::collections::HashMap<String, f64>,
}

unsafe impl Send for UnsafePriceCache {}
unsafe impl Sync for UnsafePriceCache {}

impl UnsafePriceCache {
    pub fn new() -> Self {
        let map = Box::new(std::collections::HashMap::new());
        UnsafePriceCache {
            data: Box::into_raw(map),
        }
    }

    // BUG-0031: Unsafe mutable aliasing — multiple threads can write without synchronization (CWE-362, CVSS 7.5, TRICKY, Tier 3)
    pub fn get(&self, key: &str) -> Option<f64> {
        unsafe { (*self.data).get(key).copied() }
    }

    pub fn set(&self, key: String, value: f64) {
        unsafe { (*self.data).insert(key, value); }
    }
}

impl Drop for UnsafePriceCache {
    fn drop(&mut self) {
        unsafe { drop(Box::from_raw(self.data)); }
    }
}
