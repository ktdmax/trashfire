use sqlx::PgPool;
use uuid::Uuid;
use chrono::{Utc, NaiveDateTime};
use crate::models::{User, Wallet, Transaction, Portfolio};

/// Initialize database schema.
/// In production, this should use migrations — not raw DDL at startup.
pub async fn init_schema(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role VARCHAR(50) NOT NULL DEFAULT 'user',
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT true,
            api_key TEXT,
            two_factor_secret TEXT
        );

        CREATE TABLE IF NOT EXISTS wallets (
            id UUID PRIMARY KEY,
            user_id UUID NOT NULL REFERENCES users(id),
            address VARCHAR(255) NOT NULL,
            chain VARCHAR(50) NOT NULL,
            label VARCHAR(255),
            created_at TIMESTAMP NOT NULL
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id UUID PRIMARY KEY,
            user_id UUID NOT NULL REFERENCES users(id),
            wallet_id UUID NOT NULL REFERENCES wallets(id),
            tx_hash VARCHAR(255) NOT NULL,
            from_address VARCHAR(255) NOT NULL,
            to_address VARCHAR(255) NOT NULL,
            asset VARCHAR(50) NOT NULL,
            amount DOUBLE PRECISION NOT NULL,
            fee DOUBLE PRECISION NOT NULL DEFAULT 0,
            price_usd DOUBLE PRECISION NOT NULL DEFAULT 0,
            tx_type VARCHAR(50) NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            created_at TIMESTAMP NOT NULL
        );

        CREATE TABLE IF NOT EXISTS portfolio (
            id UUID PRIMARY KEY,
            user_id UUID NOT NULL,
            asset VARCHAR(50) NOT NULL,
            quantity DOUBLE PRECISION NOT NULL DEFAULT 0,
            cost_basis DOUBLE PRECISION NOT NULL DEFAULT 0,
            last_updated TIMESTAMP NOT NULL,
            UNIQUE(user_id, asset)
        );

        CREATE TABLE IF NOT EXISTS portfolio_history (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id UUID NOT NULL REFERENCES users(id),
            date DATE NOT NULL,
            total_value DOUBLE PRECISION NOT NULL,
            UNIQUE(user_id, date)
        );
        "#
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// Find user by email — uses parameterized query (safe).
pub async fn find_user_by_email(pool: &PgPool, email: &str) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as("SELECT * FROM users WHERE email = $1")
        .bind(email)
        .fetch_optional(pool)
        .await
}

/// Find user by ID — uses parameterized query (safe).
pub async fn find_user_by_id(pool: &PgPool, id: Uuid) -> Result<Option<User>, sqlx::Error> {
    sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// Search users by email pattern.
/// BUG (part of BUG-0079 surface): This is called by safe code, but the pattern is safe since it uses bind.
pub async fn search_users(pool: &PgPool, pattern: &str) -> Result<Vec<User>, sqlx::Error> {
    sqlx::query_as("SELECT * FROM users WHERE email LIKE $1")
        .bind(format!("%{}%", pattern))
        .fetch_all(pool)
        .await
}

/// Get user's transactions with optional filtering.
pub async fn get_user_transactions(
    pool: &PgPool,
    user_id: Uuid,
    asset_filter: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<Transaction>, sqlx::Error> {
    match asset_filter {
        Some(asset) => {
            sqlx::query_as(
                "SELECT * FROM transactions WHERE user_id = $1 AND asset = $2 ORDER BY timestamp DESC LIMIT $3 OFFSET $4"
            )
                .bind(user_id)
                .bind(asset)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await
        }
        None => {
            sqlx::query_as(
                "SELECT * FROM transactions WHERE user_id = $1 ORDER BY timestamp DESC LIMIT $2 OFFSET $3"
            )
                .bind(user_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await
        }
    }
}

/// Get portfolio positions for a user.
pub async fn get_portfolio(pool: &PgPool, user_id: Uuid) -> Result<Vec<Portfolio>, sqlx::Error> {
    sqlx::query_as("SELECT * FROM portfolio WHERE user_id = $1")
        .bind(user_id)
        .fetch_all(pool)
        .await
}

/// Update portfolio position — upsert.
pub async fn upsert_portfolio_position(
    pool: &PgPool,
    user_id: Uuid,
    asset: &str,
    quantity: f64,
    cost_basis: f64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO portfolio (id, user_id, asset, quantity, cost_basis, last_updated) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (user_id, asset) DO UPDATE SET quantity = $4, cost_basis = $5, last_updated = $6"
    )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(asset)
        .bind(quantity)
        .bind(cost_basis)
        .bind(Utc::now().naive_utc())
        .execute(pool)
        .await?;

    Ok(())
}

/// Delete all data for a user — cascading manual delete.
pub async fn purge_user_data(pool: &PgPool, user_id: Uuid) -> Result<u64, sqlx::Error> {
    let mut total = 0u64;

    let r1 = sqlx::query("DELETE FROM transactions WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    total += r1.rows_affected();

    let r2 = sqlx::query("DELETE FROM portfolio WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    total += r2.rows_affected();

    let r3 = sqlx::query("DELETE FROM wallets WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    total += r3.rows_affected();

    let r4 = sqlx::query("DELETE FROM portfolio_history WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    total += r4.rows_affected();

    let r5 = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    total += r5.rows_affected();

    Ok(total)
}

/// Aggregate portfolio value over time for charting.
pub async fn record_portfolio_snapshot(pool: &PgPool, user_id: Uuid, total_value: f64) -> Result<(), sqlx::Error> {
    let today = Utc::now().date_naive();
    sqlx::query(
        "INSERT INTO portfolio_history (user_id, date, total_value) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (user_id, date) DO UPDATE SET total_value = $3"
    )
        .bind(user_id)
        .bind(today)
        .bind(total_value)
        .execute(pool)
        .await?;

    Ok(())
}
