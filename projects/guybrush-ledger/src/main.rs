use actix_web::{web, App, HttpServer, HttpResponse, middleware::Logger};
use actix_cors::Cors;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;

mod config;
mod routes;
mod models;
mod services;
mod db;
mod auth;

pub struct AppState {
    pub db: sqlx::PgPool,
    pub config: config::Config,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let cfg = config::Config::from_env();

    // BUG-0003: No connection pool size limit — can exhaust DB connections (CWE-400, CVSS 5.3, MEDIUM, Tier 2)
    let pool = PgPoolOptions::new()
        .connect(&cfg.database_url)
        .await
        .expect("Failed to create pool");

    let state = web::Data::new(AppState {
        db: pool,
        config: cfg.clone(),
    });

    log::info!("Starting server on {}:{}", cfg.host, cfg.port);
    // BUG-0004: Debug logging of config which may contain secrets (CWE-532, CVSS 3.3, LOW, Tier 1)
    log::debug!("Config: database_url={}, jwt_secret={}", cfg.database_url, cfg.jwt_secret);

    HttpServer::new(move || {
        // BUG-0005: CORS allows all origins with credentials — cookie/token theft (CWE-942, CVSS 6.5, MEDIUM, Tier 2)
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .supports_credentials()
            .max_age(3600);

        App::new()
            .app_data(state.clone())
            .wrap(Logger::default())
            .wrap(cors)
            // BUG-0006: No rate limiting on any endpoints (CWE-799, CVSS 3.7, LOW, Tier 1)
            .route("/health", web::get().to(health_check))
            .configure(routes::auth::configure)
            .configure(routes::portfolio::configure)
            .configure(routes::transactions::configure)
            .configure(routes::tax::configure)
            .configure(routes::admin::configure)
            // BUG-0007: Debug endpoint left in production — exposes internal state (CWE-489, CVSS 3.5, LOW, Tier 1)
            .route("/debug/state", web::get().to(debug_state))
    })
    // BUG-0008: Binding to 0.0.0.0 exposes service on all interfaces (CWE-668, CVSS 3.7, LOW, Tier 1)
    .bind("0.0.0.0:8080")?
    .run()
    .await
}

async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({"status": "ok"}))
}

// BUG-0007 continued: debug endpoint returns full config including secrets
async fn debug_state(state: web::Data<AppState>) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "database_url": state.config.database_url,
        "jwt_secret": state.config.jwt_secret,
        "admin_key": state.config.admin_api_key,
    }))
}
