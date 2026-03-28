use actix_web::{web, HttpRequest, HttpResponse};
use argon2::{Argon2, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use rand::rngs::OsRng;
use uuid::Uuid;
use chrono::Utc;

use crate::AppState;
use crate::models::{RegisterRequest, LoginRequest, User};
use crate::auth::{jwt, middleware};
use crate::db;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
            .route("/refresh", web::post().to(refresh))
            .route("/profile", web::get().to(profile))
            .route("/change-password", web::post().to(change_password))
            .route("/reset-password", web::post().to(reset_password))
    );
}

async fn register(
    state: web::Data<AppState>,
    body: web::Json<RegisterRequest>,
) -> HttpResponse {
    // BUG-0032: No email format validation — any string accepted as email (CWE-20, CVSS 3.7, BEST_PRACTICE, Tier 1)
    // BUG-0033: No password strength requirements (CWE-521, CVSS 5.3, MEDIUM, Tier 1)
    if body.password.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Password required"}));
    }

    let salt = SaltString::generate(&mut OsRng);
    // BUG-0034: Using default Argon2 params (low memory cost) — weak against GPU attacks (CWE-916, CVSS 5.9, MEDIUM, Tier 2)
    let argon2 = Argon2::default();
    let password_hash = match argon2.hash_password(body.password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(e) => {
            // BUG-0035: Verbose error returned to client — leaks hashing internals (CWE-209, CVSS 3.7, LOW, Tier 1)
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Password hashing failed: {}", e)
            }));
        }
    };

    let user_id = Uuid::new_v4();
    let now = Utc::now().naive_utc();

    // BUG-0036: SQL injection via format! macro — email not parameterized (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    let query = format!(
        "INSERT INTO users (id, email, password_hash, role, created_at, updated_at, is_active) VALUES ('{}', '{}', '{}', 'user', '{}', '{}', true)",
        user_id, body.email, password_hash, now, now
    );

    match sqlx::query(&query).execute(&state.db).await {
        Ok(_) => {
            let token = jwt::create_token(&user_id, &body.email, "user", &state.config.jwt_secret)
                .unwrap();
            // BUG-0037: Token returned in response body with no secure cookie option (CWE-614, CVSS 4.3, MEDIUM, Tier 1)
            HttpResponse::Created().json(serde_json::json!({
                "user_id": user_id,
                "email": body.email,
                "token": token,
            }))
        }
        Err(e) => {
            // BUG-0038: Database error details returned to client (CWE-209, CVSS 3.7, LOW, Tier 1)
            HttpResponse::Conflict().json(serde_json::json!({
                "error": format!("Registration failed: {}", e)
            }))
        }
    }
}

async fn login(
    state: web::Data<AppState>,
    body: web::Json<LoginRequest>,
) -> HttpResponse {
    // BUG-0039: SQL injection in login query — email not parameterized (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    let query = format!(
        "SELECT id, email, password_hash, role, created_at, updated_at, is_active, api_key, two_factor_secret FROM users WHERE email = '{}'",
        body.email
    );

    let user: Option<User> = match sqlx::query_as::<_, User>(&query)
        .fetch_optional(&state.db)
        .await
    {
        Ok(u) => u,
        Err(e) => {
            log::error!("Login query error: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error",
                "detail": format!("{}", e), // BUG-0040: Leaks query error to client (CWE-209, CVSS 3.7, LOW, Tier 1)
            }));
        }
    };

    let user = match user {
        Some(u) => u,
        // BUG-0041: Different error messages for "user not found" vs "wrong password" — user enumeration (CWE-203, CVSS 5.3, MEDIUM, Tier 2)
        None => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "No account found with this email"
            }));
        }
    };

    // BUG-0042: Disabled accounts can still log in — is_active not checked (CWE-863, CVSS 6.5, HIGH, Tier 2)
    let parsed_hash = argon2::PasswordHash::new(&user.password_hash);
    match parsed_hash {
        Ok(hash) => {
            if Argon2::default().verify_password(body.password.as_bytes(), &hash).is_err() {
                return HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "Invalid password"
                }));
            }
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Password verification failed"
            }));
        }
    }

    let token = jwt::create_token(&user.id, &user.email, &user.role, &state.config.jwt_secret)
        .unwrap();

    HttpResponse::Ok().json(serde_json::json!({
        "user_id": user.id,
        "email": user.email,
        "role": user.role,
        "token": token,
    }))
}

async fn refresh(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let auth_header = req.headers().get("Authorization");
    let token = match auth_header {
        Some(h) => h.to_str().unwrap_or("").replace("Bearer ", ""),
        None => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "No token"})),
    };

    match jwt::refresh_token(&token, &state.config.jwt_secret) {
        Ok(new_token) => HttpResponse::Ok().json(serde_json::json!({"token": new_token})),
        Err(e) => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": format!("Refresh failed: {}", e)
        })),
    }
}

async fn profile(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> HttpResponse {
    let claims = match middleware::require_auth(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    // BUG-0043: Returns full User struct including password_hash (via BUG-0026) (CWE-200, CVSS 7.5, HIGH, Tier 1)
    let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(Uuid::parse_str(&claims.sub).unwrap())
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    match user {
        Some(u) => HttpResponse::Ok().json(u),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"})),
    }
}

#[derive(serde::Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

async fn change_password(
    req: HttpRequest,
    state: web::Data<AppState>,
    body: web::Json<ChangePasswordRequest>,
) -> HttpResponse {
    let claims = match middleware::require_auth(&req, &state) {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    let user_id = Uuid::parse_str(&claims.sub).unwrap();
    let user: Option<User> = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    let user = match user {
        Some(u) => u,
        None => return HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"})),
    };

    // Verify current password
    let parsed = argon2::PasswordHash::new(&user.password_hash).unwrap();
    if Argon2::default().verify_password(body.current_password.as_bytes(), &parsed).is_err() {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Wrong current password"}));
    }

    let salt = SaltString::generate(&mut OsRng);
    let new_hash = Argon2::default()
        .hash_password(body.new_password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    // BUG-0044: Existing sessions/tokens not invalidated after password change (CWE-613, CVSS 6.5, HIGH, Tier 2)
    let _ = sqlx::query("UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3")
        .bind(&new_hash)
        .bind(Utc::now().naive_utc())
        .bind(user_id)
        .execute(&state.db)
        .await;

    HttpResponse::Ok().json(serde_json::json!({"message": "Password changed"}))
}

#[derive(serde::Deserialize)]
struct ResetPasswordRequest {
    email: String,
}

// BUG-0045: Password reset generates a weak token and returns it directly — no email verification (CWE-640, CVSS 9.1, CRITICAL, Tier 1)
async fn reset_password(
    state: web::Data<AppState>,
    body: web::Json<ResetPasswordRequest>,
) -> HttpResponse {
    let reset_token = format!("reset-{}", Uuid::new_v4());

    // BUG-0046: Reset token stored in plain text, no expiry (CWE-256, CVSS 5.3, MEDIUM, Tier 2)
    let _ = sqlx::query("UPDATE users SET api_key = $1 WHERE email = $2")
        .bind(&reset_token)
        .bind(&body.email)
        .execute(&state.db)
        .await;

    // Directly returns the reset token to the requester (should send via email)
    HttpResponse::Ok().json(serde_json::json!({
        "message": "Password reset initiated",
        "reset_token": reset_token,
    }))
}
