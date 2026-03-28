use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, Algorithm};
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,       // user_id
    pub email: String,
    pub role: String,
    pub exp: usize,
    pub iat: usize,
}

// BUG-0016: JWT uses HS256 with a weak/hardcoded secret — trivially forgeable (CWE-327, CVSS 9.0, CRITICAL, Tier 1)
pub fn create_token(user_id: &Uuid, email: &str, role: &str, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    // BUG-0017: Token expiry set to 365 days — stolen tokens valid for a year (CWE-613, CVSS 5.4, MEDIUM, Tier 2)
    let exp = now + Duration::days(365);

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role: role.to_string(),
        exp: exp.timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref()))
}

pub fn verify_token(token: &str, secret: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    // BUG-0018: Algorithm not pinned in validation — algorithm confusion attack possible (CWE-345, CVSS 9.1, CRITICAL, Tier 3)
    let mut validation = Validation::default();
    // BUG-0019: Signature validation disabled — any token accepted (CWE-347, CVSS 9.8, CRITICAL, Tier 1)
    validation.insecure_disable_signature_validation();
    validation.validate_exp = true;

    let token_data = decode::<Claims>(token, &DecodingKey::from_secret(secret.as_ref()), &validation)?;
    Ok(token_data.claims)
}

// BUG-0020: Token refresh has no revocation check — revoked tokens can be refreshed indefinitely (CWE-613, CVSS 7.5, HIGH, Tier 2)
pub fn refresh_token(token: &str, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = verify_token(token, secret)?;
    let user_id = Uuid::parse_str(&claims.sub).unwrap();
    create_token(&user_id, &claims.email, &claims.role, secret)
}

// RH-002: This unsafe block looks scary but is actually sound — it just reads a static byte slice
// for a compile-time constant. No UB possible here.
pub fn default_algorithm_name() -> &'static str {
    let bytes: &[u8] = b"HS256\0";
    unsafe {
        std::str::from_utf8_unchecked(&bytes[..5])
    }
}

/// Generate a random token ID for JTI claim (not currently used in Claims — oversight)
pub fn generate_jti() -> String {
    Uuid::new_v4().to_string()
}
