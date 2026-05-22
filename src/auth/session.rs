use std::net::IpAddr;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use cookie::{Cookie, SameSite, time::Duration as CookieDuration};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use sqlx::{PgPool, Row, types::ipnetwork::IpNetwork};
use uuid::Uuid;

use crate::{auth::rbac::Role, config::Config, error::AppError};

pub const SESSION_COOKIE_NAME: &str = "ins_session";

type HmacSha256 = Hmac<Sha256>;

/// Geladene Session samt aktuellem Benutzer aus der Datenbank.
#[derive(Debug, Clone)]
pub struct LoadedSession {
    pub session_id: String,
    pub csrf_token: String,
    pub expires_at: DateTime<Utc>,
    pub user_id: Uuid,
    pub email: String,
    pub full_name: String,
    pub role: Role,
    pub organization_unit_id: Option<Uuid>,
}

pub fn generate_random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn sign_session_id(session_id: &str, secret: &[u8]) -> Result<String, AppError> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|e| AppError::Internal(format!("Ungültiger Session-Key: {e}")))?;
    mac.update(session_id.as_bytes());
    let signature = mac.finalize().into_bytes();
    Ok(format!(
        "{session_id}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

pub fn verify_signed_cookie<'a>(cookie_value: &'a str, secret: &[u8]) -> Option<&'a str> {
    let (session_id, sig_b64) = cookie_value.split_once('.')?;
    if session_id.is_empty() || sig_b64.is_empty() {
        return None;
    }
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).ok()?;
    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(session_id.as_bytes());
    mac.verify_slice(&sig_bytes).ok()?;
    Some(session_id)
}

pub fn build_session_cookie(signed_value: String, config: &Config) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE_NAME, signed_value))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(config.cookie_secure)
        .max_age(CookieDuration::hours(config.session_ttl_hours))
        .build()
}

pub fn build_clear_session_cookie(config: &Config) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE_NAME, ""))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(config.cookie_secure)
        .max_age(CookieDuration::ZERO)
        .build()
}

pub async fn create_session(
    pool: &PgPool,
    user_id: Uuid,
    ip_address: Option<IpAddr>,
    user_agent: Option<&str>,
    ttl_hours: i64,
) -> Result<(String, String), AppError> {
    let session_id = generate_random_token();
    let csrf_token = generate_random_token();
    let expires_at = Utc::now() + Duration::hours(ttl_hours);
    let ip_net = ip_address.map(IpNetwork::from);

    sqlx::query(
        r#"
        INSERT INTO sessions (id, user_id, csrf_token, ip_address, user_agent, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(&session_id)
    .bind(user_id)
    .bind(&csrf_token)
    .bind(ip_net)
    .bind(user_agent)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok((session_id, csrf_token))
}

pub async fn load_and_refresh_session(
    pool: &PgPool,
    session_id: &str,
    ttl_hours: i64,
) -> Result<Option<LoadedSession>, AppError> {
    let row = sqlx::query(
        r#"
        SELECT
            s.id AS session_id,
            s.csrf_token,
            s.expires_at,
            u.id AS user_id,
            u.email,
            u.full_name,
            u.role,
            u.organization_unit_id
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.id = $1
          AND s.expires_at > NOW()
          AND u.is_active = TRUE
          AND (u.expires_at IS NULL OR u.expires_at > NOW())
        "#,
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    let role_raw: String = row.try_get("role")?;
    let role = role_raw
        .parse::<Role>()
        .map_err(|_| AppError::Internal(format!("Unbekannte Benutzerrolle: {role_raw}")))?;

    let expires_at: DateTime<Utc> = row.try_get("expires_at")?;
    let session_id_db: String = row.try_get("session_id")?;

    // Sliding Expiration: Verlängern, sobald weniger als 50 % der TTL verbleiben.
    let half_ttl = Duration::seconds((ttl_hours * 3600) / 2);
    let now = Utc::now();
    let final_expires_at = if expires_at - now < half_ttl {
        let extended = now + Duration::hours(ttl_hours);
        sqlx::query("UPDATE sessions SET expires_at = $1 WHERE id = $2")
            .bind(extended)
            .bind(&session_id_db)
            .execute(pool)
            .await?;
        extended
    } else {
        expires_at
    };

    Ok(Some(LoadedSession {
        session_id: session_id_db,
        csrf_token: row.try_get("csrf_token")?,
        expires_at: final_expires_at,
        user_id: row.try_get("user_id")?,
        email: row.try_get("email")?,
        full_name: row.try_get("full_name")?,
        role,
        organization_unit_id: row.try_get("organization_unit_id")?,
    }))
}

pub async fn delete_session(pool: &PgPool, session_id: &str) -> Result<(), AppError> {
    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(session_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_user_sessions(pool: &PgPool, user_id: Uuid) -> Result<(), AppError> {
    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_other_user_sessions(
    pool: &PgPool,
    user_id: Uuid,
    keep_session_id: &str,
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND id <> $2")
        .bind(user_id)
        .bind(keep_session_id)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_and_verifies_cookie_in_constant_time() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let sid = generate_random_token();
        assert_eq!(sid.len(), 43);

        let signed = sign_session_id(&sid, secret).unwrap();
        assert_eq!(verify_signed_cookie(&signed, secret), Some(sid.as_str()));

        let tampered = format!("{signed}x");
        assert_eq!(verify_signed_cookie(&tampered, secret), None);
        assert_eq!(
            verify_signed_cookie(&signed, b"wrong-secret-0123456789abcdef0123"),
            None
        );
    }
}
