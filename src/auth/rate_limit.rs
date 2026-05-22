use std::net::IpAddr;

use sqlx::{PgPool, types::ipnetwork::IpNetwork};

use crate::error::AppError;

pub const MAX_LOGIN_ATTEMPTS: i64 = 5;
pub const RATE_LIMIT_WINDOW_MINUTES: i64 = 15;

pub fn normalize_email(email: &str) -> String {
    email.trim().to_ascii_lowercase()
}

pub async fn check_rate_limit(
    pool: &PgPool,
    email_normalized: &str,
    client_ip: IpAddr,
) -> Result<(), AppError> {
    let ip_net = IpNetwork::from(client_ip);
    let count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM login_attempts
        WHERE email_normalized = $1
          AND client_ip = $2
          AND attempted_at > NOW() - ($3::BIGINT * INTERVAL '1 minute')
        "#,
    )
    .bind(email_normalized)
    .bind(ip_net)
    .bind(RATE_LIMIT_WINDOW_MINUTES)
    .fetch_one(pool)
    .await?;

    if count >= MAX_LOGIN_ATTEMPTS {
        return Err(AppError::TooManyRequests(
            "Zu viele fehlgeschlagene Anmeldeversuche. Bitte warten Sie 15 Minuten.".to_string(),
        ));
    }

    Ok(())
}

pub async fn record_failed_attempt(
    pool: &PgPool,
    email_normalized: &str,
    client_ip: IpAddr,
) -> Result<(), AppError> {
    let ip_net = IpNetwork::from(client_ip);
    sqlx::query(
        r#"
        INSERT INTO login_attempts (email_normalized, client_ip)
        VALUES ($1, $2)
        "#,
    )
    .bind(email_normalized)
    .bind(ip_net)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn clear_attempts(
    pool: &PgPool,
    email_normalized: &str,
    client_ip: IpAddr,
) -> Result<(), AppError> {
    let ip_net = IpNetwork::from(client_ip);
    sqlx::query(
        r#"
        DELETE FROM login_attempts
        WHERE email_normalized = $1 AND client_ip = $2
        "#,
    )
    .bind(email_normalized)
    .bind(ip_net)
    .execute(pool)
    .await?;

    Ok(())
}
