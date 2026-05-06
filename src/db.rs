use std::{net::IpAddr, time::Duration};

use sqlx::{PgPool, Postgres, Transaction, postgres::PgPoolOptions};
use uuid::Uuid;

use crate::error::AppError;

/// Erstellt den PostgreSQL-Connection-Pool für die Anwendungsrolle.
pub async fn create_pool(database_url: &str) -> Result<PgPool, AppError> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await?;
    Ok(pool)
}

/// Führt eingebettete SQLx-Migrationen wiederholbar aus.
pub async fn run_migrations(database_url: &str) -> Result<(), AppError> {
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(10))
        .connect(database_url)
        .await?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|e| AppError::Internal(format!("Migration fehlgeschlagen: {e}")))?;

    Ok(())
}

/// Startet eine revisionssichere Transaktion und setzt Actor-Kontext transaktionslokal (`is_local = true`).
pub async fn begin_audited_tx(
    pool: &PgPool,
    actor_id: Option<Uuid>,
    actor_ip: Option<IpAddr>,
) -> Result<Transaction<'_, Postgres>, AppError> {
    let mut tx = pool.begin().await?;

    let actor_id_str = actor_id.map(|id| id.to_string()).unwrap_or_default();
    let actor_ip_str = actor_ip.map(|ip| ip.to_string()).unwrap_or_default();

    sqlx::query("SELECT set_config('app.current_actor_id', $1, true)")
        .bind(actor_id_str)
        .execute(&mut *tx)
        .await?;

    sqlx::query("SELECT set_config('app.current_actor_ip', $1, true)")
        .bind(actor_ip_str)
        .execute(&mut *tx)
        .await?;

    Ok(tx)
}
