use std::{collections::BTreeSet, net::IpAddr};

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;
use sqlx::{Executor, PgPool, Postgres, Row, types::ipnetwork::IpNetwork};
use uuid::Uuid;

use crate::{
    auth::rbac::{ClientIp, RequireAuditViewer},
    error::AppError,
    state::AppState,
    web::{ShellContext, render_page, render_template},
};

#[derive(Debug, Clone)]
pub struct ChainVerificationResult {
    pub total_entries: i64,
    pub first_broken_id: Option<i64>,
    pub last_hash: Option<String>,
}

impl ChainVerificationResult {
    pub fn is_valid(&self) -> bool {
        self.first_broken_id.is_none()
    }

    pub fn status_label(&self) -> &'static str {
        if self.is_valid() {
            "VALID"
        } else {
            "COMPROMISED"
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditLogEntry {
    pub id: i64,
    pub occurred_at: DateTime<Utc>,
    pub actor_user_id: Option<Uuid>,
    pub actor_label: String,
    pub actor_ip: Option<String>,
    pub action: String,
    pub entity_type: String,
    pub entity_id: String,
    pub summary: String,
    pub row_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct AuditFilter {
    pub entity_type: Option<String>,
    pub action: Option<String>,
    pub actor: Option<String>,
    pub limit: Option<i64>,
}

pub struct AuditService;

impl AuditService {
    #[allow(clippy::too_many_arguments)]
    pub async fn log_event<'e, E>(
        executor: E,
        actor_user_id: Option<Uuid>,
        actor_ip: Option<IpAddr>,
        action: &str,
        entity_type: &str,
        entity_id: &str,
        summary: &str,
        old_values: Option<Value>,
        new_values: Option<Value>,
    ) -> Result<(), AppError>
    where
        E: Executor<'e, Database = Postgres>,
    {
        let ip_net = actor_ip.map(IpNetwork::from);
        sqlx::query(
            r#"
            INSERT INTO audit_logs (
                actor_user_id,
                actor_ip,
                action,
                entity_type,
                entity_id,
                summary,
                old_values,
                new_values
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(actor_user_id)
        .bind(ip_net)
        .bind(action)
        .bind(entity_type)
        .bind(entity_id)
        .bind(summary)
        .bind(old_values)
        .bind(new_values)
        .execute(executor)
        .await?;

        Ok(())
    }

    pub async fn log_login_success(
        pool: &PgPool,
        user_id: Uuid,
        ip: IpAddr,
        email: &str,
    ) -> Result<(), AppError> {
        Self::log_event(
            pool,
            Some(user_id),
            Some(ip),
            "auth.login_success",
            "users",
            &user_id.to_string(),
            &format!("Erfolgreiche Anmeldung: {email}"),
            None,
            None,
        )
        .await
    }

    pub async fn log_login_failed(
        pool: &PgPool,
        ip: IpAddr,
        email_normalized: &str,
    ) -> Result<(), AppError> {
        Self::log_event(
            pool,
            None,
            Some(ip),
            "auth.login_failed",
            "auth",
            email_normalized,
            &format!("Fehlgeschlagener Anmeldeversuch für {email_normalized}"),
            None,
            None,
        )
        .await
    }

    pub async fn log_login_locked(
        pool: &PgPool,
        ip: IpAddr,
        email_normalized: &str,
    ) -> Result<(), AppError> {
        Self::log_event(
            pool,
            None,
            Some(ip),
            "auth.login_locked",
            "auth",
            email_normalized,
            &format!("Anmeldung wegen Rate-Limit gesperrt: {email_normalized}"),
            None,
            None,
        )
        .await
    }

    pub async fn log_logout(pool: &PgPool, user_id: Uuid, ip: IpAddr) -> Result<(), AppError> {
        Self::log_event(
            pool,
            Some(user_id),
            Some(ip),
            "auth.logout",
            "users",
            &user_id.to_string(),
            "Benutzer hat sich abgemeldet",
            None,
            None,
        )
        .await
    }

    pub async fn log_password_changed(
        pool: &PgPool,
        user_id: Uuid,
        ip: IpAddr,
    ) -> Result<(), AppError> {
        Self::log_event(
            pool,
            Some(user_id),
            Some(ip),
            "auth.password_changed",
            "users",
            &user_id.to_string(),
            "Eigenes Passwort geändert",
            None,
            None,
        )
        .await
    }

    pub async fn log_password_reset(
        pool: &PgPool,
        admin_id: Uuid,
        target_user_id: Uuid,
        ip: IpAddr,
    ) -> Result<(), AppError> {
        Self::log_event(
            pool,
            Some(admin_id),
            Some(ip),
            "auth.password_reset",
            "users",
            &target_user_id.to_string(),
            "Administrator hat Einmal-Passwort gesetzt",
            None,
            None,
        )
        .await
    }

    pub async fn log_oidc_login(
        pool: &PgPool,
        user_id: Uuid,
        ip: IpAddr,
        email: &str,
    ) -> Result<(), AppError> {
        Self::log_event(
            pool,
            Some(user_id),
            Some(ip),
            "auth.oidc_login",
            "users",
            &user_id.to_string(),
            &format!("OIDC-Anmeldung erfolgreich: {email}"),
            None,
            None,
        )
        .await
    }
}

pub async fn verify_hash_chain(pool: &PgPool) -> Result<ChainVerificationResult, AppError> {
    let row = sqlx::query(
        r#"
        WITH checked AS (
            SELECT
                id,
                prev_hash,
                row_hash,
                COALESCE(LAG(row_hash) OVER (ORDER BY id), repeat('0', 64)) AS expected_prev_hash,
                encode(
                    digest(
                        concat_ws('|',
                            prev_hash,
                            COALESCE(actor_user_id::text, 'SYSTEM'),
                            COALESCE(actor_ip::text, 'NO_IP'),
                            action,
                            entity_type,
                            entity_id,
                            summary,
                            COALESCE(old_values::text, ''),
                            COALESCE(new_values::text, ''),
                            to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
                        ),
                        'sha256'
                    ),
                    'hex'
                ) AS expected_row_hash
            FROM audit_logs
        )
        SELECT
            COUNT(*)::BIGINT AS total_entries,
            MIN(id) FILTER (
                WHERE prev_hash IS DISTINCT FROM expected_prev_hash
                   OR row_hash  IS DISTINCT FROM expected_row_hash
            ) AS first_broken_id,
            (SELECT row_hash FROM audit_logs ORDER BY id DESC LIMIT 1) AS last_hash
        FROM checked
        "#,
    )
    .fetch_one(pool)
    .await?;

    Ok(ChainVerificationResult {
        total_entries: row.try_get("total_entries")?,
        first_broken_id: row.try_get("first_broken_id")?,
        last_hash: row.try_get("last_hash")?,
    })
}

pub async fn list_audit_logs(
    pool: &PgPool,
    entity_type: Option<&str>,
    action: Option<&str>,
    actor: Option<&str>,
    limit: i64,
) -> Result<Vec<AuditLogEntry>, AppError> {
    let clamped_limit = limit.clamp(1, 200);
    let entity_filter = entity_type.map(str::trim).filter(|s| !s.is_empty());
    let action_filter = action.map(str::trim).filter(|s| !s.is_empty());
    let actor_filter = actor.map(str::trim).filter(|s| !s.is_empty());

    let rows = sqlx::query(
        r#"
        SELECT
            al.id,
            al.occurred_at,
            al.actor_user_id,
            COALESCE(u.full_name || ' (' || u.email || ')', 'System') AS actor_label,
            al.actor_ip::text AS actor_ip_text,
            al.action,
            al.entity_type,
            al.entity_id,
            al.summary,
            al.row_hash
        FROM audit_logs al
        LEFT JOIN users u ON u.id = al.actor_user_id
        WHERE ($1::text IS NULL OR al.entity_type = $1)
          AND ($2::text IS NULL OR al.action = $2)
          AND ($3::text IS NULL OR COALESCE(u.full_name || ' (' || u.email || ')', 'System') ILIKE '%' || $3 || '%')
        ORDER BY al.id DESC
        LIMIT $4
        "#,
    )
    .bind(entity_filter)
    .bind(action_filter)
    .bind(actor_filter)
    .bind(clamped_limit)
    .fetch_all(pool)
    .await?;

    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        entries.push(AuditLogEntry {
            id: row.try_get("id")?,
            occurred_at: row.try_get("occurred_at")?,
            actor_user_id: row.try_get("actor_user_id")?,
            actor_label: row.try_get("actor_label")?,
            actor_ip: row.try_get("actor_ip_text")?,
            action: row.try_get("action")?,
            entity_type: row.try_get("entity_type")?,
            entity_id: row.try_get("entity_id")?,
            summary: row.try_get("summary")?,
            row_hash: row.try_get("row_hash")?,
        });
    }
    Ok(entries)
}

struct AuditLogRowView {
    id: i64,
    occurred_at_str: String,
    action: String,
    entity_type: String,
    summary: String,
    actor_label: String,
    actor_ip_display: String,
    short_hash: String,
}

#[derive(Template)]
#[template(path = "audit_logs.html")]
struct AuditLogsTemplate {
    entries: Vec<AuditLogRowView>,
    filter_entity_type: String,
    filter_action: String,
    filter_actor: String,
}

struct AuditDiffField {
    field: String,
    before: String,
    after: String,
}

#[derive(Template)]
#[template(path = "audit_log_drawer.html")]
struct AuditLogDrawerTemplate {
    id: i64,
    occurred_at_str: String,
    actor_label: String,
    actor_ip_display: String,
    action: String,
    entity_type: String,
    entity_id: String,
    summary: String,
    prev_hash: String,
    row_hash: String,
    diff_fields: Vec<AuditDiffField>,
}

pub async fn list_audit_logs_handler(
    State(state): State<AppState>,
    RequireAuditViewer(user): RequireAuditViewer,
    headers: HeaderMap,
    Query(filter): Query<AuditFilter>,
) -> Result<impl IntoResponse, AppError> {
    let limit = filter.limit.unwrap_or(50);
    let raw_entries = list_audit_logs(
        &state.pool,
        filter.entity_type.as_deref(),
        filter.action.as_deref(),
        filter.actor.as_deref(),
        limit,
    )
    .await?;

    let entries = raw_entries
        .into_iter()
        .map(|e| AuditLogRowView {
            id: e.id,
            occurred_at_str: e.occurred_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            action: e.action,
            entity_type: e.entity_type,
            summary: e.summary,
            actor_label: e.actor_label,
            actor_ip_display: e.actor_ip.unwrap_or_else(|| "–".to_string()),
            short_hash: e.row_hash.chars().take(12).collect(),
        })
        .collect();

    let shell = ShellContext::from_user(&user, "Audit-Log", "Nachweis & System", "audit_logs");
    render_page(
        &headers,
        shell,
        &AuditLogsTemplate {
            entries,
            filter_entity_type: filter.entity_type.unwrap_or_default(),
            filter_action: filter.action.unwrap_or_default(),
            filter_actor: filter.actor.unwrap_or_default(),
        },
    )
}

pub async fn audit_log_detail_handler(
    State(state): State<AppState>,
    RequireAuditViewer(_user): RequireAuditViewer,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, AppError> {
    let row = sqlx::query(
        r#"
        SELECT
            al.id,
            al.occurred_at,
            COALESCE(u.full_name || ' (' || u.email || ')', 'System') AS actor_label,
            al.actor_ip::text AS actor_ip_text,
            al.action,
            al.entity_type,
            al.entity_id,
            al.summary,
            al.old_values,
            al.new_values,
            al.prev_hash,
            al.row_hash
        FROM audit_logs al
        LEFT JOIN users u ON u.id = al.actor_user_id
        WHERE al.id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Audit-Log-Eintrag nicht gefunden".to_string()))?;

    let occurred_at: DateTime<Utc> = row.try_get("occurred_at")?;
    let actor_ip: Option<String> = row.try_get("actor_ip_text")?;
    let old_values: Option<Value> = row.try_get("old_values")?;
    let new_values: Option<Value> = row.try_get("new_values")?;

    let tmpl = AuditLogDrawerTemplate {
        id: row.try_get("id")?,
        occurred_at_str: occurred_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        actor_label: row.try_get("actor_label")?,
        actor_ip_display: actor_ip.unwrap_or_else(|| "–".to_string()),
        action: row.try_get("action")?,
        entity_type: row.try_get("entity_type")?,
        entity_id: row.try_get("entity_id")?,
        summary: row.try_get("summary")?,
        prev_hash: row.try_get("prev_hash")?,
        row_hash: row.try_get("row_hash")?,
        diff_fields: build_diff_fields(old_values.as_ref(), new_values.as_ref()),
    };

    render_template(&tmpl)
}

fn build_diff_fields(
    old_values: Option<&Value>,
    new_values: Option<&Value>,
) -> Vec<AuditDiffField> {
    match (old_values, new_values) {
        (None, None) => Vec::new(),
        (Some(Value::Object(old_map)), Some(Value::Object(new_map))) => {
            let mut keys = BTreeSet::new();
            keys.extend(old_map.keys().cloned());
            keys.extend(new_map.keys().cloned());
            keys.into_iter()
                .map(|key| AuditDiffField {
                    before: old_map
                        .get(&key)
                        .map(format_json_value)
                        .unwrap_or_else(|| "–".to_string()),
                    after: new_map
                        .get(&key)
                        .map(format_json_value)
                        .unwrap_or_else(|| "–".to_string()),
                    field: key,
                })
                .collect()
        }
        (Some(Value::Object(old_map)), None) => {
            let mut keys: Vec<_> = old_map.keys().cloned().collect();
            keys.sort();
            keys.into_iter()
                .map(|key| AuditDiffField {
                    before: old_map
                        .get(&key)
                        .map(format_json_value)
                        .unwrap_or_else(|| "–".to_string()),
                    after: "–".to_string(),
                    field: key,
                })
                .collect()
        }
        (None, Some(Value::Object(new_map))) => {
            let mut keys: Vec<_> = new_map.keys().cloned().collect();
            keys.sort();
            keys.into_iter()
                .map(|key| AuditDiffField {
                    before: "–".to_string(),
                    after: new_map
                        .get(&key)
                        .map(format_json_value)
                        .unwrap_or_else(|| "–".to_string()),
                    field: key,
                })
                .collect()
        }
        (old_opt, new_opt) => vec![AuditDiffField {
            field: "Wert".to_string(),
            before: old_opt
                .map(format_json_value)
                .unwrap_or_else(|| "–".to_string()),
            after: new_opt
                .map(format_json_value)
                .unwrap_or_else(|| "–".to_string()),
        }],
    }
}

fn format_json_value(value: &Value) -> String {
    match value {
        Value::Null => "–".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => {
            if s.is_empty() {
                "(leer)".to_string()
            } else {
                s.clone()
            }
        }
        Value::Array(_) | Value::Object(_) => serde_json::to_string(value).unwrap_or_default(),
    }
}

pub async fn verify_audit_logs_handler(
    State(state): State<AppState>,
    RequireAuditViewer(user): RequireAuditViewer,
    ClientIp(ip): ClientIp,
) -> Result<impl IntoResponse, AppError> {
    let result = verify_hash_chain(&state.pool).await?;

    let details = serde_json::json!({
        "status": result.status_label(),
        "total_entries": result.total_entries,
        "first_broken_id": result.first_broken_id,
    });
    AuditService::log_event(
        &state.pool,
        Some(user.id),
        Some(ip),
        "audit_logs.verified",
        "audit_logs",
        "chain",
        &format!(
            "Hash-Chain-Verifizierung: {} ({} Einträge)",
            result.status_label(),
            result.total_entries
        ),
        None,
        Some(details),
    )
    .await?;

    let banner = if result.is_valid() {
        let last = result.last_hash.as_deref().unwrap_or("–");
        format!(
            r#"<div class="alert alert-success" data-chain-status="VALID">Status: <strong>VALID</strong> – {} Einträge lückenlos verifiziert. Letzter Hash: <code>{}</code></div>"#,
            result.total_entries,
            escape_html(last)
        )
    } else {
        let broken = result.first_broken_id.unwrap_or_default();
        format!(
            r#"<div class="alert alert-error" data-chain-status="COMPROMISED">Status: <strong>COMPROMISED</strong> – Integritätsverletzung ab Eintrag ID {broken} ({} Einträge geprüft).</div>"#,
            result.total_entries
        )
    };

    Ok(Html(banner))
}

fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}
