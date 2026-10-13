use std::{collections::BTreeMap, sync::Arc, time::Duration};

use chrono::{NaiveDate, Timelike, Utc};
use chrono_tz::Tz;
use sqlx::{PgPool, Row};
use tokio::{sync::watch, task::JoinHandle};
use uuid::Uuid;

use crate::{
    config::Config, db::begin_audited_tx, domain::actions::generate_next_recurrence_tx,
    error::AppError, mailer::Mailer,
};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Nis2AlertSummary {
    pub alerts_24h_triggered: usize,
    pub alerts_72h_triggered: usize,
    pub emails_sent: usize,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DailyActionSummary {
    pub recurrences_generated: usize,
    pub digest_emails_sent: usize,
}

pub async fn cleanup_expired_sessions_and_attempts(pool: &PgPool) -> Result<(u64, u64), AppError> {
    let sessions_deleted = sqlx::query("DELETE FROM sessions WHERE expires_at <= NOW()")
        .execute(pool)
        .await?
        .rows_affected();

    let attempts_deleted =
        sqlx::query("DELETE FROM login_attempts WHERE attempted_at < NOW() - INTERVAL '24 hours'")
            .execute(pool)
            .await?
            .rows_affected();

    Ok((sessions_deleted, attempts_deleted))
}

async fn load_iso_admin_emails(pool: &PgPool) -> Result<Vec<String>, AppError> {
    let emails: Vec<String> = sqlx::query_scalar(
        "SELECT email FROM users WHERE is_active = TRUE AND role IN ('admin', 'iso') ORDER BY email ASC",
    )
    .fetch_all(pool)
    .await?;
    Ok(emails)
}

pub async fn check_nis2_alerts(
    pool: &PgPool,
    mailer: &Mailer,
) -> Result<Nis2AlertSummary, AppError> {
    let mut summary = Nis2AlertSummary::default();
    let iso_emails = load_iso_admin_emails(pool).await?;

    let rows_24h = sqlx::query(
        r#"
        SELECT si.id, si.reference_code, si.title, si.early_warning_due_at, u.email AS lead_email
        FROM security_incidents si
        LEFT JOIN users u ON u.id = si.lead_handler_id AND u.is_active = TRUE
        WHERE si.is_nis2_significant = TRUE
          AND si.status <> 'closed'
          AND si.early_warning_submitted_at IS NULL
          AND si.early_warning_due_at IS NOT NULL
          AND si.early_warning_due_at <= NOW() + INTERVAL '6 hours'
          AND si.nis2_alert_24h_sent_at IS NULL
        "#,
    )
    .fetch_all(pool)
    .await?;

    for r in rows_24h {
        let id: Uuid = r.get("id");
        let code: String = r.get("reference_code");
        let title: String = r.get("title");
        let due: chrono::DateTime<Utc> = r.get("early_warning_due_at");
        let lead_email: Option<String> = r.get("lead_email");

        let mut recipients = iso_emails.clone();
        if let Some(le) = lead_email
            && !recipients.contains(&le)
        {
            recipients.push(le);
        }

        let subject = format!("[ins-isms] NIS2-24h-Frühwarnung fällig: {code}");
        let body = format!(
            "Für den NIS2-relevanten Sicherheitsvorfall {code} ({title}) läuft die 24h-Frühwarnfrist am {} ab.",
            due.format("%d.%m.%Y %H:%M UTC")
        );

        for to in &recipients {
            match mailer.send_text(to, &subject, &body).await {
                Ok(true) => summary.emails_sent += 1,
                Ok(false) => {}
                Err(err) => {
                    tracing::warn!(error = %err, to = %to, "NIS2-24h-E-Mail fehlgeschlagen");
                }
            }
        }

        let mut tx = begin_audited_tx(pool, None, None).await?;
        let res = sqlx::query(
            r#"
            UPDATE security_incidents
            SET nis2_alert_24h_sent_at = NOW(), updated_at = NOW()
            WHERE id = $1 AND nis2_alert_24h_sent_at IS NULL
            "#,
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        if res.rows_affected() > 0 {
            summary.alerts_24h_triggered += 1;
        }
    }

    let rows_72h = sqlx::query(
        r#"
        SELECT si.id, si.reference_code, si.title, si.incident_report_due_at, u.email AS lead_email
        FROM security_incidents si
        LEFT JOIN users u ON u.id = si.lead_handler_id AND u.is_active = TRUE
        WHERE si.is_nis2_significant = TRUE
          AND si.status <> 'closed'
          AND si.incident_report_submitted_at IS NULL
          AND si.incident_report_due_at IS NOT NULL
          AND si.incident_report_due_at <= NOW() + INTERVAL '12 hours'
          AND si.nis2_alert_72h_sent_at IS NULL
        "#,
    )
    .fetch_all(pool)
    .await?;

    for r in rows_72h {
        let id: Uuid = r.get("id");
        let code: String = r.get("reference_code");
        let title: String = r.get("title");
        let due: chrono::DateTime<Utc> = r.get("incident_report_due_at");
        let lead_email: Option<String> = r.get("lead_email");

        let mut recipients = iso_emails.clone();
        if let Some(le) = lead_email
            && !recipients.contains(&le)
        {
            recipients.push(le);
        }

        let subject = format!("[ins-isms] NIS2-72h-Vorfallsmeldung fällig: {code}");
        let body = format!(
            "Für den NIS2-relevanten Sicherheitsvorfall {code} ({title}) läuft die 72h-Meldefrist am {} ab.",
            due.format("%d.%m.%Y %H:%M UTC")
        );

        for to in &recipients {
            match mailer.send_text(to, &subject, &body).await {
                Ok(true) => summary.emails_sent += 1,
                Ok(false) => {}
                Err(err) => {
                    tracing::warn!(error = %err, to = %to, "NIS2-72h-E-Mail fehlgeschlagen");
                }
            }
        }

        let mut tx = begin_audited_tx(pool, None, None).await?;
        let res = sqlx::query(
            r#"
            UPDATE security_incidents
            SET nis2_alert_72h_sent_at = NOW(), updated_at = NOW()
            WHERE id = $1 AND nis2_alert_72h_sent_at IS NULL
            "#,
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        if res.rows_affected() > 0 {
            summary.alerts_72h_triggered += 1;
        }
    }

    Ok(summary)
}

pub async fn run_daily_action_maintenance(
    pool: &PgPool,
    mailer: &Mailer,
) -> Result<DailyActionSummary, AppError> {
    let mut summary = DailyActionSummary::default();

    let due_recurrence_ids: Vec<Uuid> = sqlx::query_scalar(
        r#"
        SELECT id
        FROM action_items
        WHERE recurrence_interval IS NOT NULL
          AND recurrence_next_generated = FALSE
          AND due_date IS NOT NULL
          AND due_date < CURRENT_DATE
          AND status <> 'cancelled'
        ORDER BY due_date ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    for action_id in due_recurrence_ids {
        let mut tx = begin_audited_tx(pool, None, None).await?;
        if generate_next_recurrence_tx(&mut tx, action_id)
            .await?
            .is_some()
        {
            summary.recurrences_generated += 1;
        }
        tx.commit().await?;
    }

    if !mailer.is_enabled() {
        return Ok(summary);
    }

    let due_rows = sqlx::query(
        r#"
        SELECT
            ai.reference_code,
            ai.title,
            ai.priority,
            ai.due_date,
            u.email AS assignee_email,
            (ai.due_date < CURRENT_DATE) AS is_overdue
        FROM action_items ai
        LEFT JOIN users u ON u.id = ai.assignee_user_id AND u.is_active = TRUE
        WHERE ai.status NOT IN ('done', 'cancelled')
          AND ai.due_date IS NOT NULL
          AND ai.due_date <= CURRENT_DATE + INTERVAL '7 days'
        ORDER BY ai.due_date ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut per_user: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut iso_escalations = Vec::new();

    for r in due_rows {
        let code: String = r.get("reference_code");
        let title: String = r.get("title");
        let priority: String = r.get("priority");
        let due: NaiveDate = r.get("due_date");
        let is_overdue: bool = r.get("is_overdue");
        let line = format!(
            "- {code}: {title} (Fällig: {}{})",
            due.format("%d.%m.%Y"),
            if is_overdue { ", ÜBERFÄLLIG" } else { "" }
        );

        if let Some(email) = r.get::<Option<String>, _>("assignee_email") {
            per_user.entry(email).or_default().push(line.clone());
        }
        if is_overdue && matches!(priority.as_str(), "high" | "critical") {
            iso_escalations.push(line);
        }
    }

    for (email, lines) in per_user {
        let body = format!(
            "Folgende ISMS-Maßnahmen sind überfällig oder in den nächsten 7 Tagen fällig:\n\n{}",
            lines.join("\n")
        );
        match mailer
            .send_text(&email, "[ins-isms] Maßnahmen-Fristenübersicht", &body)
            .await
        {
            Ok(true) => summary.digest_emails_sent += 1,
            Ok(false) => {}
            Err(err) => {
                tracing::warn!(error = %err, to = %email, "Maßnahmen-Digest-E-Mail fehlgeschlagen");
            }
        }
    }

    if !iso_escalations.is_empty() {
        let iso_emails: Vec<String> =
            sqlx::query_scalar("SELECT email FROM users WHERE is_active = TRUE AND role = 'iso'")
                .fetch_all(pool)
                .await?;
        let body = format!(
            "Überfällige Maßnahmen mit hoher oder kritischer Priorität:\n\n{}",
            iso_escalations.join("\n")
        );
        for email in iso_emails {
            match mailer
                .send_text(
                    &email,
                    "[ins-isms] Eskalation überfälliger Maßnahmen",
                    &body,
                )
                .await
            {
                Ok(true) => summary.digest_emails_sent += 1,
                Ok(false) => {}
                Err(err) => {
                    tracing::warn!(error = %err, to = %email, "ISB-Eskalations-E-Mail fehlgeschlagen");
                }
            }
        }
    }

    Ok(summary)
}

pub fn spawn_scheduler(
    pool: PgPool,
    config: Arc<Config>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    let mailer = Mailer::new(config.smtp.clone());
    let tz: Tz = config.app_timezone;

    tokio::spawn(async move {
        let mut hourly_tick = tokio::time::interval(Duration::from_secs(3600));
        let mut nis2_tick = tokio::time::interval(Duration::from_secs(1800));
        let mut daily_check_tick = tokio::time::interval(Duration::from_secs(60));
        let mut last_daily_run: Option<NaiveDate> = None;

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("Hintergrund-Scheduler wird sauber beendet");
                        break;
                    }
                }
                _ = hourly_tick.tick() => {
                    if let Err(err) = cleanup_expired_sessions_and_attempts(&pool).await {
                        tracing::warn!(error = %err, "Session-Bereinigung fehlgeschlagen");
                    }
                }
                _ = nis2_tick.tick() => {
                    if let Err(err) = check_nis2_alerts(&pool, &mailer).await {
                        tracing::warn!(error = %err, "NIS2-Fristenprüfung fehlgeschlagen");
                    }
                }
                _ = daily_check_tick.tick() => {
                    let now_local = Utc::now().with_timezone(&tz);
                    let today = now_local.date_naive();
                    if now_local.hour() >= 6 && last_daily_run != Some(today) {
                        last_daily_run = Some(today);
                        if let Err(err) = run_daily_action_maintenance(&pool, &mailer).await {
                            tracing::warn!(error = %err, "Tägliche Maßnahmen-Wartung fehlgeschlagen");
                        }
                    }
                }
            }
        }
    })
}
