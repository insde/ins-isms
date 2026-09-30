use std::str::FromStr;

use askama::Template;
use axum::{
    extract::{Form, Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, NaiveDate, Utc};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    auth::rbac::{ClientIp, CurrentUser, forbid_auditor},
    db::begin_audited_tx,
    domain::audits::{KpiSnapshot, ReviewStatus, aggregate_iso93_kpis, ensure_audit_read_access},
    error::AppError,
    state::AppState,
    web::{ShellContext, hx_redirect_or_303, render_page, with_toast},
};

struct ReviewRowView {
    id: Uuid,
    period_label: String,
    review_date_label: String,
    participants: String,
    status_label: &'static str,
    status_css: &'static str,
    approved_label: String,
    soa_percent: String,
    open_nc_count: i64,
}

#[derive(Template)]
#[template(path = "audits/reviews_list.html")]
struct ReviewListTemplate {
    reviews: Vec<ReviewRowView>,
    can_manage: bool,
    only_approved_visible: bool,
}

#[derive(Template)]
#[template(path = "audits/review_new.html")]
struct NewReviewTemplate {
    default_date: String,
    default_period: String,
    kpi: KpiSnapshot,
}

#[derive(Template)]
#[template(path = "audits/review_detail.html")]
struct ReviewDetailTemplate {
    id: Uuid,
    period_label: String,
    review_date_input: String,
    review_date_label: String,
    participants: String,
    management_decisions: String,
    status_label: &'static str,
    status_css: &'static str,
    is_approved: bool,
    approved_by_label: String,
    approved_at_label: String,
    kpi: KpiSnapshot,
    can_manage: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateReviewForm {
    pub review_date: String,
    pub period_label: String,
    pub participants: String,
    pub management_decisions: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateReviewForm {
    pub review_date: String,
    pub period_label: String,
    pub participants: String,
    pub management_decisions: Option<String>,
}

fn parse_required_date(raw: &str) -> Result<NaiveDate, AppError> {
    NaiveDate::parse_from_str(raw.trim(), "%Y-%m-%d").map_err(|_| {
        AppError::Validation(vec![
            "Ungültiges Bewertungsdatum (Format JJJJ-MM-TT erwartet).".to_string(),
        ])
    })
}

/// `GET /management-reviews` – Übersicht der Management-Bewertungen (ISO 9.3).
pub async fn list_reviews_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    ensure_audit_read_access(&user)?;
    let only_approved_visible = !user.role.is_iso_or_admin();

    let rows = sqlx::query(
        r#"
        SELECT
            mr.id,
            mr.review_date,
            mr.period_label,
            mr.participants,
            mr.status,
            mr.kpi_snapshot_json,
            mr.approved_at,
            u.full_name AS approved_by_name
        FROM management_reviews mr
        LEFT JOIN users u ON u.id = mr.approved_by_user_id
        WHERE (NOT $1 OR mr.status = 'approved')
        ORDER BY mr.review_date DESC, mr.created_at DESC
        "#,
    )
    .bind(only_approved_visible)
    .fetch_all(&state.pool)
    .await?;

    let mut reviews = Vec::with_capacity(rows.len());
    for r in rows {
        let status = ReviewStatus::from_str(r.get::<&str, _>("status"))?;
        let review_date: NaiveDate = r.get("review_date");
        let approved_at: Option<DateTime<Utc>> = r.get("approved_at");
        let approved_by: Option<String> = r.get("approved_by_name");
        let kpi_val: serde_json::Value = r.get("kpi_snapshot_json");
        let kpi: KpiSnapshot = serde_json::from_value(kpi_val).map_err(|e| {
            AppError::Internal(format!("Ungültiger KPI-Snapshot in Datenbank: {e}"))
        })?;

        let approved_label = match (approved_at, approved_by) {
            (Some(ts), Some(name)) => {
                format!("{} ({name})", ts.format("%d.%m.%Y"))
            }
            (Some(ts), None) => ts.format("%d.%m.%Y").to_string(),
            _ => "–".to_string(),
        };

        reviews.push(ReviewRowView {
            id: r.get("id"),
            period_label: r.get("period_label"),
            review_date_label: review_date.format("%d.%m.%Y").to_string(),
            participants: r.get("participants"),
            status_label: status.label(),
            status_css: status.css_class(),
            approved_label,
            soa_percent: format!("{:.1} %", kpi.soa.implementation_percent),
            open_nc_count: kpi.audits_and_actions.open_major_nc
                + kpi.audits_and_actions.open_minor_nc,
        });
    }

    let shell = ShellContext::from_user(
        &user,
        "Management-Bewertung (ISO 9.3)",
        "Betrieb (PDCA & NIS2)",
        "audits",
    );
    render_page(
        &headers,
        shell,
        &ReviewListTemplate {
            reviews,
            can_manage: user.role.is_iso_or_admin(),
            only_approved_visible,
        },
    )
}

pub async fn new_review_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;
    if !user.role.is_iso_or_admin() {
        return Err(AppError::Forbidden(
            "Nur Admin oder ISB dürfen Management-Bewertungen erstellen.".to_string(),
        ));
    }

    let kpi = aggregate_iso93_kpis(&state.pool).await?;
    let now = Utc::now();
    let default_date = now.format("%Y-%m-%d").to_string();
    let default_period = format!("GJ {}", now.format("%Y"));

    let shell = ShellContext::from_user(
        &user,
        "Neue Management-Bewertung",
        "Management-Bewertung",
        "audits",
    );
    render_page(
        &headers,
        shell,
        &NewReviewTemplate {
            default_date,
            default_period,
            kpi,
        },
    )
}

pub async fn create_review_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Form(form): Form<CreateReviewForm>,
) -> Result<Response, AppError> {
    forbid_auditor(&user)?;
    if !user.role.is_iso_or_admin() {
        return Err(AppError::Forbidden(
            "Nur Admin oder ISB dürfen Management-Bewertungen anlegen.".to_string(),
        ));
    }

    let period_label = form.period_label.trim();
    let participants = form.participants.trim();
    if period_label.is_empty() || participants.is_empty() {
        return Err(AppError::Validation(vec![
            "Berichtszeitraum und Teilnehmerkreis sind Pflichtfelder.".to_string(),
        ]));
    }
    let review_date = parse_required_date(&form.review_date)?;
    let decisions = form
        .management_decisions
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .to_string();

    let kpi = aggregate_iso93_kpis(&state.pool).await?;
    let kpi_json = serde_json::to_value(&kpi)
        .map_err(|e| AppError::Internal(format!("KPI-Serialisierung fehlgeschlagen: {e}")))?;

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;
    let review_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO management_reviews (
            id, review_date, period_label, participants, status, kpi_snapshot_json, management_decisions
        )
        VALUES ($1, $2, $3, $4, 'draft', $5, $6)
        "#,
    )
    .bind(review_id)
    .bind(review_date)
    .bind(period_label)
    .bind(participants)
    .bind(kpi_json)
    .bind(decisions)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let resp = hx_redirect_or_303(&headers, &format!("/management-reviews/{review_id}"));
    Ok(with_toast(
        resp,
        "success",
        "Management-Bewertung mit Live-KPIs erstellt.",
    ))
}

pub async fn review_detail_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Path(review_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    ensure_audit_read_access(&user)?;

    let row = sqlx::query(
        r#"
        SELECT
            mr.id,
            mr.review_date,
            mr.period_label,
            mr.participants,
            mr.status,
            mr.kpi_snapshot_json,
            mr.management_decisions,
            mr.approved_at,
            u.full_name AS approved_by_name
        FROM management_reviews mr
        LEFT JOIN users u ON u.id = mr.approved_by_user_id
        WHERE mr.id = $1
        "#,
    )
    .bind(review_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Management-Bewertung nicht gefunden.".to_string()))?;

    let status = ReviewStatus::from_str(row.get::<&str, _>("status"))?;
    if status == ReviewStatus::Draft && !user.role.is_iso_or_admin() {
        return Err(AppError::Forbidden(
            "Entwürfe von Management-Bewertungen sind nur für Admin und ISB sichtbar.".to_string(),
        ));
    }

    let review_date: NaiveDate = row.get("review_date");
    let period_label: String = row.get("period_label");
    let kpi: KpiSnapshot = serde_json::from_value(row.get("kpi_snapshot_json"))
        .map_err(|e| AppError::Internal(format!("Ungültiger KPI-Snapshot: {e}")))?;

    let approved_at: Option<DateTime<Utc>> = row.get("approved_at");
    let approved_by_label = row
        .get::<Option<String>, _>("approved_by_name")
        .unwrap_or_else(|| "–".to_string());
    let approved_at_label = approved_at
        .map(|ts| ts.format("%d.%m.%Y %H:%M UTC").to_string())
        .unwrap_or_else(|| "–".to_string());

    let page_title = format!("Management-Bewertung · {period_label}");
    let shell = ShellContext::from_user(&user, &page_title, "Management-Bewertung", "audits");
    render_page(
        &headers,
        shell,
        &ReviewDetailTemplate {
            id: row.get("id"),
            period_label,
            review_date_input: review_date.format("%Y-%m-%d").to_string(),
            review_date_label: review_date.format("%d.%m.%Y").to_string(),
            participants: row.get("participants"),
            management_decisions: row.get("management_decisions"),
            status_label: status.label(),
            status_css: status.css_class(),
            is_approved: status == ReviewStatus::Approved,
            approved_by_label,
            approved_at_label,
            kpi,
            can_manage: user.role.is_iso_or_admin(),
        },
    )
}

pub async fn update_review_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Path(review_id): Path<Uuid>,
    Form(form): Form<UpdateReviewForm>,
) -> Result<Response, AppError> {
    forbid_auditor(&user)?;
    if !user.role.is_iso_or_admin() {
        return Err(AppError::Forbidden(
            "Nur Admin oder ISB dürfen Management-Bewertungen bearbeiten.".to_string(),
        ));
    }

    let period_label = form.period_label.trim();
    let participants = form.participants.trim();
    if period_label.is_empty() || participants.is_empty() {
        return Err(AppError::Validation(vec![
            "Berichtszeitraum und Teilnehmerkreis dürfen nicht leer sein.".to_string(),
        ]));
    }
    let review_date = parse_required_date(&form.review_date)?;
    let decisions = form
        .management_decisions
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .to_string();

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;
    let current_status: String =
        sqlx::query_scalar("SELECT status FROM management_reviews WHERE id = $1 FOR UPDATE")
            .bind(review_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| {
                AppError::NotFound("Management-Bewertung nicht gefunden.".to_string())
            })?;

    if ReviewStatus::from_str(&current_status)? == ReviewStatus::Approved {
        return Err(AppError::Conflict(
            "Freigegebene Management-Bewertungen sind unveränderlich eingefroren.".to_string(),
        ));
    }

    sqlx::query(
        r#"
        UPDATE management_reviews
        SET review_date = $2,
            period_label = $3,
            participants = $4,
            management_decisions = $5,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(review_id)
    .bind(review_date)
    .bind(period_label)
    .bind(participants)
    .bind(decisions)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let resp = hx_redirect_or_303(&headers, &format!("/management-reviews/{review_id}"));
    Ok(with_toast(
        resp,
        "success",
        "Management-Bewertung gespeichert.",
    ))
}

pub async fn refresh_review_kpis_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Path(review_id): Path<Uuid>,
) -> Result<Response, AppError> {
    forbid_auditor(&user)?;
    if !user.role.is_iso_or_admin() {
        return Err(AppError::Forbidden(
            "Nur Admin oder ISB dürfen KPIs aktualisieren.".to_string(),
        ));
    }

    let kpi = aggregate_iso93_kpis(&state.pool).await?;
    let kpi_json = serde_json::to_value(&kpi)
        .map_err(|e| AppError::Internal(format!("KPI-Serialisierung fehlgeschlagen: {e}")))?;

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;
    let current_status: String =
        sqlx::query_scalar("SELECT status FROM management_reviews WHERE id = $1 FOR UPDATE")
            .bind(review_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| {
                AppError::NotFound("Management-Bewertung nicht gefunden.".to_string())
            })?;

    if ReviewStatus::from_str(&current_status)? == ReviewStatus::Approved {
        return Err(AppError::Conflict(
            "Der KPI-Snapshot einer freigegebenen Management-Bewertung ist eingefroren."
                .to_string(),
        ));
    }

    sqlx::query(
        "UPDATE management_reviews SET kpi_snapshot_json = $2, updated_at = NOW() WHERE id = $1",
    )
    .bind(review_id)
    .bind(kpi_json)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let resp = hx_redirect_or_303(&headers, &format!("/management-reviews/{review_id}"));
    Ok(with_toast(
        resp,
        "success",
        "ISO-9.3-Kennzahlen aktualisiert.",
    ))
}

pub async fn approve_review_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Path(review_id): Path<Uuid>,
) -> Result<Response, AppError> {
    forbid_auditor(&user)?;
    if !user.role.is_iso_or_admin() {
        return Err(AppError::Forbidden(
            "Nur Admin oder ISB dürfen Management-Bewertungen freigeben.".to_string(),
        ));
    }

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;
    let current_status: String =
        sqlx::query_scalar("SELECT status FROM management_reviews WHERE id = $1 FOR UPDATE")
            .bind(review_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| {
                AppError::NotFound("Management-Bewertung nicht gefunden.".to_string())
            })?;

    if ReviewStatus::from_str(&current_status)? == ReviewStatus::Approved {
        return Err(AppError::Conflict(
            "Diese Management-Bewertung wurde bereits freigegeben.".to_string(),
        ));
    }

    sqlx::query(
        r#"
        UPDATE management_reviews
        SET status = 'approved',
            approved_by_user_id = $2,
            approved_at = NOW(),
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(review_id)
    .bind(user.id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let resp = hx_redirect_or_303(&headers, &format!("/management-reviews/{review_id}"));
    Ok(with_toast(
        resp,
        "success",
        "Management-Bewertung freigegeben und KPI-Snapshot eingefroren.",
    ))
}
