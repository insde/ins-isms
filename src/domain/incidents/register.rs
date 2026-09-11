use std::str::FromStr;

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{
    auth::rbac::{CurrentUser, Role, forbid_auditor},
    domain::incidents::{
        CountdownBadge, IncidentSeverity, IncidentStatus, can_edit_incident_or_timeline,
        can_view_incident, format_nis2_countdown,
    },
    error::AppError,
    state::AppState,
    web::{ShellContext, render_page, render_template},
};

#[derive(Debug, Deserialize)]
pub struct IncidentFilterQuery {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub nis2_only: Option<String>,
    pub q: Option<String>,
}

struct SelectOption {
    id: String,
    label: String,
    selected: bool,
}

struct IncidentRowView {
    id: Uuid,
    reference_code: String,
    title: String,
    severity_label: &'static str,
    severity_css: &'static str,
    status_label: &'static str,
    status_css: &'static str,
    is_closed: bool,
    is_nis2_significant: bool,
    detected_label: String,
    unit_label: String,
    handler_label: String,
    nis2_badges: Vec<CountdownBadge>,
}

pub struct TimelineEventView {
    pub occurred_label: String,
    pub author_name: String,
    pub note: String,
}

#[derive(Template)]
#[template(path = "incidents/register.html")]
struct IncidentRegisterTemplate {
    rows: Vec<IncidentRowView>,
    filter_status: String,
    filter_severity: String,
    filter_nis2_only: bool,
    filter_q: String,
    open_count: usize,
    nis2_open_count: usize,
    can_create: bool,
    is_employee: bool,
}

#[derive(Template)]
#[template(path = "incidents/new_drawer.html")]
struct NewIncidentDrawerTemplate {
    system_assets: Vec<SelectOption>,
    units: Vec<SelectOption>,
    users: Vec<SelectOption>,
    can_classify_nis2: bool,
    default_detected_at: String,
}

#[derive(Template)]
#[template(path = "incidents/report.html")]
struct EmployeeReportTemplate {
    system_assets: Vec<SelectOption>,
}

#[derive(Template)]
#[template(path = "incidents/drawer.html")]
struct IncidentDrawerTemplate {
    id: Uuid,
    reference_code: String,
    title: String,
    description: String,
    severity_label: &'static str,
    severity_css: &'static str,
    status_label: &'static str,
    status_css: &'static str,
    detected_label: String,
    unit_label: String,
    handler_label: String,
    is_nis2_significant: bool,
    nis2_badges: Vec<CountdownBadge>,
}

#[derive(Template)]
#[template(path = "incidents/timeline_list.html")]
struct TimelineListTemplate {
    events: Vec<TimelineEventView>,
}

#[derive(Template)]
#[template(path = "incidents/detail.html")]
struct IncidentDetailTemplate {
    id: Uuid,
    reference_code: String,
    title: String,
    description: String,
    severity: String,
    severity_label: &'static str,
    severity_css: &'static str,
    status: String,
    status_label: &'static str,
    status_css: &'static str,
    detected_input: String,
    detected_label: String,
    contained_label: String,
    resolved_label: String,
    reporter_label: String,
    unit_label: String,
    is_nis2_significant: bool,
    bsi_ticket_reference: String,
    early_warning_due_label: String,
    early_warning_submitted_label: String,
    early_warning_submitted: bool,
    early_badge: Option<CountdownBadge>,
    incident_report_due_label: String,
    incident_report_submitted_label: String,
    incident_report_submitted: bool,
    report_badge: Option<CountdownBadge>,
    final_report_due_label: String,
    final_report_submitted_label: String,
    final_report_submitted: bool,
    final_badge: Option<CountdownBadge>,
    root_cause_analysis: String,
    lessons_learned: String,
    system_assets: Vec<SelectOption>,
    units: Vec<SelectOption>,
    users: Vec<SelectOption>,
    events: Vec<TimelineEventView>,
    can_edit: bool,
    can_manage_nis2_and_close: bool,
}

fn format_dt_local(dt: DateTime<Utc>, tz: chrono_tz::Tz) -> String {
    dt.with_timezone(&tz).format("%d.%m.%Y %H:%M").to_string()
}

fn format_dt_input(dt: DateTime<Utc>, tz: chrono_tz::Tz) -> String {
    dt.with_timezone(&tz).format("%Y-%m-%dT%H:%M").to_string()
}

pub async fn load_timeline_events(
    pool: &PgPool,
    incident_id: Uuid,
    tz: chrono_tz::Tz,
) -> Result<Vec<TimelineEventView>, AppError> {
    let rows = sqlx::query(
        r#"
        SELECT e.occurred_at, e.note, COALESCE(u.full_name, 'System') AS author_name
        FROM incident_timeline_events e
        LEFT JOIN users u ON u.id = e.author_id
        WHERE e.incident_id = $1
        ORDER BY e.occurred_at ASC, e.created_at ASC
        "#,
    )
    .bind(incident_id)
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let occurred_at: DateTime<Utc> = row.try_get("occurred_at")?;
        out.push(TimelineEventView {
            occurred_label: format_dt_local(occurred_at, tz),
            author_name: row.try_get("author_name")?,
            note: row.try_get("note")?,
        });
    }
    Ok(out)
}

pub async fn render_timeline_partial(
    pool: &PgPool,
    incident_id: Uuid,
) -> Result<Html<String>, AppError> {
    let events = load_timeline_events(pool, incident_id, chrono_tz::Europe::Berlin).await?;
    render_template(&TimelineListTemplate { events })
}

async fn load_select_options(
    pool: &PgPool,
    selected_asset: Option<Uuid>,
    selected_unit: Option<Uuid>,
    selected_user: Option<Uuid>,
) -> Result<(Vec<SelectOption>, Vec<SelectOption>, Vec<SelectOption>), AppError> {
    let asset_rows =
        sqlx::query("SELECT id, asset_code, name FROM system_assets ORDER BY asset_code ASC")
            .fetch_all(pool)
            .await?;
    let mut system_assets = Vec::with_capacity(asset_rows.len());
    for row in asset_rows {
        let id: Uuid = row.try_get("id")?;
        let code: String = row.try_get("asset_code")?;
        let name: String = row.try_get("name")?;
        system_assets.push(SelectOption {
            id: id.to_string(),
            label: format!("{code} · {name}"),
            selected: selected_asset == Some(id),
        });
    }

    let unit_rows = sqlx::query("SELECT id, name FROM organization_units ORDER BY name ASC")
        .fetch_all(pool)
        .await?;
    let mut units = Vec::with_capacity(unit_rows.len());
    for row in unit_rows {
        let id: Uuid = row.try_get("id")?;
        units.push(SelectOption {
            id: id.to_string(),
            label: row.try_get("name")?,
            selected: selected_unit == Some(id),
        });
    }

    let user_rows = sqlx::query(
        "SELECT id, full_name FROM users WHERE is_active = TRUE ORDER BY full_name ASC",
    )
    .fetch_all(pool)
    .await?;
    let mut users = Vec::with_capacity(user_rows.len());
    for row in user_rows {
        let id: Uuid = row.try_get("id")?;
        users.push(SelectOption {
            id: id.to_string(),
            label: row.try_get("full_name")?,
            selected: selected_user == Some(id),
        });
    }

    Ok((system_assets, units, users))
}

pub async fn list_incidents_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Query(query): Query<IncidentFilterQuery>,
) -> Result<impl IntoResponse, AppError> {
    let filter_status = query.status.unwrap_or_default().trim().to_string();
    let filter_severity = query.severity.unwrap_or_default().trim().to_string();
    let filter_nis2_only =
        query.nis2_only.as_deref() == Some("1") || query.nis2_only.as_deref() == Some("true");
    let filter_q = query.q.unwrap_or_default().trim().to_string();
    let like_q = format!("%{filter_q}%");

    let scope_mode: i32 = match user.role {
        Role::Admin | Role::Iso | Role::Auditor => 0,
        Role::Owner => 1,
        Role::Employee => 2,
    };

    let db_rows = sqlx::query(
        r#"
        SELECT
            si.id,
            si.reference_code,
            si.title,
            si.severity,
            si.status,
            si.detected_at,
            si.is_nis2_significant,
            si.early_warning_due_at,
            si.early_warning_submitted_at,
            si.incident_report_due_at,
            si.incident_report_submitted_at,
            si.final_report_due_at,
            si.final_report_submitted_at,
            COALESCE(ou.name, '–') AS unit_label,
            COALESCE(lh.full_name, 'Nicht zugewiesen') AS handler_label
        FROM security_incidents si
        LEFT JOIN organization_units ou ON ou.id = si.owner_unit_id
        LEFT JOIN users lh ON lh.id = si.lead_handler_id
        WHERE (
            $1 = 0
            OR ($1 = 1 AND (si.owner_unit_id = $2 OR si.reported_by_user_id = $3 OR si.lead_handler_id = $3))
            OR ($1 = 2 AND si.reported_by_user_id = $3)
        )
          AND ($4 = '' OR si.status = $4)
          AND ($5 = '' OR si.severity = $5)
          AND (NOT $6 OR si.is_nis2_significant = TRUE)
          AND ($7 = '' OR si.reference_code ILIKE $8 OR si.title ILIKE $8)
        ORDER BY (si.status = 'closed') ASC, si.is_nis2_significant DESC, si.detected_at DESC
        "#,
    )
    .bind(scope_mode)
    .bind(user.organization_unit_id)
    .bind(user.id)
    .bind(&filter_status)
    .bind(&filter_severity)
    .bind(filter_nis2_only)
    .bind(&filter_q)
    .bind(&like_q)
    .fetch_all(&state.pool)
    .await?;

    let now = Utc::now();
    let tz = state.config.app_timezone;
    let mut rows = Vec::with_capacity(db_rows.len());
    let mut open_count = 0usize;
    let mut nis2_open_count = 0usize;

    for row in db_rows {
        let sev_raw: String = row.try_get("severity")?;
        let st_raw: String = row.try_get("status")?;
        let sev = IncidentSeverity::from_str(&sev_raw).unwrap_or(IncidentSeverity::Medium);
        let st = IncidentStatus::from_str(&st_raw).unwrap_or(IncidentStatus::Detected);
        let is_closed = st == IncidentStatus::Closed;
        let is_nis2: bool = row.try_get("is_nis2_significant")?;

        if !is_closed {
            open_count += 1;
            if is_nis2 {
                nis2_open_count += 1;
            }
        }

        let mut nis2_badges = Vec::new();
        if is_nis2 {
            let early_due: Option<DateTime<Utc>> = row.try_get("early_warning_due_at")?;
            let early_sub: Option<DateTime<Utc>> = row.try_get("early_warning_submitted_at")?;
            let rep_due: Option<DateTime<Utc>> = row.try_get("incident_report_due_at")?;
            let rep_sub: Option<DateTime<Utc>> = row.try_get("incident_report_submitted_at")?;
            let fin_due: Option<DateTime<Utc>> = row.try_get("final_report_due_at")?;
            let fin_sub: Option<DateTime<Utc>> = row.try_get("final_report_submitted_at")?;

            if let Some(b) = format_nis2_countdown("24h", early_due, early_sub, now) {
                nis2_badges.push(b);
            }
            if let Some(b) = format_nis2_countdown("72h", rep_due, rep_sub, now) {
                nis2_badges.push(b);
            }
            if let Some(b) = format_nis2_countdown("30d", fin_due, fin_sub, now) {
                nis2_badges.push(b);
            }
        }

        let detected_at: DateTime<Utc> = row.try_get("detected_at")?;
        rows.push(IncidentRowView {
            id: row.try_get("id")?,
            reference_code: row.try_get("reference_code")?,
            title: row.try_get("title")?,
            severity_label: sev.label(),
            severity_css: sev.css_class(),
            status_label: st.label(),
            status_css: st.css_class(),
            is_closed,
            is_nis2_significant: is_nis2,
            detected_label: format_dt_local(detected_at, tz),
            unit_label: row.try_get("unit_label")?,
            handler_label: row.try_get("handler_label")?,
            nis2_badges,
        });
    }

    let shell = ShellContext::from_user(
        &user,
        "Sicherheitsvorfälle & NIS2",
        "Betrieb (PDCA & NIS2)",
        "incidents",
    );
    render_page(
        &headers,
        shell,
        &IncidentRegisterTemplate {
            rows,
            filter_status,
            filter_severity,
            filter_nis2_only,
            filter_q,
            open_count,
            nis2_open_count,
            can_create: matches!(user.role, Role::Admin | Role::Iso | Role::Owner),
            is_employee: user.role == Role::Employee,
        },
    )
}

pub async fn new_incident_form_handler(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Bitte nutzen Sie das Mitarbeiter-Meldeformular.".to_string(),
        ));
    }

    let (system_assets, units, users) = load_select_options(&state.pool, None, None, None).await?;
    render_template(&NewIncidentDrawerTemplate {
        system_assets,
        units,
        users,
        can_classify_nis2: user.role.is_iso_or_admin(),
        default_detected_at: format_dt_input(Utc::now(), state.config.app_timezone),
    })
}

pub async fn report_form_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;

    let (system_assets, _, _) = load_select_options(&state.pool, None, None, None).await?;
    let shell = ShellContext::from_user(
        &user,
        "Sicherheitsvorfall melden",
        "Betrieb (PDCA & NIS2)",
        "incidents",
    );
    render_page(&headers, shell, &EmployeeReportTemplate { system_assets })
}

pub async fn incident_drawer_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let row = sqlx::query(
        r#"
        SELECT
            si.*,
            COALESCE(ou.name, '–') AS unit_label,
            COALESCE(lh.full_name, 'Nicht zugewiesen') AS handler_label
        FROM security_incidents si
        LEFT JOIN organization_units ou ON ou.id = si.owner_unit_id
        LEFT JOIN users lh ON lh.id = si.lead_handler_id
        WHERE si.id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Sicherheitsvorfall nicht gefunden".to_string()))?;

    let owner_unit: Option<Uuid> = row.try_get("owner_unit_id")?;
    let reporter: Option<Uuid> = row.try_get("reported_by_user_id")?;
    let lead: Option<Uuid> = row.try_get("lead_handler_id")?;
    if !can_view_incident(&user, owner_unit, reporter, lead) {
        return Err(AppError::Forbidden(
            "Kein Zugriff auf diesen Sicherheitsvorfall.".to_string(),
        ));
    }

    let sev_raw: String = row.try_get("severity")?;
    let st_raw: String = row.try_get("status")?;
    let sev = IncidentSeverity::from_str(&sev_raw).unwrap_or(IncidentSeverity::Medium);
    let st = IncidentStatus::from_str(&st_raw).unwrap_or(IncidentStatus::Detected);
    let is_nis2: bool = row.try_get("is_nis2_significant")?;
    let now = Utc::now();

    let mut nis2_badges = Vec::new();
    if is_nis2 {
        let early_due: Option<DateTime<Utc>> = row.try_get("early_warning_due_at")?;
        let early_sub: Option<DateTime<Utc>> = row.try_get("early_warning_submitted_at")?;
        let rep_due: Option<DateTime<Utc>> = row.try_get("incident_report_due_at")?;
        let rep_sub: Option<DateTime<Utc>> = row.try_get("incident_report_submitted_at")?;
        let fin_due: Option<DateTime<Utc>> = row.try_get("final_report_due_at")?;
        let fin_sub: Option<DateTime<Utc>> = row.try_get("final_report_submitted_at")?;

        if let Some(b) = format_nis2_countdown("24h Frühwarnung", early_due, early_sub, now) {
            nis2_badges.push(b);
        }
        if let Some(b) = format_nis2_countdown("72h Meldung", rep_due, rep_sub, now) {
            nis2_badges.push(b);
        }
        if let Some(b) = format_nis2_countdown("30d Abschluss", fin_due, fin_sub, now) {
            nis2_badges.push(b);
        }
    }

    let detected_at: DateTime<Utc> = row.try_get("detected_at")?;
    render_template(&IncidentDrawerTemplate {
        id,
        reference_code: row.try_get("reference_code")?,
        title: row.try_get("title")?,
        description: row.try_get("description")?,
        severity_label: sev.label(),
        severity_css: sev.css_class(),
        status_label: st.label(),
        status_css: st.css_class(),
        detected_label: format_dt_local(detected_at, state.config.app_timezone),
        unit_label: row.try_get("unit_label")?,
        handler_label: row.try_get("handler_label")?,
        is_nis2_significant: is_nis2,
        nis2_badges,
    })
}

pub async fn incident_detail_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let row = sqlx::query(
        r#"
        SELECT
            si.*,
            COALESCE(ou.name, '–') AS unit_label,
            COALESCE(rep.full_name, 'System') AS reporter_label
        FROM security_incidents si
        LEFT JOIN organization_units ou ON ou.id = si.owner_unit_id
        LEFT JOIN users rep ON rep.id = si.reported_by_user_id
        WHERE si.id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Sicherheitsvorfall nicht gefunden".to_string()))?;

    let owner_unit: Option<Uuid> = row.try_get("owner_unit_id")?;
    let reporter: Option<Uuid> = row.try_get("reported_by_user_id")?;
    let lead: Option<Uuid> = row.try_get("lead_handler_id")?;
    if !can_view_incident(&user, owner_unit, reporter, lead) {
        return Err(AppError::Forbidden(
            "Kein Zugriff auf diesen Sicherheitsvorfall.".to_string(),
        ));
    }

    let asset_id: Option<Uuid> = row.try_get("affected_system_asset_id")?;
    let (system_assets, units, users) =
        load_select_options(&state.pool, asset_id, owner_unit, lead).await?;

    let tz = state.config.app_timezone;
    let timeline_events = load_timeline_events(&state.pool, id, tz).await?;

    let sev_raw: String = row.try_get("severity")?;
    let st_raw: String = row.try_get("status")?;
    let sev = IncidentSeverity::from_str(&sev_raw).unwrap_or(IncidentSeverity::Medium);
    let st = IncidentStatus::from_str(&st_raw).unwrap_or(IncidentStatus::Detected);

    let detected_at: DateTime<Utc> = row.try_get("detected_at")?;
    let contained_at: Option<DateTime<Utc>> = row.try_get("contained_at")?;
    let resolved_at: Option<DateTime<Utc>> = row.try_get("resolved_at")?;
    let is_nis2: bool = row.try_get("is_nis2_significant")?;

    let early_due: Option<DateTime<Utc>> = row.try_get("early_warning_due_at")?;
    let early_sub: Option<DateTime<Utc>> = row.try_get("early_warning_submitted_at")?;
    let rep_due: Option<DateTime<Utc>> = row.try_get("incident_report_due_at")?;
    let rep_sub: Option<DateTime<Utc>> = row.try_get("incident_report_submitted_at")?;
    let fin_due: Option<DateTime<Utc>> = row.try_get("final_report_due_at")?;
    let fin_sub: Option<DateTime<Utc>> = row.try_get("final_report_submitted_at")?;

    let now = Utc::now();
    let reference_code: String = row.try_get("reference_code")?;
    let title: String = row.try_get("title")?;

    let shell = ShellContext::from_user(
        &user,
        format!("{reference_code} · {title}"),
        "Sicherheitsvorfälle",
        "incidents",
    );
    render_page(
        &headers,
        shell,
        &IncidentDetailTemplate {
            id,
            reference_code,
            title,
            description: row.try_get("description")?,
            severity: sev_raw,
            severity_label: sev.label(),
            severity_css: sev.css_class(),
            status: st_raw,
            status_label: st.label(),
            status_css: st.css_class(),
            detected_input: format_dt_input(detected_at, tz),
            detected_label: format_dt_local(detected_at, tz),
            contained_label: contained_at
                .map(|d| format_dt_local(d, tz))
                .unwrap_or_else(|| "–".to_string()),
            resolved_label: resolved_at
                .map(|d| format_dt_local(d, tz))
                .unwrap_or_else(|| "–".to_string()),
            reporter_label: row.try_get("reporter_label")?,
            unit_label: row.try_get("unit_label")?,
            is_nis2_significant: is_nis2,
            bsi_ticket_reference: row
                .try_get::<Option<String>, _>("bsi_ticket_reference")?
                .unwrap_or_default(),
            early_warning_due_label: early_due
                .map(|d| format_dt_local(d, tz))
                .unwrap_or_else(|| "–".to_string()),
            early_warning_submitted_label: early_sub
                .map(|d| format_dt_local(d, tz))
                .unwrap_or_else(|| "Ausstehend".to_string()),
            early_warning_submitted: early_sub.is_some(),
            early_badge: if is_nis2 {
                format_nis2_countdown("24h", early_due, early_sub, now)
            } else {
                None
            },
            incident_report_due_label: rep_due
                .map(|d| format_dt_local(d, tz))
                .unwrap_or_else(|| "–".to_string()),
            incident_report_submitted_label: rep_sub
                .map(|d| format_dt_local(d, tz))
                .unwrap_or_else(|| "Ausstehend".to_string()),
            incident_report_submitted: rep_sub.is_some(),
            report_badge: if is_nis2 {
                format_nis2_countdown("72h", rep_due, rep_sub, now)
            } else {
                None
            },
            final_report_due_label: fin_due
                .map(|d| format_dt_local(d, tz))
                .unwrap_or_else(|| "–".to_string()),
            final_report_submitted_label: fin_sub
                .map(|d| format_dt_local(d, tz))
                .unwrap_or_else(|| "Ausstehend".to_string()),
            final_report_submitted: fin_sub.is_some(),
            final_badge: if is_nis2 {
                format_nis2_countdown("30d", fin_due, fin_sub, now)
            } else {
                None
            },
            root_cause_analysis: row
                .try_get::<Option<String>, _>("root_cause_analysis")?
                .unwrap_or_default(),
            lessons_learned: row
                .try_get::<Option<String>, _>("lessons_learned")?
                .unwrap_or_default(),
            system_assets,
            units,
            users,
            events: timeline_events,
            can_edit: can_edit_incident_or_timeline(&user, owner_unit, reporter, lead),
            can_manage_nis2_and_close: user.role.is_iso_or_admin(),
        },
    )
}
