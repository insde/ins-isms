use std::str::FromStr;

use askama::Template;
use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect},
};
use chrono::{NaiveDate, Utc};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    auth::rbac::{ClientIp, CurrentUser, Role, forbid_auditor, is_htmx_request},
    db::begin_audited_tx,
    domain::actions::{
        ActionPriority, ActionSourceType, ActionStatus, RecurrenceInterval,
        ensure_action_read_access, ensure_action_write_access, generate_next_recurrence_tx,
        next_action_reference_code, validate_action_transition,
    },
    error::AppError,
    state::AppState,
    web::{ShellContext, render_page, render_template},
};

#[derive(Debug, Clone)]
pub struct SelectOption {
    pub id: String,
    pub label: String,
    pub selected: bool,
}

#[derive(Debug, Clone)]
pub struct ActionRowView {
    pub id: Uuid,
    pub reference_code: String,
    pub title: String,
    pub source_type_str: String,
    pub source_type_label: &'static str,
    pub priority_label: &'static str,
    pub priority_css: &'static str,
    pub status_str: String,
    pub status_label: &'static str,
    pub status_css: &'static str,
    pub due_date_label: String,
    pub is_overdue: bool,
    pub assignee_name: String,
    pub unit_name: String,
    pub recurrence_label: String,
    pub source_ref_label: String,
    pub source_ref_href: String,
    pub needs_verification_modal: bool,
    pub next_status_str: String,
}

#[derive(Debug, Deserialize)]
pub struct ActionFilterQuery {
    pub filter: Option<String>,
    pub source_type: Option<String>,
    pub priority: Option<String>,
    pub q: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct NewActionQuery {
    pub linked_risk_id: Option<String>,
    pub linked_soa_entry_id: Option<String>,
    pub linked_audit_finding_id: Option<String>,
    pub linked_incident_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateActionForm {
    pub reference_code: Option<String>,
    pub title: String,
    pub description: Option<String>,
    pub source_type: Option<String>,
    pub priority: String,
    pub due_date: Option<String>,
    pub assignee_user_id: Option<String>,
    pub owner_unit_id: Option<String>,
    pub recurrence_interval: Option<String>,
    pub linked_risk_id: Option<String>,
    pub linked_soa_entry_id: Option<String>,
    pub linked_audit_finding_id: Option<String>,
    pub linked_incident_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateActionForm {
    pub title: String,
    pub description: Option<String>,
    pub priority: String,
    pub status: String,
    pub due_date: Option<String>,
    pub assignee_user_id: Option<String>,
    pub owner_unit_id: Option<String>,
    pub recurrence_interval: Option<String>,
    pub verification_note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct QuickStatusForm {
    pub status: String,
    pub verification_note: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct QuickAssignForm {
    pub assignee_user_id: Option<String>,
}

#[derive(Template)]
#[template(path = "actions/list.html")]
struct ActionsListTemplate {
    actions: Vec<ActionRowView>,
    active_filter: String,
    filter_source_type: String,
    filter_priority: String,
    filter_q: String,
    open_count: i64,
    overdue_count: i64,
    review_count: i64,
    can_create: bool,
    can_edit_any: bool,
    is_employee: bool,
}

#[derive(Template)]
#[template(path = "actions/new_drawer.html")]
struct NewActionDrawerTemplate {
    default_source_type: String,
    default_due_date: String,
    linked_risk_id: String,
    linked_soa_entry_id: String,
    linked_audit_finding_id: String,
    linked_incident_id: String,
    users: Vec<SelectOption>,
    units: Vec<SelectOption>,
}

#[derive(Template)]
#[template(path = "actions/drawer.html")]
struct ActionDrawerTemplate {
    id: Uuid,
    reference_code: String,
    title: String,
    description: String,
    source_type_label: &'static str,
    priority_str: String,
    priority_label: &'static str,
    priority_css: &'static str,
    status_str: String,
    status_label: &'static str,
    status_css: &'static str,
    due_date_value: String,
    due_date_label: String,
    is_overdue: bool,
    recurrence_str: String,
    recurrence_label: String,
    recurrence_next_generated: bool,
    verification_note: String,
    verified_info: String,
    source_ref_label: String,
    source_ref_href: String,
    assignee_name: String,
    unit_name: String,
    can_edit: bool,
    can_verify_iso102: bool,
    users: Vec<SelectOption>,
    units: Vec<SelectOption>,
}

#[derive(Template)]
#[template(path = "actions/verify_modal.html")]
struct VerifyModalTemplate {
    id: Uuid,
    reference_code: String,
    title: String,
    source_type_label: &'static str,
    verification_note: String,
}

fn parse_optional_uuid(raw: Option<&str>) -> Result<Option<Uuid>, AppError> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        Some(v) => Uuid::parse_str(v)
            .map(Some)
            .map_err(|_| AppError::Validation(vec!["Ungültige UUID-Auswahl.".to_string()])),
        None => Ok(None),
    }
}

fn parse_optional_date(raw: Option<&str>) -> Result<Option<NaiveDate>, AppError> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        Some(v) => NaiveDate::parse_from_str(v, "%Y-%m-%d")
            .map(Some)
            .map_err(|_| AppError::Validation(vec!["Ungültiges Fälligkeitsdatum.".to_string()])),
        None => Ok(None),
    }
}

async fn load_user_options(
    pool: &sqlx::PgPool,
    selected: Option<Uuid>,
) -> Result<Vec<SelectOption>, AppError> {
    let rows = sqlx::query(
        "SELECT id, full_name, email FROM users WHERE is_active = TRUE ORDER BY full_name ASC",
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            let full_name: String = r.get("full_name");
            let email: String = r.get("email");
            SelectOption {
                id: id.to_string(),
                label: format!("{full_name} ({email})"),
                selected: selected == Some(id),
            }
        })
        .collect())
}

async fn load_unit_options(
    pool: &sqlx::PgPool,
    selected: Option<Uuid>,
) -> Result<Vec<SelectOption>, AppError> {
    let rows = sqlx::query("SELECT id, name FROM organization_units ORDER BY name ASC")
        .fetch_all(pool)
        .await?;

    Ok(rows
        .into_iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            SelectOption {
                id: id.to_string(),
                label: r.get("name"),
                selected: selected == Some(id),
            }
        })
        .collect())
}

fn format_source_link(
    risk_code: Option<String>,
    soa_code: Option<String>,
    finding_code: Option<String>,
    finding_audit_id: Option<Uuid>,
    incident_code: Option<String>,
    incident_id: Option<Uuid>,
) -> (String, String) {
    if let Some(code) = risk_code {
        return (code, "/risks".to_string());
    }
    if let Some(code) = soa_code {
        return (code, "/soa".to_string());
    }
    if let (Some(code), Some(audit_id)) = (finding_code, finding_audit_id) {
        return (code, format!("/audits/{audit_id}"));
    }
    if let (Some(code), Some(inc_id)) = (incident_code, incident_id) {
        return (code, format!("/incidents/{inc_id}"));
    }
    (String::new(), String::new())
}

pub async fn list_actions_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Query(query): Query<ActionFilterQuery>,
) -> Result<impl IntoResponse, AppError> {
    let active_filter = query.filter.unwrap_or_default().trim().to_string();
    let filter_source_type = query.source_type.unwrap_or_default().trim().to_string();
    let filter_priority = query.priority.unwrap_or_default().trim().to_string();
    let filter_q = query.q.unwrap_or_default().trim().to_string();
    let like_q = format!("%{filter_q}%");

    let is_employee = user.role == Role::Employee;
    let is_owner = user.role == Role::Owner;
    let owner_unit_id = user.organization_unit_id.unwrap_or_else(Uuid::nil);

    let kpi_row = sqlx::query(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE status IN ('open', 'in_progress', 'review')) AS open_count,
            COUNT(*) FILTER (
                WHERE status IN ('open', 'in_progress', 'review')
                  AND due_date < CURRENT_DATE
            ) AS overdue_count,
            COUNT(*) FILTER (WHERE status = 'review') AS review_count
        FROM action_items
        WHERE (NOT $1 OR assignee_user_id = $3)
          AND (NOT $2 OR owner_unit_id = $4 OR assignee_user_id = $3)
        "#,
    )
    .bind(is_employee)
    .bind(is_owner)
    .bind(user.id)
    .bind(owner_unit_id)
    .fetch_one(&state.pool)
    .await?;

    let rows = sqlx::query(
        r#"
        SELECT
            ai.id,
            ai.reference_code,
            ai.title,
            ai.source_type,
            ai.priority,
            ai.status,
            ai.due_date,
            ai.recurrence_interval,
            ai.linked_incident_id,
            COALESCE(u.full_name, 'Nicht zugewiesen') AS assignee_name,
            COALESCE(ou.name, 'Keine Einheit') AS unit_name,
            rs.reference_code AS risk_code,
            fc.code AS soa_code,
            af.finding_code AS finding_code,
            af.audit_id AS finding_audit_id,
            si.reference_code AS incident_code
        FROM action_items ai
        LEFT JOIN users u ON u.id = ai.assignee_user_id
        LEFT JOIN organization_units ou ON ou.id = ai.owner_unit_id
        LEFT JOIN risk_scenarios rs ON rs.id = ai.linked_risk_id
        LEFT JOIN soa_entries se ON se.id = ai.linked_soa_entry_id
        LEFT JOIN framework_controls fc ON fc.id = se.control_id
        LEFT JOIN audit_findings af ON af.id = ai.linked_audit_finding_id
        LEFT JOIN security_incidents si ON si.id = ai.linked_incident_id
        WHERE (NOT $1 OR ai.assignee_user_id = $3)
          AND (NOT $2 OR ai.owner_unit_id = $4 OR ai.assignee_user_id = $3)
          AND ($5 = '' OR ai.source_type = $5)
          AND ($6 = '' OR ai.priority = $6)
          AND ($7 = '' OR ai.reference_code ILIKE $8 OR ai.title ILIKE $8 OR COALESCE(ai.description, '') ILIKE $8)
          AND (
              $9 = ''
              OR ($9 = 'mine' AND ai.assignee_user_id = $3 AND ai.status NOT IN ('done', 'cancelled'))
              OR ($9 = 'overdue' AND ai.due_date < CURRENT_DATE AND ai.status NOT IN ('done', 'cancelled'))
              OR ($9 = 'open' AND ai.status IN ('open', 'in_progress'))
              OR ($9 = 'review' AND ai.status = 'review')
              OR ($9 = 'recurring' AND ai.recurrence_interval IS NOT NULL)
              OR ($9 = 'done' AND ai.status = 'done')
          )
        ORDER BY
            (ai.status IN ('done', 'cancelled')) ASC,
            (ai.due_date < CURRENT_DATE AND ai.status NOT IN ('done', 'cancelled')) DESC,
            ai.due_date ASC NULLS LAST,
            ai.created_at DESC
        "#,
    )
    .bind(is_employee)
    .bind(is_owner)
    .bind(user.id)
    .bind(owner_unit_id)
    .bind(&filter_source_type)
    .bind(&filter_priority)
    .bind(&filter_q)
    .bind(&like_q)
    .bind(&active_filter)
    .fetch_all(&state.pool)
    .await?;

    let today = Utc::now().date_naive();
    let can_close_iso102 = user.role.is_iso_or_admin();
    let mut actions = Vec::with_capacity(rows.len());

    for r in rows {
        let source_type = ActionSourceType::from_str(r.get::<&str, _>("source_type"))?;
        let priority = ActionPriority::from_str(r.get::<&str, _>("priority"))?;
        let status = ActionStatus::from_str(r.get::<&str, _>("status"))?;
        let due_date: Option<NaiveDate> = r.get("due_date");
        let is_overdue = due_date
            .map(|d| d < today && !matches!(status, ActionStatus::Done | ActionStatus::Cancelled))
            .unwrap_or(false);

        let recurrence_label = match r.get::<Option<String>, _>("recurrence_interval") {
            Some(ref s) => RecurrenceInterval::from_str(s)?.label().to_string(),
            None => String::new(),
        };

        let (source_ref_label, source_ref_href) = format_source_link(
            r.get("risk_code"),
            r.get("soa_code"),
            r.get("finding_code"),
            r.get("finding_audit_id"),
            r.get("incident_code"),
            r.get("linked_incident_id"),
        );

        let can_cycle_to_done = !source_type.requires_iso102_verification() || can_close_iso102;
        let next_status = status.next_cycle(can_cycle_to_done);
        let needs_verification_modal =
            source_type.requires_iso102_verification() && next_status == ActionStatus::Done;

        actions.push(ActionRowView {
            id: r.get("id"),
            reference_code: r.get("reference_code"),
            title: r.get("title"),
            source_type_str: source_type.as_str().to_string(),
            source_type_label: source_type.label(),
            priority_label: priority.label(),
            priority_css: priority.css_class(),
            status_str: status.as_str().to_string(),
            status_label: status.label(),
            status_css: status.css_class(),
            due_date_label: due_date
                .map(|d| d.format("%d.%m.%Y").to_string())
                .unwrap_or_else(|| "–".to_string()),
            is_overdue,
            assignee_name: r.get("assignee_name"),
            unit_name: r.get("unit_name"),
            recurrence_label,
            source_ref_label,
            source_ref_href,
            needs_verification_modal,
            next_status_str: next_status.as_str().to_string(),
        });
    }

    let can_create = matches!(user.role, Role::Admin | Role::Iso | Role::Owner);
    let can_edit_any = matches!(user.role, Role::Admin | Role::Iso | Role::Owner);
    let shell = ShellContext::from_user(
        &user,
        "Maßnahmen & CAPA",
        "Betrieb (PDCA & NIS2)",
        "actions",
    );

    render_page(
        &headers,
        shell,
        &ActionsListTemplate {
            actions,
            active_filter,
            filter_source_type,
            filter_priority,
            filter_q,
            open_count: kpi_row.get("open_count"),
            overdue_count: kpi_row.get("overdue_count"),
            review_count: kpi_row.get("review_count"),
            can_create,
            can_edit_any,
            is_employee,
        },
    )
}

pub async fn new_action_drawer_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<NewActionQuery>,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Mitarbeitende können keine Maßnahmen anlegen.".to_string(),
        ));
    }

    let linked_risk_id = query.linked_risk_id.unwrap_or_default().trim().to_string();
    let linked_soa_entry_id = query
        .linked_soa_entry_id
        .unwrap_or_default()
        .trim()
        .to_string();
    let linked_audit_finding_id = query
        .linked_audit_finding_id
        .unwrap_or_default()
        .trim()
        .to_string();
    let linked_incident_id = query
        .linked_incident_id
        .unwrap_or_default()
        .trim()
        .to_string();

    let default_source_type = if !linked_risk_id.is_empty() {
        "risk_treatment"
    } else if !linked_soa_entry_id.is_empty() {
        "soa_gap"
    } else if !linked_audit_finding_id.is_empty() {
        "audit_finding"
    } else if !linked_incident_id.is_empty() {
        "incident_capa"
    } else {
        "general"
    }
    .to_string();

    let default_due_date = (Utc::now().date_naive() + chrono::Duration::days(14))
        .format("%Y-%m-%d")
        .to_string();

    let users = load_user_options(&state.pool, Some(user.id)).await?;
    let units = load_unit_options(&state.pool, user.organization_unit_id).await?;

    render_template(&NewActionDrawerTemplate {
        default_source_type,
        default_due_date,
        linked_risk_id,
        linked_soa_entry_id,
        linked_audit_finding_id,
        linked_incident_id,
        users,
        units,
    })
}

pub async fn create_action_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Form(form): Form<CreateActionForm>,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Mitarbeitende können keine Maßnahmen anlegen.".to_string(),
        ));
    }

    let title = form.title.trim();
    if title.is_empty() {
        return Err(AppError::Validation(vec![
            "Der Titel der Maßnahme darf nicht leer sein.".to_string(),
        ]));
    }

    let source_type = match form.source_type.as_deref().map(str::trim) {
        Some(s) if !s.is_empty() => ActionSourceType::from_str(s)?,
        _ => ActionSourceType::General,
    };
    let priority = ActionPriority::from_str(&form.priority)?;
    let due_date = parse_optional_date(form.due_date.as_deref())?;
    let assignee_user_id = parse_optional_uuid(form.assignee_user_id.as_deref())?;
    let mut owner_unit_id = parse_optional_uuid(form.owner_unit_id.as_deref())?;
    if user.role == Role::Owner {
        owner_unit_id = user.organization_unit_id;
    }

    let recurrence_interval = match form.recurrence_interval.as_deref().map(str::trim) {
        Some(s) if !s.is_empty() => Some(RecurrenceInterval::from_str(s)?),
        _ => None,
    };

    let linked_risk_id = parse_optional_uuid(form.linked_risk_id.as_deref())?;
    let linked_soa_entry_id = parse_optional_uuid(form.linked_soa_entry_id.as_deref())?;
    let linked_audit_finding_id = parse_optional_uuid(form.linked_audit_finding_id.as_deref())?;
    let linked_incident_id = parse_optional_uuid(form.linked_incident_id.as_deref())?;

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;

    let reference_code = match form.reference_code.as_deref().map(str::trim) {
        Some(c) if !c.is_empty() => c.to_string(),
        _ => next_action_reference_code(&mut tx).await?,
    };

    let description = form
        .description
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    sqlx::query(
        r#"
        INSERT INTO action_items (
            reference_code,
            title,
            description,
            source_type,
            linked_risk_id,
            linked_soa_entry_id,
            linked_audit_finding_id,
            linked_incident_id,
            assignee_user_id,
            owner_unit_id,
            priority,
            status,
            due_date,
            recurrence_interval
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'open', $12, $13)
        "#,
    )
    .bind(&reference_code)
    .bind(title)
    .bind(description)
    .bind(source_type.as_str())
    .bind(linked_risk_id)
    .bind(linked_soa_entry_id)
    .bind(linked_audit_finding_id)
    .bind(linked_incident_id)
    .bind(assignee_user_id)
    .bind(owner_unit_id)
    .bind(priority.as_str())
    .bind(due_date)
    .bind(recurrence_interval.map(|r| r.as_str()))
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    if is_htmx_request(&headers) {
        return Ok(([("HX-Redirect", "/actions")], "").into_response());
    }
    Ok(Redirect::to("/actions").into_response())
}

pub async fn action_drawer_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let row = sqlx::query(
        r#"
        SELECT
            ai.*,
            COALESCE(u.full_name, 'Nicht zugewiesen') AS assignee_name,
            COALESCE(ou.name, 'Keine Einheit') AS unit_name,
            vu.full_name AS verified_by_name,
            rs.reference_code AS risk_code,
            fc.code AS soa_code,
            af.finding_code AS finding_code,
            af.audit_id AS finding_audit_id,
            si.reference_code AS incident_code
        FROM action_items ai
        LEFT JOIN users u ON u.id = ai.assignee_user_id
        LEFT JOIN organization_units ou ON ou.id = ai.owner_unit_id
        LEFT JOIN users vu ON vu.id = ai.verified_by_user_id
        LEFT JOIN risk_scenarios rs ON rs.id = ai.linked_risk_id
        LEFT JOIN soa_entries se ON se.id = ai.linked_soa_entry_id
        LEFT JOIN framework_controls fc ON fc.id = se.control_id
        LEFT JOIN audit_findings af ON af.id = ai.linked_audit_finding_id
        LEFT JOIN security_incidents si ON si.id = ai.linked_incident_id
        WHERE ai.id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Maßnahme nicht gefunden.".to_string()))?;

    let assignee_user_id: Option<Uuid> = row.get("assignee_user_id");
    let owner_unit_id: Option<Uuid> = row.get("owner_unit_id");
    ensure_action_read_access(&user, assignee_user_id, owner_unit_id)?;

    let source_type = ActionSourceType::from_str(row.get::<&str, _>("source_type"))?;
    let priority = ActionPriority::from_str(row.get::<&str, _>("priority"))?;
    let status = ActionStatus::from_str(row.get::<&str, _>("status"))?;
    let due_date: Option<NaiveDate> = row.get("due_date");
    let today = Utc::now().date_naive();
    let is_overdue = due_date
        .map(|d| d < today && !matches!(status, ActionStatus::Done | ActionStatus::Cancelled))
        .unwrap_or(false);

    let recurrence_str = row
        .get::<Option<String>, _>("recurrence_interval")
        .unwrap_or_default();
    let recurrence_label = if recurrence_str.is_empty() {
        "Einmalig".to_string()
    } else {
        RecurrenceInterval::from_str(&recurrence_str)?
            .label()
            .to_string()
    };

    let completed_at: Option<chrono::DateTime<Utc>> = row.get("completed_at");
    let verified_by_name: Option<String> = row.get("verified_by_name");
    let verified_info = match (verified_by_name, completed_at) {
        (Some(name), Some(ts)) => {
            format!("{name} am {}", ts.format("%d.%m.%Y %H:%M UTC"))
        }
        (Some(name), None) => name,
        _ => String::new(),
    };

    let (source_ref_label, source_ref_href) = format_source_link(
        row.get("risk_code"),
        row.get("soa_code"),
        row.get("finding_code"),
        row.get("finding_audit_id"),
        row.get("incident_code"),
        row.get("linked_incident_id"),
    );

    let can_edit = ensure_action_write_access(&user, assignee_user_id, owner_unit_id).is_ok();
    let can_verify_iso102 =
        !source_type.requires_iso102_verification() || user.role.is_iso_or_admin();
    let users = load_user_options(&state.pool, assignee_user_id).await?;
    let units = load_unit_options(&state.pool, owner_unit_id).await?;

    render_template(&ActionDrawerTemplate {
        id,
        reference_code: row.get("reference_code"),
        title: row.get("title"),
        description: row
            .get::<Option<String>, _>("description")
            .unwrap_or_default(),
        source_type_label: source_type.label(),
        priority_str: priority.as_str().to_string(),
        priority_label: priority.label(),
        priority_css: priority.css_class(),
        status_str: status.as_str().to_string(),
        status_label: status.label(),
        status_css: status.css_class(),
        due_date_value: due_date
            .map(|d| d.format("%Y-%m-%d").to_string())
            .unwrap_or_default(),
        due_date_label: due_date
            .map(|d| d.format("%d.%m.%Y").to_string())
            .unwrap_or_else(|| "–".to_string()),
        is_overdue,
        recurrence_str,
        recurrence_label,
        recurrence_next_generated: row.get("recurrence_next_generated"),
        verification_note: row
            .get::<Option<String>, _>("verification_note")
            .unwrap_or_default(),
        verified_info,
        source_ref_label,
        source_ref_href,
        assignee_name: row.get("assignee_name"),
        unit_name: row.get("unit_name"),
        can_edit,
        can_verify_iso102,
        users,
        units,
    })
}

pub async fn verify_modal_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if !user.role.is_iso_or_admin() {
        return Err(AppError::Forbidden(
            "Nur Admin oder ISB dürfen die Wirksamkeit einer CAPA bestätigen.".to_string(),
        ));
    }

    let row = sqlx::query(
        "SELECT reference_code, title, source_type, verification_note FROM action_items WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Maßnahme nicht gefunden.".to_string()))?;

    let source_type = ActionSourceType::from_str(row.get::<&str, _>("source_type"))?;

    render_template(&VerifyModalTemplate {
        id,
        reference_code: row.get("reference_code"),
        title: row.get("title"),
        source_type_label: source_type.label(),
        verification_note: row
            .get::<Option<String>, _>("verification_note")
            .unwrap_or_default(),
    })
}

pub async fn update_action_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<UpdateActionForm>,
) -> Result<impl IntoResponse, AppError> {
    let title = form.title.trim();
    if title.is_empty() {
        return Err(AppError::Validation(vec![
            "Der Titel der Maßnahme darf nicht leer sein.".to_string(),
        ]));
    }

    let priority = ActionPriority::from_str(&form.priority)?;
    let target_status = ActionStatus::from_str(&form.status)?;
    let due_date = parse_optional_date(form.due_date.as_deref())?;
    let assignee_user_id = parse_optional_uuid(form.assignee_user_id.as_deref())?;
    let owner_unit_id = parse_optional_uuid(form.owner_unit_id.as_deref())?;
    let recurrence_interval = match form.recurrence_interval.as_deref().map(str::trim) {
        Some(s) if !s.is_empty() => Some(RecurrenceInterval::from_str(s)?),
        _ => None,
    };

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;

    let existing = sqlx::query(
        r#"
        SELECT source_type, assignee_user_id, owner_unit_id, recurrence_next_generated
        FROM action_items
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::NotFound("Maßnahme nicht gefunden.".to_string()))?;

    let current_assignee: Option<Uuid> = existing.get("assignee_user_id");
    let current_unit: Option<Uuid> = existing.get("owner_unit_id");
    ensure_action_write_access(&user, current_assignee, current_unit)?;

    let source_type = ActionSourceType::from_str(existing.get::<&str, _>("source_type"))?;
    let verification_note = form
        .verification_note
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    validate_action_transition(
        &user,
        source_type,
        target_status,
        verification_note.as_deref(),
    )?;

    let effective_unit_id = if user.role == Role::Owner {
        current_unit.or(user.organization_unit_id)
    } else {
        owner_unit_id
    };

    let description = form
        .description
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    sqlx::query(
        r#"
        UPDATE action_items
        SET title = $2,
            description = $3,
            priority = $4,
            status = $5,
            due_date = $6,
            assignee_user_id = $7,
            owner_unit_id = $8,
            recurrence_interval = $9,
            verification_note = $10,
            completed_at = CASE WHEN $5 = 'done' THEN COALESCE(completed_at, NOW()) ELSE NULL END,
            verified_by_user_id = CASE WHEN $5 = 'done' THEN $11 ELSE NULL END,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(title)
    .bind(description)
    .bind(priority.as_str())
    .bind(target_status.as_str())
    .bind(due_date)
    .bind(assignee_user_id)
    .bind(effective_unit_id)
    .bind(recurrence_interval.map(|r| r.as_str()))
    .bind(verification_note)
    .bind(user.id)
    .execute(&mut *tx)
    .await?;

    if target_status == ActionStatus::Done {
        let _ = generate_next_recurrence_tx(&mut tx, id).await?;
    }

    tx.commit().await?;

    if is_htmx_request(&headers) {
        return Ok(([("HX-Redirect", "/actions")], "").into_response());
    }
    Ok(Redirect::to("/actions").into_response())
}

pub async fn quick_status_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<QuickStatusForm>,
) -> Result<impl IntoResponse, AppError> {
    let target_status = ActionStatus::from_str(&form.status)?;

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;
    let existing = sqlx::query(
        r#"
        SELECT source_type, assignee_user_id, owner_unit_id, verification_note
        FROM action_items
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::NotFound("Maßnahme nicht gefunden.".to_string()))?;

    let assignee: Option<Uuid> = existing.get("assignee_user_id");
    let unit: Option<Uuid> = existing.get("owner_unit_id");
    ensure_action_write_access(&user, assignee, unit)?;

    let source_type = ActionSourceType::from_str(existing.get::<&str, _>("source_type"))?;
    let existing_note: Option<String> = existing.get("verification_note");
    let effective_note = form
        .verification_note
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or(existing_note);

    validate_action_transition(&user, source_type, target_status, effective_note.as_deref())?;

    sqlx::query(
        r#"
        UPDATE action_items
        SET status = $2,
            verification_note = $3,
            completed_at = CASE WHEN $2 = 'done' THEN COALESCE(completed_at, NOW()) ELSE NULL END,
            verified_by_user_id = CASE WHEN $2 = 'done' THEN $4 ELSE NULL END,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(target_status.as_str())
    .bind(effective_note)
    .bind(user.id)
    .execute(&mut *tx)
    .await?;

    if target_status == ActionStatus::Done {
        let _ = generate_next_recurrence_tx(&mut tx, id).await?;
    }

    tx.commit().await?;

    if is_htmx_request(&headers) {
        return Ok(([("HX-Redirect", "/actions")], "").into_response());
    }
    Ok(Redirect::to("/actions").into_response())
}

pub async fn quick_assign_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<QuickAssignForm>,
) -> Result<impl IntoResponse, AppError> {
    let assignee_user_id = parse_optional_uuid(form.assignee_user_id.as_deref())?;

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;
    let existing = sqlx::query(
        "SELECT assignee_user_id, owner_unit_id FROM action_items WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::NotFound("Maßnahme nicht gefunden.".to_string()))?;

    ensure_action_write_access(
        &user,
        existing.get("assignee_user_id"),
        existing.get("owner_unit_id"),
    )?;

    sqlx::query("UPDATE action_items SET assignee_user_id = $2, updated_at = NOW() WHERE id = $1")
        .bind(id)
        .bind(assignee_user_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    if is_htmx_request(&headers) {
        return Ok(([("HX-Redirect", "/actions")], "").into_response());
    }
    Ok(Redirect::to("/actions").into_response())
}
