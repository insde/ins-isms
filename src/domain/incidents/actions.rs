use std::str::FromStr;

use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::IntoResponse,
};
use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    auth::rbac::{
        ClientIp, CurrentUser, RequireIsoOrAdmin, Role, ensure_owner_scope, forbid_auditor,
        is_htmx_request,
    },
    db::begin_audited_tx,
    domain::incidents::{
        IncidentSeverity, IncidentStatus, can_edit_incident_or_timeline, compute_nis2_deadlines,
        register::render_timeline_partial, validate_closure_guard,
    },
    error::AppError,
    state::AppState,
    web::{hx_redirect_or_303, with_toast},
};

#[derive(Debug, Deserialize)]
pub struct CreateIncidentForm {
    pub reference_code: Option<String>,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub affected_system_asset_id: Option<String>,
    pub owner_unit_id: Option<String>,
    pub lead_handler_id: Option<String>,
    pub detected_at: Option<String>,
    pub is_nis2_significant: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EmployeeReportForm {
    pub title: String,
    pub description: String,
    pub severity: Option<String>,
    pub affected_system_asset_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateIncidentForm {
    pub title: String,
    pub description: String,
    pub severity: String,
    pub status: String,
    pub affected_system_asset_id: Option<String>,
    pub owner_unit_id: Option<String>,
    pub lead_handler_id: Option<String>,
    pub detected_at: Option<String>,
    pub is_nis2_significant: Option<String>,
    pub bsi_ticket_reference: Option<String>,
    pub root_cause_analysis: Option<String>,
    pub lessons_learned: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Nis2SubmitForm {
    pub stage: String,
    pub bsi_ticket_reference: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TimelineEventForm {
    pub note: String,
    pub occurred_at: Option<String>,
}

fn parse_optional_uuid(raw: Option<&str>, field_label: &str) -> Result<Option<Uuid>, AppError> {
    let trimmed = raw.map(str::trim).unwrap_or("");
    if trimmed.is_empty() {
        return Ok(None);
    }
    Uuid::parse_str(trimmed)
        .map(Some)
        .map_err(|_| AppError::Validation(vec![format!("Ungültige {field_label}-ID.")]))
}

fn parse_optional_datetime(
    raw: Option<&str>,
    tz: chrono_tz::Tz,
) -> Result<Option<DateTime<Utc>>, AppError> {
    let trimmed = raw.map(str::trim).unwrap_or("");
    if trimmed.is_empty() {
        return Ok(None);
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Ok(Some(dt.with_timezone(&Utc)));
    }
    for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M"] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(trimmed, fmt)
            && let Some(local) = tz.from_local_datetime(&naive).earliest()
        {
            return Ok(Some(local.with_timezone(&Utc)));
        }
    }
    if let Ok(date) = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d")
        && let Some(naive) = date.and_hms_opt(0, 0, 0)
    {
        return Ok(Some(DateTime::from_naive_utc_and_offset(naive, Utc)));
    }
    Err(AppError::Validation(vec![
        "Ungültiges Datums-/Zeitformat.".to_string(),
    ]))
}

fn generate_reference_code() -> String {
    let year = Utc::now().format("%Y");
    let suffix = &Uuid::new_v4().simple().to_string()[..6].to_ascii_uppercase();
    format!("INC-{year}-{suffix}")
}

fn map_incident_db_error(err: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(ref db_err) = err
        && db_err.code().as_deref() == Some("23505")
    {
        return AppError::Validation(vec![
            "Der Referenz-Code existiert bereits im Vorfallsregister.".to_string(),
        ]);
    }
    AppError::Database(err)
}

pub async fn create_incident_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    client_ip: ClientIp,
    headers: HeaderMap,
    Form(form): Form<CreateIncidentForm>,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Bitte nutzen Sie das Mitarbeiter-Meldeformular (/incidents/report).".to_string(),
        ));
    }

    let title = form.title.trim().to_string();
    let description = form.description.trim().to_string();
    if title.is_empty() || title.len() > 255 {
        return Err(AppError::Validation(vec![
            "Der Titel darf nicht leer und maximal 255 Zeichen lang sein.".to_string(),
        ]));
    }
    if description.is_empty() {
        return Err(AppError::Validation(vec![
            "Die Vorfallsbeschreibung darf nicht leer sein.".to_string(),
        ]));
    }

    let reference_code = form
        .reference_code
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(generate_reference_code);
    if reference_code.len() > 32 {
        return Err(AppError::Validation(vec![
            "Der Referenz-Code darf maximal 32 Zeichen lang sein.".to_string(),
        ]));
    }

    let severity = IncidentSeverity::from_str(&form.severity)?;
    let affected_system_asset_id =
        parse_optional_uuid(form.affected_system_asset_id.as_deref(), "System-Asset")?;
    let mut owner_unit_id =
        parse_optional_uuid(form.owner_unit_id.as_deref(), "Organisationseinheit")?;
    let lead_handler_id = parse_optional_uuid(form.lead_handler_id.as_deref(), "Bearbeiter")?;
    let detected_at =
        parse_optional_datetime(form.detected_at.as_deref(), state.config.app_timezone)?
            .unwrap_or_else(Utc::now);

    if user.role == Role::Owner {
        if owner_unit_id.is_none() {
            owner_unit_id = user.organization_unit_id;
        }
        ensure_owner_scope(&user, owner_unit_id, Some(user.id))?;
    }

    let is_nis2_significant = if user.role.is_iso_or_admin() {
        form.is_nis2_significant.is_some()
    } else {
        if form.is_nis2_significant.is_some() {
            return Err(AppError::Forbidden(
                "Nur Admin oder ISB dürfen eine NIS2-Meldepflicht festlegen.".to_string(),
            ));
        }
        false
    };

    let deadlines = compute_nis2_deadlines(
        is_nis2_significant,
        detected_at,
        None,
        None,
        None,
        crate::domain::incidents::Nis2Deadlines::default(),
    );

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip.0)).await?;
    let incident_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO security_incidents (
            reference_code, title, description, severity, status,
            affected_system_asset_id, owner_unit_id, reported_by_user_id, lead_handler_id,
            detected_at, is_nis2_significant,
            early_warning_due_at, incident_report_due_at, final_report_due_at
        )
        VALUES ($1, $2, $3, $4, 'detected', $5, $6, $7, $8, $9, $10, $11, $12, $13)
        RETURNING id
        "#,
    )
    .bind(&reference_code)
    .bind(&title)
    .bind(&description)
    .bind(severity.as_str())
    .bind(affected_system_asset_id)
    .bind(owner_unit_id)
    .bind(user.id)
    .bind(lead_handler_id)
    .bind(detected_at)
    .bind(is_nis2_significant)
    .bind(deadlines.early_warning_due_at)
    .bind(deadlines.incident_report_due_at)
    .bind(deadlines.final_report_due_at)
    .fetch_one(&mut *tx)
    .await
    .map_err(map_incident_db_error)?;

    sqlx::query(
        r#"
        INSERT INTO incident_timeline_events (incident_id, occurred_at, author_id, note)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(incident_id)
    .bind(detected_at)
    .bind(user.id)
    .bind("Sicherheitsvorfall im Register erfasst.")
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(with_toast(
        hx_redirect_or_303(&headers, &format!("/incidents/{incident_id}")),
        "success",
        "Sicherheitsvorfall erfasst.",
    ))
}

pub async fn submit_employee_report_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    client_ip: ClientIp,
    headers: HeaderMap,
    Form(form): Form<EmployeeReportForm>,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;

    let title = form.title.trim().to_string();
    let description = form.description.trim().to_string();
    if title.is_empty() || title.len() > 255 {
        return Err(AppError::Validation(vec![
            "Bitte geben Sie eine kurze Zusammenfassung (max. 255 Zeichen) an.".to_string(),
        ]));
    }
    if description.is_empty() {
        return Err(AppError::Validation(vec![
            "Bitte beschreiben Sie, was passiert ist.".to_string(),
        ]));
    }

    let severity = match form
        .severity
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => IncidentSeverity::from_str(raw)?,
        None => IncidentSeverity::Medium,
    };
    let affected_system_asset_id =
        parse_optional_uuid(form.affected_system_asset_id.as_deref(), "System-Asset")?;
    let reference_code = generate_reference_code();
    let now = Utc::now();

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip.0)).await?;
    let incident_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO security_incidents (
            reference_code, title, description, severity, status,
            affected_system_asset_id, owner_unit_id, reported_by_user_id, detected_at
        )
        VALUES ($1, $2, $3, $4, 'detected', $5, $6, $7, $8)
        RETURNING id
        "#,
    )
    .bind(&reference_code)
    .bind(&title)
    .bind(&description)
    .bind(severity.as_str())
    .bind(affected_system_asset_id)
    .bind(user.organization_unit_id)
    .bind(user.id)
    .bind(now)
    .fetch_one(&mut *tx)
    .await
    .map_err(map_incident_db_error)?;

    sqlx::query(
        r#"
        INSERT INTO incident_timeline_events (incident_id, occurred_at, author_id, note)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(incident_id)
    .bind(now)
    .bind(user.id)
    .bind("Vorfallsmeldung über Meldeformular eingegangen.")
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    let target = format!("/incidents/{incident_id}");
    Ok(with_toast(
        hx_redirect_or_303(&headers, &target),
        "success",
        "Vorfallsmeldung erfolgreich übermittelt.",
    ))
}

pub async fn update_incident_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    client_ip: ClientIp,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<UpdateIncidentForm>,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;

    let existing = sqlx::query(
        r#"
        SELECT owner_unit_id, reported_by_user_id, lead_handler_id,
               detected_at, contained_at, resolved_at, is_nis2_significant,
               early_warning_due_at, early_warning_submitted_at,
               incident_report_due_at, incident_report_submitted_at,
               final_report_due_at, final_report_submitted_at
        FROM security_incidents
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Sicherheitsvorfall nicht gefunden".to_string()))?;

    let existing_unit: Option<Uuid> = existing.try_get("owner_unit_id")?;
    let existing_reporter: Option<Uuid> = existing.try_get("reported_by_user_id")?;
    let existing_lead: Option<Uuid> = existing.try_get("lead_handler_id")?;
    if !can_edit_incident_or_timeline(&user, existing_unit, existing_reporter, existing_lead) {
        return Err(AppError::Forbidden(
            "Keine Berechtigung zum Bearbeiten dieses Sicherheitsvorfalls.".to_string(),
        ));
    }

    let title = form.title.trim().to_string();
    let description = form.description.trim().to_string();
    if title.is_empty() || title.len() > 255 {
        return Err(AppError::Validation(vec![
            "Der Titel darf nicht leer und maximal 255 Zeichen lang sein.".to_string(),
        ]));
    }
    if description.is_empty() {
        return Err(AppError::Validation(vec![
            "Die Vorfallsbeschreibung darf nicht leer sein.".to_string(),
        ]));
    }

    let severity = IncidentSeverity::from_str(&form.severity)?;
    let status = IncidentStatus::from_str(&form.status)?;

    if user.role == Role::Owner && status == IncidentStatus::Closed {
        return Err(AppError::Forbidden(
            "Nur Admin oder ISB dürfen einen Sicherheitsvorfall abschließen.".to_string(),
        ));
    }

    let root_cause = form
        .root_cause_analysis
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);
    let lessons_learned = form
        .lessons_learned
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);

    validate_closure_guard(status, root_cause.as_deref(), lessons_learned.as_deref())?;

    let existing_detected: DateTime<Utc> = existing.try_get("detected_at")?;
    let detected_at =
        parse_optional_datetime(form.detected_at.as_deref(), state.config.app_timezone)?
            .unwrap_or(existing_detected);

    let existing_nis2: bool = existing.try_get("is_nis2_significant")?;
    let is_nis2_significant = if user.role.is_iso_or_admin() {
        form.is_nis2_significant.is_some()
    } else {
        existing_nis2
    };

    let early_sub: Option<DateTime<Utc>> = existing.try_get("early_warning_submitted_at")?;
    let report_sub: Option<DateTime<Utc>> = existing.try_get("incident_report_submitted_at")?;
    let final_sub: Option<DateTime<Utc>> = existing.try_get("final_report_submitted_at")?;
    let existing_early_due: Option<DateTime<Utc>> = existing.try_get("early_warning_due_at")?;
    let existing_report_due: Option<DateTime<Utc>> = existing.try_get("incident_report_due_at")?;
    let existing_final_due: Option<DateTime<Utc>> = existing.try_get("final_report_due_at")?;

    let deadlines = compute_nis2_deadlines(
        is_nis2_significant,
        detected_at,
        early_sub,
        report_sub,
        final_sub,
        crate::domain::incidents::Nis2Deadlines {
            early_warning_due_at: existing_early_due,
            incident_report_due_at: existing_report_due,
            final_report_due_at: existing_final_due,
        },
    );

    let affected_system_asset_id =
        parse_optional_uuid(form.affected_system_asset_id.as_deref(), "System-Asset")?;
    let owner_unit_id = if user.role.is_iso_or_admin() {
        parse_optional_uuid(form.owner_unit_id.as_deref(), "Organisationseinheit")?
    } else {
        existing_unit
    };
    let lead_handler_id = if user.role.is_iso_or_admin() {
        parse_optional_uuid(form.lead_handler_id.as_deref(), "Bearbeiter")?
    } else {
        existing_lead
    };
    let bsi_ticket = if user.role.is_iso_or_admin() {
        form.bsi_ticket_reference
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
    } else {
        None
    };

    let existing_contained: Option<DateTime<Utc>> = existing.try_get("contained_at")?;
    let existing_resolved: Option<DateTime<Utc>> = existing.try_get("resolved_at")?;
    let now = Utc::now();
    let contained_at = if status == IncidentStatus::Contained && existing_contained.is_none() {
        Some(now)
    } else {
        existing_contained
    };
    let resolved_at = if status == IncidentStatus::Closed {
        Some(existing_resolved.unwrap_or(now))
    } else {
        existing_resolved
    };

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip.0)).await?;
    sqlx::query(
        r#"
        UPDATE security_incidents
        SET title = $2,
            description = $3,
            severity = $4,
            status = $5,
            affected_system_asset_id = $6,
            owner_unit_id = $7,
            lead_handler_id = $8,
            detected_at = $9,
            contained_at = $10,
            resolved_at = $11,
            is_nis2_significant = $12,
            early_warning_due_at = $13,
            incident_report_due_at = $14,
            final_report_due_at = $15,
            bsi_ticket_reference = COALESCE($16, bsi_ticket_reference),
            root_cause_analysis = $17,
            lessons_learned = $18,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(&title)
    .bind(&description)
    .bind(severity.as_str())
    .bind(status.as_str())
    .bind(affected_system_asset_id)
    .bind(owner_unit_id)
    .bind(lead_handler_id)
    .bind(detected_at)
    .bind(contained_at)
    .bind(resolved_at)
    .bind(is_nis2_significant)
    .bind(deadlines.early_warning_due_at)
    .bind(deadlines.incident_report_due_at)
    .bind(deadlines.final_report_due_at)
    .bind(bsi_ticket)
    .bind(root_cause)
    .bind(lessons_learned)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    let msg = if status == IncidentStatus::Closed {
        "Sicherheitsvorfall abgeschlossen."
    } else {
        "Sicherheitsvorfall aktualisiert."
    };
    Ok(with_toast(
        hx_redirect_or_303(&headers, &format!("/incidents/{id}")),
        "success",
        msg,
    ))
}

pub async fn submit_nis2_report_handler(
    State(state): State<AppState>,
    RequireIsoOrAdmin(user): RequireIsoOrAdmin,
    client_ip: ClientIp,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<Nis2SubmitForm>,
) -> Result<impl IntoResponse, AppError> {
    let existing = sqlx::query(
        r#"
        SELECT detected_at, early_warning_due_at, early_warning_submitted_at,
               incident_report_due_at, incident_report_submitted_at,
               final_report_due_at, final_report_submitted_at
        FROM security_incidents
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Sicherheitsvorfall nicht gefunden".to_string()))?;

    let detected_at: DateTime<Utc> = existing.try_get("detected_at")?;
    let mut early_sub: Option<DateTime<Utc>> = existing.try_get("early_warning_submitted_at")?;
    let mut report_sub: Option<DateTime<Utc>> = existing.try_get("incident_report_submitted_at")?;
    let mut final_sub: Option<DateTime<Utc>> = existing.try_get("final_report_submitted_at")?;
    let existing_early_due: Option<DateTime<Utc>> = existing.try_get("early_warning_due_at")?;
    let existing_report_due: Option<DateTime<Utc>> = existing.try_get("incident_report_due_at")?;
    let existing_final_due: Option<DateTime<Utc>> = existing.try_get("final_report_due_at")?;

    let now = Utc::now();
    let stage_note = match form.stage.trim() {
        "early_warning" => {
            if early_sub.is_none() {
                early_sub = Some(now);
            }
            "BSI-Frühwarnung (24h, § 32 BSIG) als eingereicht markiert."
        }
        "incident_report" => {
            if report_sub.is_none() {
                report_sub = Some(now);
            }
            "BSI-Vorfallsmeldung (72h, § 32 BSIG) als eingereicht markiert."
        }
        "final_report" => {
            if report_sub.is_none() {
                return Err(AppError::Validation(vec![
                    "Bitte zuerst die 72h-Vorfallsmeldung als eingereicht erfassen.".to_string(),
                ]));
            }
            if final_sub.is_none() {
                final_sub = Some(now);
            }
            "BSI-Abschlussbericht (30d, § 32 BSIG) als eingereicht markiert."
        }
        other => {
            return Err(AppError::Validation(vec![format!(
                "Ungültige NIS2-Meldestufe: {other}"
            )]));
        }
    };

    let deadlines = compute_nis2_deadlines(
        true,
        detected_at,
        early_sub,
        report_sub,
        final_sub,
        crate::domain::incidents::Nis2Deadlines {
            early_warning_due_at: existing_early_due,
            incident_report_due_at: existing_report_due,
            final_report_due_at: existing_final_due,
        },
    );

    let bsi_ticket = form
        .bsi_ticket_reference
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip.0)).await?;
    sqlx::query(
        r#"
        UPDATE security_incidents
        SET is_nis2_significant = TRUE,
            early_warning_due_at = $2,
            early_warning_submitted_at = $3,
            incident_report_due_at = $4,
            incident_report_submitted_at = $5,
            final_report_due_at = $6,
            final_report_submitted_at = $7,
            bsi_ticket_reference = COALESCE($8, bsi_ticket_reference),
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(deadlines.early_warning_due_at)
    .bind(early_sub)
    .bind(deadlines.incident_report_due_at)
    .bind(report_sub)
    .bind(deadlines.final_report_due_at)
    .bind(final_sub)
    .bind(bsi_ticket)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO incident_timeline_events (incident_id, occurred_at, author_id, note)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(id)
    .bind(now)
    .bind(user.id)
    .bind(stage_note)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(with_toast(
        hx_redirect_or_303(&headers, &format!("/incidents/{id}")),
        "success",
        stage_note,
    ))
}

pub async fn add_timeline_event_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    client_ip: ClientIp,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<TimelineEventForm>,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;

    let row = sqlx::query(
        "SELECT owner_unit_id, reported_by_user_id, lead_handler_id FROM security_incidents WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Sicherheitsvorfall nicht gefunden".to_string()))?;

    let owner_unit: Option<Uuid> = row.try_get("owner_unit_id")?;
    let reporter: Option<Uuid> = row.try_get("reported_by_user_id")?;
    let lead: Option<Uuid> = row.try_get("lead_handler_id")?;
    if !can_edit_incident_or_timeline(&user, owner_unit, reporter, lead) {
        return Err(AppError::Forbidden(
            "Keine Berechtigung zum Ergänzen der Einsatz-Timeline.".to_string(),
        ));
    }

    let note = form.note.trim().to_string();
    if note.is_empty() {
        return Err(AppError::Validation(vec![
            "Der Timeline-Eintrag darf nicht leer sein.".to_string(),
        ]));
    }

    let occurred_at =
        parse_optional_datetime(form.occurred_at.as_deref(), state.config.app_timezone)?
            .unwrap_or_else(Utc::now);

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip.0)).await?;
    sqlx::query(
        r#"
        INSERT INTO incident_timeline_events (incident_id, occurred_at, author_id, note)
        VALUES ($1, $2, $3, $4)
        "#,
    )
    .bind(id)
    .bind(occurred_at)
    .bind(user.id)
    .bind(&note)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    if is_htmx_request(&headers) {
        let html = render_timeline_partial(&state.pool, id).await?;
        return Ok(with_toast(
            html.into_response(),
            "success",
            "Timeline-Eintrag hinzugefügt.",
        ));
    }

    Ok(with_toast(
        hx_redirect_or_303(&headers, &format!("/incidents/{id}")),
        "success",
        "Timeline-Eintrag hinzugefügt.",
    ))
}
