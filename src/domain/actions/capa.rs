use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect},
};
use chrono::{Duration, Utc};
use sqlx::Row;
use uuid::Uuid;

use crate::{
    auth::rbac::{ClientIp, CurrentUser, Role, forbid_auditor, is_htmx_request},
    db::begin_audited_tx,
    domain::actions::next_action_reference_code,
    error::AppError,
    state::AppState,
};

pub async fn create_incident_capa_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(incident_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Mitarbeitende können keine CAPA-Maßnahmen anlegen.".to_string(),
        ));
    }

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;

    let row = sqlx::query(
        r#"
        SELECT id, reference_code, title, severity, owner_unit_id, lead_handler_id, reported_by_user_id
        FROM security_incidents
        WHERE id = $1
        "#,
    )
    .bind(incident_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::NotFound("Sicherheitsvorfall nicht gefunden.".to_string()))?;

    let owner_unit_id: Option<Uuid> = row.get("owner_unit_id");
    let reported_by_user_id: Option<Uuid> = row.get("reported_by_user_id");
    if user.role == Role::Owner {
        let in_unit =
            user.organization_unit_id.is_some() && owner_unit_id == user.organization_unit_id;
        let is_reporter = reported_by_user_id == Some(user.id);
        if !in_unit && !is_reporter {
            return Err(AppError::Forbidden(
                "Kein Zugriff auf Vorfälle außerhalb Ihrer Organisationseinheit.".to_string(),
            ));
        }
    }

    let inc_code: String = row.get("reference_code");
    let inc_title: String = row.get("title");
    let severity: String = row.get("severity");
    let lead_handler_id: Option<Uuid> = row.get("lead_handler_id");

    let action_code = next_action_reference_code(&mut tx).await?;
    let action_title = format!("CAPA zu {inc_code}: {inc_title}");
    let description =
        format!("Korrektur- und Vorbeugungsmaßnahme (ISO 10.2) aus Sicherheitsvorfall {inc_code}.");
    let due_date = (Utc::now() + Duration::days(14)).date_naive();

    sqlx::query(
        r#"
        INSERT INTO action_items (
            reference_code,
            title,
            description,
            source_type,
            linked_incident_id,
            assignee_user_id,
            owner_unit_id,
            priority,
            status,
            due_date
        )
        VALUES ($1, $2, $3, 'incident_capa', $4, $5, $6, $7, 'open', $8)
        "#,
    )
    .bind(&action_code)
    .bind(action_title)
    .bind(description)
    .bind(incident_id)
    .bind(lead_handler_id)
    .bind(owner_unit_id)
    .bind(severity)
    .bind(due_date)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    if is_htmx_request(&headers) {
        return Ok(([("HX-Redirect", "/actions?source_type=incident_capa")], "").into_response());
    }
    Ok(Redirect::to("/actions?source_type=incident_capa").into_response())
}

pub async fn create_finding_capa_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path((audit_id, finding_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;
    if !user.role.is_iso_or_admin() {
        return Err(AppError::Forbidden(
            "Nur Admin oder ISB dürfen CAPA-Maßnahmen aus Audit-Feststellungen anlegen."
                .to_string(),
        ));
    }

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;

    let row = sqlx::query(
        r#"
        SELECT af.id, af.finding_code, af.finding_type, af.owner_unit_id, af.description, ia.audit_code
        FROM audit_findings af
        JOIN internal_audits ia ON ia.id = af.audit_id
        WHERE af.id = $1 AND af.audit_id = $2
        FOR UPDATE OF af
        "#,
    )
    .bind(finding_id)
    .bind(audit_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::NotFound("Audit-Feststellung nicht gefunden.".to_string()))?;

    let finding_code: String = row.get("finding_code");
    let audit_code: String = row.get("audit_code");
    let finding_type: String = row.get("finding_type");
    let owner_unit_id: Option<Uuid> = row.get("owner_unit_id");
    let finding_desc: String = row.get("description");

    let priority = match finding_type.as_str() {
        "major_nc" => "critical",
        "minor_nc" => "high",
        _ => "medium",
    };

    let action_code = next_action_reference_code(&mut tx).await?;
    let action_title = format!("CAPA zu {audit_code}/{finding_code}");
    let due_date = (Utc::now() + Duration::days(30)).date_naive();

    sqlx::query(
        r#"
        INSERT INTO action_items (
            reference_code,
            title,
            description,
            source_type,
            linked_audit_finding_id,
            owner_unit_id,
            priority,
            status,
            due_date
        )
        VALUES ($1, $2, $3, 'audit_finding', $4, $5, $6, 'open', $7)
        "#,
    )
    .bind(&action_code)
    .bind(action_title)
    .bind(finding_desc)
    .bind(finding_id)
    .bind(owner_unit_id)
    .bind(priority)
    .bind(due_date)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        UPDATE audit_findings
        SET status = 'action_planned',
            updated_at = NOW()
        WHERE id = $1 AND status = 'open'
        "#,
    )
    .bind(finding_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    if is_htmx_request(&headers) {
        return Ok(([("HX-Redirect", "/actions?source_type=audit_finding")], "").into_response());
    }
    Ok(Redirect::to("/actions?source_type=audit_finding").into_response())
}
