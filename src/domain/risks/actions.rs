use std::str::FromStr;

use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::IntoResponse,
};
use chrono::{DateTime, NaiveDate, Utc};
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    audit::AuditService,
    auth::rbac::{ClientIp, CurrentUser, Role, ensure_owner_scope, forbid_auditor},
    db::begin_audited_tx,
    domain::risks::{
        RiskRating, RiskStatus, TreatmentStrategy, risk_score, validate_acceptance_guard,
        validate_scale,
    },
    error::AppError,
    state::AppState,
    web::{hx_redirect_or_303, with_toast},
};

#[derive(Debug, Deserialize)]
pub struct RiskScenarioForm {
    pub reference_code: String,
    pub title: String,
    pub threat_description: String,
    pub vulnerability_description: Option<String>,
    pub affected_information_asset_id: Option<String>,
    pub affected_system_asset_id: Option<String>,
    pub owner_unit_id: Option<String>,
    pub owner_user_id: Option<String>,
    pub inherent_likelihood: i16,
    pub inherent_impact: i16,
    pub treatment_strategy: String,
    pub treatment_plan: Option<String>,
    pub acceptance_justification: Option<String>,
    pub residual_likelihood: i16,
    pub residual_impact: i16,
    pub status: String,
    pub next_review_due_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LinkControlForm {
    pub soa_entry_id: Uuid,
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

fn parse_optional_review_date(raw: Option<&str>) -> Result<Option<DateTime<Utc>>, AppError> {
    let trimmed = raw.map(str::trim).unwrap_or("");
    if trimmed.is_empty() {
        return Ok(None);
    }
    let date = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d").map_err(|_| {
        AppError::Validation(vec![
            "Ungültiges Review-Datum (Format JJJJ-MM-TT erwartet).".to_string(),
        ])
    })?;
    let dt = date
        .and_hms_opt(0, 0, 0)
        .ok_or_else(|| AppError::Validation(vec!["Ungültiges Review-Datum.".to_string()]))?;
    Ok(Some(DateTime::from_naive_utc_and_offset(dt, Utc)))
}

fn map_risk_db_error(err: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(ref db_err) = err
        && db_err.code().as_deref() == Some("23505")
    {
        return AppError::Validation(vec![
            "Der Referenz-Code existiert bereits im Risikoregister.".to_string(),
        ]);
    }
    AppError::Database(err)
}

pub async fn create_risk_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    client_ip: ClientIp,
    headers: HeaderMap,
    Form(form): Form<RiskScenarioForm>,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Keine Berechtigung zum Anlegen von Risikoszenarien.".to_string(),
        ));
    }

    let reference_code = form.reference_code.trim().to_string();
    let title = form.title.trim().to_string();
    let threat_description = form.threat_description.trim().to_string();
    if reference_code.is_empty() || reference_code.len() > 32 {
        return Err(AppError::Validation(vec![
            "Der Referenz-Code darf nicht leer und maximal 32 Zeichen lang sein.".to_string(),
        ]));
    }
    if title.is_empty() || title.len() > 200 {
        return Err(AppError::Validation(vec![
            "Der Titel darf nicht leer und maximal 200 Zeichen lang sein.".to_string(),
        ]));
    }
    if threat_description.is_empty() {
        return Err(AppError::Validation(vec![
            "Die Bedrohungsbeschreibung darf nicht leer sein.".to_string(),
        ]));
    }

    let inh_l = validate_scale(form.inherent_likelihood, "Brutto-Wahrscheinlichkeit")?;
    let inh_i = validate_scale(form.inherent_impact, "Brutto-Auswirkung")?;
    let res_l = validate_scale(form.residual_likelihood, "Netto-Wahrscheinlichkeit")?;
    let res_i = validate_scale(form.residual_impact, "Netto-Auswirkung")?;

    let strategy = TreatmentStrategy::from_str(&form.treatment_strategy)?;
    let status = RiskStatus::from_str(&form.status)?;

    let aff_ia_id = parse_optional_uuid(
        form.affected_information_asset_id.as_deref(),
        "Informationswert",
    )?;
    let aff_sa_id = parse_optional_uuid(form.affected_system_asset_id.as_deref(), "System-Asset")?;
    let owner_unit_id = parse_optional_uuid(form.owner_unit_id.as_deref(), "Organisationseinheit")?;
    let owner_user_id = parse_optional_uuid(form.owner_user_id.as_deref(), "Benutzer")?;
    let next_review_due_at = parse_optional_review_date(form.next_review_due_at.as_deref())?;

    if user.role == Role::Owner {
        ensure_owner_scope(&user, owner_unit_id, owner_user_id)?;
    }

    let residual_rating = RiskRating::from_score(risk_score(res_l, res_i));
    validate_acceptance_guard(
        &user,
        status,
        residual_rating,
        form.acceptance_justification.as_deref(),
    )?;

    let (accepted_by_user_id, accepted_at) = if status == RiskStatus::Accepted {
        (Some(user.id), Some(Utc::now()))
    } else {
        (None, None)
    };

    let vuln = form
        .vulnerability_description
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let plan = form
        .treatment_plan
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let justification = form
        .acceptance_justification
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip.0)).await?;
    sqlx::query(
        r#"
        INSERT INTO risk_scenarios (
            reference_code, title, threat_description, vulnerability_description,
            affected_information_asset_id, affected_system_asset_id,
            owner_unit_id, owner_user_id,
            inherent_likelihood, inherent_impact,
            treatment_strategy, treatment_plan, acceptance_justification,
            accepted_by_user_id, accepted_at,
            residual_likelihood, residual_impact, status, next_review_due_at
        )
        VALUES (
            $1, $2, $3, $4,
            $5, $6,
            $7, $8,
            $9, $10,
            $11, $12, $13,
            $14, $15,
            $16, $17, $18, $19
        )
        "#,
    )
    .bind(&reference_code)
    .bind(&title)
    .bind(&threat_description)
    .bind(&vuln)
    .bind(aff_ia_id)
    .bind(aff_sa_id)
    .bind(owner_unit_id)
    .bind(owner_user_id)
    .bind(inh_l)
    .bind(inh_i)
    .bind(strategy.as_str())
    .bind(&plan)
    .bind(&justification)
    .bind(accepted_by_user_id)
    .bind(accepted_at)
    .bind(res_l)
    .bind(res_i)
    .bind(status.as_str())
    .bind(next_review_due_at)
    .execute(&mut *tx)
    .await
    .map_err(map_risk_db_error)?;

    tx.commit().await?;
    Ok(with_toast(
        hx_redirect_or_303(&headers, "/risks"),
        "success",
        "Risikoszenario angelegt.",
    ))
}

pub async fn update_risk_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    client_ip: ClientIp,
    headers: HeaderMap,
    Path(risk_id): Path<Uuid>,
    Form(form): Form<RiskScenarioForm>,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Keine Berechtigung zum Bearbeiten von Risikoszenarien.".to_string(),
        ));
    }

    let existing = sqlx::query(
        r#"
        SELECT owner_unit_id, owner_user_id, status, residual_likelihood, residual_impact,
               accepted_by_user_id, accepted_at
        FROM risk_scenarios
        WHERE id = $1
        "#,
    )
    .bind(risk_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Risikoszenario nicht gefunden.".to_string()))?;

    let ex_unit: Option<Uuid> = existing.get("owner_unit_id");
    let ex_user: Option<Uuid> = existing.get("owner_user_id");
    let ex_status = RiskStatus::from_str(existing.get::<&str, _>("status"))?;
    let ex_res_l: i16 = existing.get("residual_likelihood");
    let ex_res_i: i16 = existing.get("residual_impact");
    let ex_acc_by: Option<Uuid> = existing.get("accepted_by_user_id");
    let ex_acc_at: Option<DateTime<Utc>> = existing.get("accepted_at");

    if user.role == Role::Owner {
        ensure_owner_scope(&user, ex_unit, ex_user)?;
    }

    let reference_code = form.reference_code.trim().to_string();
    let title = form.title.trim().to_string();
    let threat_description = form.threat_description.trim().to_string();
    if reference_code.is_empty() || reference_code.len() > 32 {
        return Err(AppError::Validation(vec![
            "Der Referenz-Code darf nicht leer und maximal 32 Zeichen lang sein.".to_string(),
        ]));
    }
    if title.is_empty() || title.len() > 200 {
        return Err(AppError::Validation(vec![
            "Der Titel darf nicht leer und maximal 200 Zeichen lang sein.".to_string(),
        ]));
    }
    if threat_description.is_empty() {
        return Err(AppError::Validation(vec![
            "Die Bedrohungsbeschreibung darf nicht leer sein.".to_string(),
        ]));
    }

    let inh_l = validate_scale(form.inherent_likelihood, "Brutto-Wahrscheinlichkeit")?;
    let inh_i = validate_scale(form.inherent_impact, "Brutto-Auswirkung")?;
    let res_l = validate_scale(form.residual_likelihood, "Netto-Wahrscheinlichkeit")?;
    let res_i = validate_scale(form.residual_impact, "Netto-Auswirkung")?;

    let strategy = TreatmentStrategy::from_str(&form.treatment_strategy)?;
    let requested_status = RiskStatus::from_str(&form.status)?;

    let aff_ia_id = parse_optional_uuid(
        form.affected_information_asset_id.as_deref(),
        "Informationswert",
    )?;
    let aff_sa_id = parse_optional_uuid(form.affected_system_asset_id.as_deref(), "System-Asset")?;
    let owner_unit_id = parse_optional_uuid(form.owner_unit_id.as_deref(), "Organisationseinheit")?;
    let owner_user_id = parse_optional_uuid(form.owner_user_id.as_deref(), "Benutzer")?;
    let next_review_due_at = parse_optional_review_date(form.next_review_due_at.as_deref())?;

    if user.role == Role::Owner {
        ensure_owner_scope(&user, owner_unit_id, owner_user_id)?;
    }

    let residual_increased = res_l > ex_res_l || res_i > ex_res_i;
    let (effective_status, accepted_by_user_id, accepted_at, toast_msg) =
        if ex_status == RiskStatus::Accepted && residual_increased {
            (
                RiskStatus::Assessed,
                None,
                None,
                "Restrisiko erhöht: Bestehende Akzeptanz wurde automatisch zurückgesetzt.",
            )
        } else {
            let residual_rating = RiskRating::from_score(risk_score(res_l, res_i));
            validate_acceptance_guard(
                &user,
                requested_status,
                residual_rating,
                form.acceptance_justification.as_deref(),
            )?;

            if requested_status == RiskStatus::Accepted {
                if ex_status == RiskStatus::Accepted && ex_acc_by.is_some() {
                    (
                        RiskStatus::Accepted,
                        ex_acc_by,
                        ex_acc_at,
                        "Risikoszenario aktualisiert.",
                    )
                } else {
                    (
                        RiskStatus::Accepted,
                        Some(user.id),
                        Some(Utc::now()),
                        "Risikoszenario akzeptiert und gespeichert.",
                    )
                }
            } else {
                (requested_status, None, None, "Risikoszenario aktualisiert.")
            }
        };

    let vuln = form
        .vulnerability_description
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let plan = form
        .treatment_plan
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let justification = form
        .acceptance_justification
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip.0)).await?;
    sqlx::query(
        r#"
        UPDATE risk_scenarios
        SET reference_code = $1,
            title = $2,
            threat_description = $3,
            vulnerability_description = $4,
            affected_information_asset_id = $5,
            affected_system_asset_id = $6,
            owner_unit_id = $7,
            owner_user_id = $8,
            inherent_likelihood = $9,
            inherent_impact = $10,
            treatment_strategy = $11,
            treatment_plan = $12,
            acceptance_justification = $13,
            accepted_by_user_id = $14,
            accepted_at = $15,
            residual_likelihood = $16,
            residual_impact = $17,
            status = $18,
            next_review_due_at = $19,
            updated_at = NOW()
        WHERE id = $20
        "#,
    )
    .bind(&reference_code)
    .bind(&title)
    .bind(&threat_description)
    .bind(&vuln)
    .bind(aff_ia_id)
    .bind(aff_sa_id)
    .bind(owner_unit_id)
    .bind(owner_user_id)
    .bind(inh_l)
    .bind(inh_i)
    .bind(strategy.as_str())
    .bind(&plan)
    .bind(&justification)
    .bind(accepted_by_user_id)
    .bind(accepted_at)
    .bind(res_l)
    .bind(res_i)
    .bind(effective_status.as_str())
    .bind(next_review_due_at)
    .bind(risk_id)
    .execute(&mut *tx)
    .await
    .map_err(map_risk_db_error)?;

    tx.commit().await?;
    Ok(with_toast(
        hx_redirect_or_303(&headers, "/risks"),
        "success",
        toast_msg,
    ))
}

pub async fn delete_risk_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    client_ip: ClientIp,
    headers: HeaderMap,
    Path(risk_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Keine Berechtigung zum Löschen von Risikoszenarien.".to_string(),
        ));
    }

    let existing =
        sqlx::query("SELECT owner_unit_id, owner_user_id FROM risk_scenarios WHERE id = $1")
            .bind(risk_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| AppError::NotFound("Risikoszenario nicht gefunden.".to_string()))?;

    if user.role == Role::Owner {
        ensure_owner_scope(
            &user,
            existing.get("owner_unit_id"),
            existing.get("owner_user_id"),
        )?;
    }

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip.0)).await?;
    sqlx::query("DELETE FROM risk_scenarios WHERE id = $1")
        .bind(risk_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(with_toast(
        hx_redirect_or_303(&headers, "/risks"),
        "success",
        "Risikoszenario gelöscht.",
    ))
}

pub async fn link_control_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    client_ip: ClientIp,
    headers: HeaderMap,
    Path(risk_id): Path<Uuid>,
    Form(form): Form<LinkControlForm>,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Keine Berechtigung zum Verknüpfen von Controls.".to_string(),
        ));
    }

    let existing = sqlx::query(
        "SELECT reference_code, owner_unit_id, owner_user_id FROM risk_scenarios WHERE id = $1",
    )
    .bind(risk_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Risikoszenario nicht gefunden.".to_string()))?;

    if user.role == Role::Owner {
        ensure_owner_scope(
            &user,
            existing.get("owner_unit_id"),
            existing.get("owner_user_id"),
        )?;
    }
    let ref_code: String = existing.get("reference_code");

    let ctrl_row = sqlx::query(
        r#"
        SELECT fc.code
        FROM soa_entries se
        JOIN framework_controls fc ON fc.id = se.control_id
        WHERE se.id = $1
        "#,
    )
    .bind(form.soa_entry_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("SoA-Control nicht gefunden.".to_string()))?;
    let ctrl_code: String = ctrl_row.get("code");

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip.0)).await?;
    let res = sqlx::query(
        r#"
        INSERT INTO risk_control_links (risk_id, soa_entry_id)
        VALUES ($1, $2)
        ON CONFLICT (risk_id, soa_entry_id) DO NOTHING
        "#,
    )
    .bind(risk_id)
    .bind(form.soa_entry_id)
    .execute(&mut *tx)
    .await?;

    if res.rows_affected() > 0 {
        let risk_id_str = risk_id.to_string();
        AuditService::log_event(
            &mut *tx,
            Some(user.id),
            Some(client_ip.0),
            "risk_control_links.linked",
            "risk_control_links",
            &risk_id_str,
            &format!("Control {ctrl_code} mit Risiko {ref_code} verknüpft"),
            None,
            Some(json!({
                "risk_id": risk_id,
                "soa_entry_id": form.soa_entry_id,
                "reference_code": ref_code,
                "control_code": ctrl_code,
            })),
        )
        .await?;
    }

    tx.commit().await?;
    Ok(with_toast(
        hx_redirect_or_303(&headers, "/risks"),
        "success",
        "Control verknüpft.",
    ))
}

pub async fn unlink_control_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    client_ip: ClientIp,
    headers: HeaderMap,
    Path((risk_id, soa_entry_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Keine Berechtigung zum Lösen von Control-Verknüpfungen.".to_string(),
        ));
    }

    let existing = sqlx::query(
        "SELECT reference_code, owner_unit_id, owner_user_id FROM risk_scenarios WHERE id = $1",
    )
    .bind(risk_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Risikoszenario nicht gefunden.".to_string()))?;

    if user.role == Role::Owner {
        ensure_owner_scope(
            &user,
            existing.get("owner_unit_id"),
            existing.get("owner_user_id"),
        )?;
    }
    let ref_code: String = existing.get("reference_code");

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip.0)).await?;
    let res =
        sqlx::query("DELETE FROM risk_control_links WHERE risk_id = $1 AND soa_entry_id = $2")
            .bind(risk_id)
            .bind(soa_entry_id)
            .execute(&mut *tx)
            .await?;

    if res.rows_affected() > 0 {
        let risk_id_str = risk_id.to_string();
        AuditService::log_event(
            &mut *tx,
            Some(user.id),
            Some(client_ip.0),
            "risk_control_links.unlinked",
            "risk_control_links",
            &risk_id_str,
            &format!("Control-Verknüpfung von Risiko {ref_code} gelöst"),
            Some(json!({
                "risk_id": risk_id,
                "soa_entry_id": soa_entry_id,
                "reference_code": ref_code,
            })),
            None,
        )
        .await?;
    }

    tx.commit().await?;
    Ok(with_toast(
        hx_redirect_or_303(&headers, "/risks"),
        "success",
        "Control-Verknüpfung gelöst.",
    ))
}
