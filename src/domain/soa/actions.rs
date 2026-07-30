use std::str::FromStr;

use axum::{
    extract::{Form, Multipart, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::NaiveDate;
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    auth::rbac::{ClientIp, CurrentUser, Role, ensure_owner_scope, forbid_auditor},
    db::begin_audited_tx,
    domain::soa::{
        EvidenceType, ImplementationStatus, validate_evidence_url, validate_section_anchor,
        validate_soa_justification, validate_verified_status_permission,
    },
    error::AppError,
    state::AppState,
    web::{hx_redirect_or_303, with_toast},
};

#[derive(Debug, Deserialize)]
pub struct UpdateSoaEntryForm {
    pub is_applicable: Option<String>,
    pub justification: Option<String>,
    pub implementation_status: String,
    pub implementation_notes: Option<String>,
    pub owner_unit_id: Option<String>,
    pub owner_user_id: Option<String>,
    pub target_date: Option<String>,
    pub redirect_framework: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ToggleApplicabilityForm {
    pub is_applicable: Option<String>,
    pub justification: Option<String>,
}

fn parse_optional_uuid(raw: Option<&str>) -> Result<Option<Uuid>, AppError> {
    let trimmed = raw.map(str::trim).unwrap_or("");
    if trimmed.is_empty() {
        return Ok(None);
    }
    Uuid::parse_str(trimmed)
        .map(Some)
        .map_err(|_| AppError::Validation(vec!["Ungültige UUID-Auswahl.".to_string()]))
}

fn parse_optional_date(raw: Option<&str>) -> Result<Option<NaiveDate>, AppError> {
    let trimmed = raw.map(str::trim).unwrap_or("");
    if trimmed.is_empty() {
        return Ok(None);
    }
    NaiveDate::parse_from_str(trimmed, "%Y-%m-%d")
        .map(Some)
        .map_err(|_| {
            AppError::Validation(vec![
                "Ungültiges Zieldatum (Format JJJJ-MM-TT erwartet).".to_string(),
            ])
        })
}

fn sanitize_download_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "nachweis.bin".to_string()
    } else {
        cleaned
    }
}

pub async fn update_soa_entry_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Path(soa_id): Path<Uuid>,
    Form(form): Form<UpdateSoaEntryForm>,
) -> Result<Response, AppError> {
    forbid_auditor(&user)?;

    let existing = sqlx::query(
        r#"
        SELECT se.owner_unit_id, se.owner_user_id, cf.code AS framework_code
        FROM soa_entries se
        JOIN framework_controls fc ON fc.id = se.control_id
        JOIN compliance_frameworks cf ON cf.id = fc.framework_id
        WHERE se.id = $1
        "#,
    )
    .bind(soa_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("SoA-Eintrag nicht gefunden.".to_string()))?;

    ensure_owner_scope(
        &user,
        existing.get("owner_unit_id"),
        existing.get("owner_user_id"),
    )?;

    let is_applicable = matches!(
        form.is_applicable.as_deref().map(str::trim),
        Some("true" | "1" | "on")
    );
    let justification = form.justification.unwrap_or_default().trim().to_string();
    validate_soa_justification(is_applicable, &justification)?;

    let status = ImplementationStatus::from_str(&form.implementation_status)?;
    validate_verified_status_permission(&user, status)?;

    let implementation_notes = form
        .implementation_notes
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let owner_unit_id = parse_optional_uuid(form.owner_unit_id.as_deref())?;
    let owner_user_id = parse_optional_uuid(form.owner_user_id.as_deref())?;
    let target_date = parse_optional_date(form.target_date.as_deref())?;

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;
    sqlx::query(
        r#"
        UPDATE soa_entries
        SET is_applicable = $2,
            justification = $3,
            implementation_status = $4,
            implementation_notes = $5,
            owner_unit_id = $6,
            owner_user_id = $7,
            target_date = $8,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(soa_id)
    .bind(is_applicable)
    .bind(&justification)
    .bind(status.as_str())
    .bind(&implementation_notes)
    .bind(owner_unit_id)
    .bind(owner_user_id)
    .bind(target_date)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let fw = form
        .redirect_framework
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| existing.get("framework_code"));
    let target = format!("/soa?framework={fw}");
    Ok(with_toast(
        hx_redirect_or_303(&headers, &target),
        "success",
        "SoA-Bewertung gespeichert.",
    ))
}

pub async fn cycle_status_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Path(soa_id): Path<Uuid>,
) -> Result<Response, AppError> {
    forbid_auditor(&user)?;

    let existing = sqlx::query(
        r#"
        SELECT se.implementation_status, se.owner_unit_id, se.owner_user_id, cf.code AS framework_code
        FROM soa_entries se
        JOIN framework_controls fc ON fc.id = se.control_id
        JOIN compliance_frameworks cf ON cf.id = fc.framework_id
        WHERE se.id = $1
        "#,
    )
    .bind(soa_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("SoA-Eintrag nicht gefunden.".to_string()))?;

    ensure_owner_scope(
        &user,
        existing.get("owner_unit_id"),
        existing.get("owner_user_id"),
    )?;

    let current = ImplementationStatus::from_str(existing.get::<&str, _>("implementation_status"))?;
    let next = current.next_for_role(user.role);
    validate_verified_status_permission(&user, next)?;

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;
    sqlx::query(
        r#"
        UPDATE soa_entries
        SET implementation_status = $2,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(soa_id)
    .bind(next.as_str())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let fw: String = existing.get("framework_code");
    let target = format!("/soa?framework={fw}");
    Ok(with_toast(
        hx_redirect_or_303(&headers, &target),
        "success",
        &format!("Status auf „{}“ aktualisiert.", next.label()),
    ))
}

pub async fn toggle_applicability_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Path(soa_id): Path<Uuid>,
    Form(form): Form<ToggleApplicabilityForm>,
) -> Result<Response, AppError> {
    forbid_auditor(&user)?;

    let existing = sqlx::query(
        r#"
        SELECT se.is_applicable, se.justification, se.owner_unit_id, se.owner_user_id, cf.code AS framework_code
        FROM soa_entries se
        JOIN framework_controls fc ON fc.id = se.control_id
        JOIN compliance_frameworks cf ON cf.id = fc.framework_id
        WHERE se.id = $1
        "#,
    )
    .bind(soa_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("SoA-Eintrag nicht gefunden.".to_string()))?;

    ensure_owner_scope(
        &user,
        existing.get("owner_unit_id"),
        existing.get("owner_user_id"),
    )?;

    let current_applicable: bool = existing.get("is_applicable");
    let target_applicable = match form.is_applicable.as_deref().map(str::trim) {
        Some("true" | "1" | "on") => true,
        Some("false" | "0") => false,
        _ => !current_applicable,
    };
    let justification = form
        .justification
        .unwrap_or_else(|| existing.get("justification"))
        .trim()
        .to_string();

    validate_soa_justification(target_applicable, &justification)?;

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;
    sqlx::query(
        r#"
        UPDATE soa_entries
        SET is_applicable = $2,
            justification = $3,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(soa_id)
    .bind(target_applicable)
    .bind(&justification)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let fw: String = existing.get("framework_code");
    let target = format!("/soa?framework={fw}");
    let msg = if target_applicable {
        "Control als anwendbar markiert."
    } else {
        "Control mit Begründung ausgeschlossen."
    };
    Ok(with_toast(
        hx_redirect_or_303(&headers, &target),
        "success",
        msg,
    ))
}

pub async fn create_evidence_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Path(soa_id): Path<Uuid>,
    mut multipart: Multipart,
) -> Result<Response, AppError> {
    forbid_auditor(&user)?;

    let existing = sqlx::query(
        r#"
        SELECT se.owner_unit_id, se.owner_user_id, cf.code AS framework_code
        FROM soa_entries se
        JOIN framework_controls fc ON fc.id = se.control_id
        JOIN compliance_frameworks cf ON cf.id = fc.framework_id
        WHERE se.id = $1
        "#,
    )
    .bind(soa_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("SoA-Eintrag nicht gefunden.".to_string()))?;

    ensure_owner_scope(
        &user,
        existing.get("owner_unit_id"),
        existing.get("owner_user_id"),
    )?;

    let mut title = String::new();
    let mut evidence_type_raw = String::new();
    let mut linked_document_id_raw = String::new();
    let mut section_anchor_raw = String::new();
    let mut section_label_raw = String::new();
    let mut evidence_url_raw = String::new();
    let mut evidence_note_raw = String::new();
    let mut uploaded_file: Option<(String, Option<String>, Vec<u8>)> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|err| AppError::Validation(vec![format!("Ungültiger Upload: {err}")]))?
    {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "title" => title = field.text().await.unwrap_or_default(),
            "evidence_type" => evidence_type_raw = field.text().await.unwrap_or_default(),
            "linked_document_id" => linked_document_id_raw = field.text().await.unwrap_or_default(),
            "section_anchor" => section_anchor_raw = field.text().await.unwrap_or_default(),
            "section_label" => section_label_raw = field.text().await.unwrap_or_default(),
            "evidence_url" => evidence_url_raw = field.text().await.unwrap_or_default(),
            "evidence_note" => evidence_note_raw = field.text().await.unwrap_or_default(),
            "file" => {
                let filename = field.file_name().unwrap_or("nachweis.bin").to_string();
                let content_type = field.content_type().map(str::to_string);
                let bytes = field.bytes().await.map_err(|err| {
                    AppError::Validation(vec![format!("Datei fehlerhaft: {err}")])
                })?;
                if !bytes.is_empty() {
                    uploaded_file = Some((filename, content_type, bytes.to_vec()));
                }
            }
            _ => {}
        }
    }

    let title = title.trim().to_string();
    if title.is_empty() {
        return Err(AppError::Validation(vec![
            "Bitte einen Titel für den Nachweis angeben.".to_string(),
        ]));
    }

    let evidence_type = EvidenceType::from_str(&evidence_type_raw)?;

    let mut file_storage_key: Option<String> = None;
    let mut original_filename: Option<String> = None;
    let mut file_sha256: Option<String> = None;
    let mut linked_document_id: Option<Uuid> = None;
    let mut section_anchor: Option<String> = None;
    let mut section_label: Option<String> = None;
    let mut evidence_url: Option<String> = None;
    let mut evidence_note: Option<String> = None;

    match evidence_type {
        EvidenceType::File => {
            let (filename, content_type, bytes) = uploaded_file.ok_or_else(|| {
                AppError::Validation(vec![
                    "Bitte wählen Sie eine Datei zum Hochladen aus.".to_string(),
                ])
            })?;
            let stored = state.storage.put(&bytes, content_type.as_deref()).await?;
            file_storage_key = Some(stored.storage_key);
            original_filename = Some(sanitize_download_filename(&filename));
            file_sha256 = Some(stored.sha256_hex);
        }
        EvidenceType::PolicyLink => {
            let doc_id = parse_optional_uuid(Some(&linked_document_id_raw))?.ok_or_else(|| {
                AppError::Validation(vec![
                    "Bitte ein verknüpftes Dokument auswählen.".to_string(),
                ])
            })?;
            let doc_exists: bool =
                sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM documents WHERE id = $1)")
                    .bind(doc_id)
                    .fetch_one(&state.pool)
                    .await?;
            if !doc_exists {
                return Err(AppError::NotFound(
                    "Verknüpftes Dokument nicht gefunden.".to_string(),
                ));
            }
            linked_document_id = Some(doc_id);
            section_anchor = validate_section_anchor(Some(&section_anchor_raw))?;
            let lbl = section_label_raw.trim();
            if !lbl.is_empty() {
                section_label = Some(lbl.to_string());
            }
        }
        EvidenceType::ExternalUrl => {
            let validated = validate_evidence_url(&evidence_url_raw, state.config.is_production())?;
            evidence_url = Some(validated);
        }
        EvidenceType::Note => {
            let note = evidence_note_raw.trim().to_string();
            if note.is_empty() {
                return Err(AppError::Validation(vec![
                    "Bitte eine Prüfnotiz eingeben.".to_string(),
                ]));
            }
            evidence_note = Some(note);
        }
    }

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;
    sqlx::query(
        r#"
        INSERT INTO control_evidences (
            soa_entry_id, title, evidence_type,
            file_storage_key, original_filename, file_sha256,
            linked_document_id, section_anchor, section_label,
            evidence_url, evidence_note, uploaded_by_user_id
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#,
    )
    .bind(soa_id)
    .bind(&title)
    .bind(evidence_type.as_str())
    .bind(&file_storage_key)
    .bind(&original_filename)
    .bind(&file_sha256)
    .bind(linked_document_id)
    .bind(&section_anchor)
    .bind(&section_label)
    .bind(&evidence_url)
    .bind(&evidence_note)
    .bind(user.id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let fw: String = existing.get("framework_code");
    let target = format!("/soa?framework={fw}");
    Ok(with_toast(
        hx_redirect_or_303(&headers, &target),
        "success",
        "Nachweis hinzugefügt.",
    ))
}

pub async fn verify_evidence_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Path((soa_id, evidence_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, AppError> {
    if !user.role.is_iso_or_admin() {
        return Err(AppError::Forbidden(
            "Nur Administratoren und ISBs dürfen Nachweise verifizieren.".to_string(),
        ));
    }

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;
    let updated = sqlx::query(
        r#"
        UPDATE control_evidences
        SET verified_by_user_id = $3,
            verified_at = NOW()
        WHERE id = $1 AND soa_entry_id = $2
        "#,
    )
    .bind(evidence_id)
    .bind(soa_id)
    .bind(user.id)
    .execute(&mut *tx)
    .await?;

    if updated.rows_affected() == 0 {
        return Err(AppError::NotFound("Nachweis nicht gefunden.".to_string()));
    }
    tx.commit().await?;

    let fw: Option<String> = sqlx::query_scalar(
        r#"
        SELECT cf.code
        FROM soa_entries se
        JOIN framework_controls fc ON fc.id = se.control_id
        JOIN compliance_frameworks cf ON cf.id = fc.framework_id
        WHERE se.id = $1
        "#,
    )
    .bind(soa_id)
    .fetch_optional(&state.pool)
    .await?;

    let target = fw
        .map(|code| format!("/soa?framework={code}"))
        .unwrap_or_else(|| "/soa".to_string());
    Ok(with_toast(
        hx_redirect_or_303(&headers, &target),
        "success",
        "Nachweis verifiziert.",
    ))
}

pub async fn delete_evidence_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Path((soa_id, evidence_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, AppError> {
    forbid_auditor(&user)?;

    let row = sqlx::query(
        r#"
        SELECT se.owner_unit_id, se.owner_user_id, ce.file_storage_key, cf.code AS framework_code
        FROM control_evidences ce
        JOIN soa_entries se ON se.id = ce.soa_entry_id
        JOIN framework_controls fc ON fc.id = se.control_id
        JOIN compliance_frameworks cf ON cf.id = fc.framework_id
        WHERE ce.id = $1 AND ce.soa_entry_id = $2
        "#,
    )
    .bind(evidence_id)
    .bind(soa_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Nachweis nicht gefunden.".to_string()))?;

    ensure_owner_scope(&user, row.get("owner_unit_id"), row.get("owner_user_id"))?;

    let storage_key: Option<String> = row.get("file_storage_key");
    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;
    sqlx::query("DELETE FROM control_evidences WHERE id = $1 AND soa_entry_id = $2")
        .bind(evidence_id)
        .bind(soa_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    if let Some(key) = storage_key {
        let _ = state.storage.delete(&key).await;
    }

    let fw: String = row.get("framework_code");
    let target = format!("/soa?framework={fw}");
    Ok(with_toast(
        hx_redirect_or_303(&headers, &target),
        "info",
        "Nachweis entfernt.",
    ))
}

pub async fn download_evidence_file_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    Path((soa_id, evidence_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, AppError> {
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Kein Zugriff auf SoA-Nachweise.".to_string(),
        ));
    }

    let row = sqlx::query(
        r#"
        SELECT evidence_type, file_storage_key, original_filename
        FROM control_evidences
        WHERE id = $1 AND soa_entry_id = $2
        "#,
    )
    .bind(evidence_id)
    .bind(soa_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Nachweis nicht gefunden.".to_string()))?;

    let ev_type = EvidenceType::from_str(row.get::<&str, _>("evidence_type"))?;
    if ev_type != EvidenceType::File {
        return Err(AppError::Validation(vec![
            "Dieser Nachweis enthält keine herunterladbare Datei.".to_string(),
        ]));
    }

    let key: String = row
        .get::<Option<String>, _>("file_storage_key")
        .ok_or_else(|| AppError::NotFound("Datei-Schlüssel fehlt.".to_string()))?;
    let filename = row
        .get::<Option<String>, _>("original_filename")
        .unwrap_or_else(|| "nachweis.bin".to_string());
    let bytes = state.storage.get(&key).await?;

    let safe_name = sanitize_download_filename(&filename);
    let mut response = (StatusCode::OK, bytes).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(val) = HeaderValue::from_str(&format!("attachment; filename=\"{safe_name}\"")) {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, val);
    }
    Ok(response)
}
