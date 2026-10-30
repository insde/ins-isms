use std::collections::HashMap;
use std::str::FromStr;

use askama::Template;
use axum::{
    extract::{Multipart, State},
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::{
    audit::AuditService,
    auth::rbac::{ClientIp, RequireIsoOrAdmin},
    db::begin_audited_tx,
    domain::soa::MappingType,
    error::AppError,
    state::AppState,
    web::{render_template, with_toast},
};

#[derive(Debug, Deserialize)]
pub struct CatalogImportPayload {
    pub framework: CatalogFrameworkInput,
    pub controls: Vec<CatalogControlInput>,
    #[serde(default)]
    pub mappings: Vec<CatalogMappingInput>,
}

#[derive(Debug, Deserialize)]
pub struct CatalogFrameworkInput {
    pub code: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Deserialize)]
pub struct CatalogControlInput {
    pub code: String,
    pub domain: String,
    pub title: String,
    pub description: String,
    pub audit_question: Option<String>,
    pub default_not_applicable_reason: Option<String>,
    #[serde(default)]
    pub sort_order: i32,
}

#[derive(Debug, Deserialize)]
pub struct CatalogMappingInput {
    pub source_framework_code: String,
    pub source_control_code: String,
    pub target_framework_code: String,
    pub target_control_code: String,
    #[serde(default = "default_mapping_type")]
    pub mapping_type: String,
}

fn default_mapping_type() -> String {
    "equivalent".to_string()
}

#[derive(Template)]
#[template(path = "exports/catalog_result.html")]
struct CatalogImportResultTemplate {
    framework_code: String,
    framework_name: String,
    framework_version: String,
    created_controls: usize,
    updated_controls: usize,
    mappings_upserted: usize,
    file_sha256: String,
}

#[derive(Debug)]
struct ValidatedCatalog {
    framework_code: String,
    framework_name: String,
    framework_version: String,
    controls: Vec<CatalogControlInput>,
    mappings: Vec<(CatalogMappingInput, MappingType)>,
}

fn contains_disallowed_placeholder(text: &str) -> bool {
    let lower = text.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return true;
    }
    const FORBIDDEN_MARKERS: &[&str] = &[
        "todo",
        "tbd",
        "placeholder",
        "lorem ipsum",
        "© iso",
        "copyright iso",
        "iso/iec 27001 originaltext",
        "din en iso",
        "hier normtext einfügen",
    ];
    FORBIDDEN_MARKERS.iter().any(|m| lower.contains(m))
}

fn parse_catalog_bytes(filename: &str, bytes: &[u8]) -> Result<CatalogImportPayload, AppError> {
    let raw_text = std::str::from_utf8(bytes).map_err(|_| {
        AppError::Validation(vec![
            "Die Katalogdatei muss gültiges UTF-8 sein.".to_string(),
        ])
    })?;
    let text = raw_text.strip_prefix('\u{FEFF}').unwrap_or(raw_text).trim();
    if text.is_empty() {
        return Err(AppError::Validation(vec![
            "Die hochgeladene Katalogdatei ist leer.".to_string(),
        ]));
    }

    let lower_name = filename.to_ascii_lowercase();
    if lower_name.ends_with(".yaml") || lower_name.ends_with(".yml") {
        serde_yml::from_str::<CatalogImportPayload>(text)
            .map_err(|e| AppError::Validation(vec![format!("Ungültiges YAML-Katalogformat: {e}")]))
    } else if lower_name.ends_with(".json") {
        serde_json::from_str::<CatalogImportPayload>(text)
            .map_err(|e| AppError::Validation(vec![format!("Ungültiges JSON-Katalogformat: {e}")]))
    } else if text.starts_with('{') {
        serde_json::from_str::<CatalogImportPayload>(text)
            .map_err(|e| AppError::Validation(vec![format!("Ungültiges JSON-Katalogformat: {e}")]))
    } else {
        serde_yml::from_str::<CatalogImportPayload>(text).map_err(|e| {
            AppError::Validation(vec![format!(
                "Ungültiges Katalogformat (erwartet JSON oder YAML): {e}"
            )])
        })
    }
}

fn validate_catalog(payload: CatalogImportPayload) -> Result<ValidatedCatalog, AppError> {
    let mut errors = Vec::new();

    let fw_code = payload.framework.code.trim().to_string();
    let fw_name = payload.framework.name.trim().to_string();
    let fw_version = payload.framework.version.trim().to_string();

    if fw_code.is_empty() || fw_code.len() > 32 {
        errors.push("Framework-Code muss zwischen 1 und 32 Zeichen lang sein.".to_string());
    } else if !fw_code
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        errors.push(
            "Framework-Code darf nur ASCII-Buchstaben, Ziffern, '_', '-' oder '.' enthalten."
                .to_string(),
        );
    }

    if fw_name.is_empty() || fw_name.len() > 150 {
        errors.push("Framework-Name darf nicht leer sein (max. 150 Zeichen).".to_string());
    }
    if fw_version.is_empty() || fw_version.len() > 32 {
        errors.push("Framework-Version darf nicht leer sein (max. 32 Zeichen).".to_string());
    }
    if payload.controls.is_empty() {
        errors.push("Der Katalog muss mindestens ein Control enthalten.".to_string());
    }

    let mut seen_codes = std::collections::HashSet::new();
    let mut cleaned_controls = Vec::with_capacity(payload.controls.len());
    for (idx, mut ctrl) in payload.controls.into_iter().enumerate() {
        let row_no = idx + 1;
        ctrl.code = ctrl.code.trim().to_string();
        ctrl.domain = ctrl.domain.trim().to_string();
        ctrl.title = ctrl.title.trim().to_string();
        ctrl.description = ctrl.description.trim().to_string();

        if ctrl.code.is_empty() || ctrl.code.len() > 32 {
            errors.push(format!(
                "Control #{row_no}: Code muss 1 bis 32 Zeichen lang sein."
            ));
        } else if !seen_codes.insert(ctrl.code.clone()) {
            errors.push(format!(
                "Control #{row_no}: Doppelter Control-Code '{}'.",
                ctrl.code
            ));
        }
        if ctrl.domain.is_empty() || ctrl.domain.len() > 100 {
            errors.push(format!(
                "Control #{row_no} ({}): Domain darf nicht leer sein (max. 100 Zeichen).",
                ctrl.code
            ));
        }
        if ctrl.title.is_empty() || ctrl.title.len() > 255 {
            errors.push(format!(
                "Control #{row_no} ({}): Titel darf nicht leer sein (max. 255 Zeichen).",
                ctrl.code
            ));
        }
        if contains_disallowed_placeholder(&ctrl.description) || ctrl.description.len() < 10 {
            errors.push(format!(
                "Control #{row_no} ({}): Beschreibung ist leer, zu kurz oder enthält unzulässige Platzhalter/Normtext-Marker.",
                ctrl.code
            ));
        }
        if contains_disallowed_placeholder(&ctrl.title) {
            errors.push(format!(
                "Control #{row_no} ({}): Titel enthält unzulässige Platzhalter.",
                ctrl.code
            ));
        }
        if ctrl.sort_order == 0 {
            ctrl.sort_order = row_no as i32;
        }
        cleaned_controls.push(ctrl);
    }

    let mut validated_mappings = Vec::with_capacity(payload.mappings.len());
    for (idx, mut m) in payload.mappings.into_iter().enumerate() {
        let row_no = idx + 1;
        m.source_framework_code = m.source_framework_code.trim().to_string();
        m.source_control_code = m.source_control_code.trim().to_string();
        m.target_framework_code = m.target_framework_code.trim().to_string();
        m.target_control_code = m.target_control_code.trim().to_string();

        if m.source_framework_code.is_empty()
            || m.source_control_code.is_empty()
            || m.target_framework_code.is_empty()
            || m.target_control_code.is_empty()
        {
            errors.push(format!(
                "Mapping #{row_no}: Quell- und Ziel-Framework/Control-Code dürfen nicht leer sein."
            ));
            continue;
        }
        if m.source_framework_code == m.target_framework_code
            && m.source_control_code == m.target_control_code
        {
            errors.push(format!(
                "Mapping #{row_no}: Quell- und Ziel-Control dürfen nicht identisch sein."
            ));
            continue;
        }
        match MappingType::from_str(&m.mapping_type) {
            Ok(mt) => validated_mappings.push((m, mt)),
            Err(_) => errors.push(format!(
                "Mapping #{row_no}: Ungültiger Mapping-Typ '{}'.",
                m.mapping_type
            )),
        }
    }

    if !errors.is_empty() {
        return Err(AppError::Validation(errors));
    }

    Ok(ValidatedCatalog {
        framework_code: fw_code,
        framework_name: fw_name,
        framework_version: fw_version,
        controls: cleaned_controls,
        mappings: validated_mappings,
    })
}

pub async fn import_catalog_handler(
    State(state): State<AppState>,
    RequireIsoOrAdmin(user): RequireIsoOrAdmin,
    ClientIp(client_ip): ClientIp,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut filename = String::from("catalog.json");

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::BadRequest(format!("Ungültiger Multipart-Upload: {e}")))?
    {
        if field.name() == Some("file") {
            if let Some(name) = field.file_name()
                && !name.trim().is_empty()
            {
                filename = name.trim().to_string();
            }
            let bytes = field.bytes().await.map_err(|e| {
                AppError::BadRequest(format!("Datei konnte nicht gelesen werden: {e}"))
            })?;
            if bytes.len() > state.config.max_upload_bytes {
                return Err(AppError::Validation(vec![format!(
                    "Katalogdatei überschreitet das Upload-Limit von {} Bytes.",
                    state.config.max_upload_bytes
                )]));
            }
            file_bytes = Some(bytes.to_vec());
        }
    }

    let raw_bytes = file_bytes.ok_or_else(|| {
        AppError::Validation(vec![
            "Bitte eine JSON- oder YAML-Katalogdatei auswählen.".to_string(),
        ])
    })?;

    let mut hasher = Sha256::new();
    hasher.update(&raw_bytes);
    let file_sha256 = hex::encode(hasher.finalize());

    let parsed = parse_catalog_bytes(&filename, &raw_bytes)?;
    let catalog = validate_catalog(parsed)?;

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;

    let framework_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO compliance_frameworks (code, name, version, is_active)
        VALUES ($1, $2, $3, TRUE)
        ON CONFLICT (code) DO UPDATE
        SET name = EXCLUDED.name,
            version = EXCLUDED.version,
            is_active = TRUE
        RETURNING id
        "#,
    )
    .bind(&catalog.framework_code)
    .bind(&catalog.framework_name)
    .bind(&catalog.framework_version)
    .fetch_one(&mut *tx)
    .await?;

    let existing_rows =
        sqlx::query("SELECT id, code FROM framework_controls WHERE framework_id = $1")
            .bind(framework_id)
            .fetch_all(&mut *tx)
            .await?;
    let mut existing_codes: HashMap<String, Uuid> = existing_rows
        .into_iter()
        .map(|r| (r.get::<String, _>("code"), r.get::<Uuid, _>("id")))
        .collect();

    let mut created_controls = 0usize;
    let mut updated_controls = 0usize;

    for ctrl in &catalog.controls {
        let was_existing = existing_codes.contains_key(&ctrl.code);
        let control_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO framework_controls (
                framework_id, code, domain, title, description,
                audit_question, default_not_applicable_reason, sort_order
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (framework_id, code) DO UPDATE
            SET domain = EXCLUDED.domain,
                title = EXCLUDED.title,
                description = EXCLUDED.description,
                audit_question = EXCLUDED.audit_question,
                default_not_applicable_reason = EXCLUDED.default_not_applicable_reason,
                sort_order = EXCLUDED.sort_order
            RETURNING id
            "#,
        )
        .bind(framework_id)
        .bind(&ctrl.code)
        .bind(&ctrl.domain)
        .bind(&ctrl.title)
        .bind(&ctrl.description)
        .bind(
            ctrl.audit_question
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty()),
        )
        .bind(
            ctrl.default_not_applicable_reason
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty()),
        )
        .bind(ctrl.sort_order)
        .fetch_one(&mut *tx)
        .await?;

        if was_existing {
            updated_controls += 1;
        } else {
            created_controls += 1;
            existing_codes.insert(ctrl.code.clone(), control_id);
        }

        sqlx::query(
            "INSERT INTO soa_entries (control_id) VALUES ($1) ON CONFLICT (control_id) DO NOTHING",
        )
        .bind(control_id)
        .execute(&mut *tx)
        .await?;
    }

    let mut mappings_upserted = 0usize;
    for (mapping, mapping_type) in &catalog.mappings {
        let source_id: Option<Uuid> = sqlx::query_scalar(
            r#"
            SELECT fc.id
            FROM framework_controls fc
            JOIN compliance_frameworks cf ON cf.id = fc.framework_id
            WHERE cf.code = $1 AND fc.code = $2
            "#,
        )
        .bind(&mapping.source_framework_code)
        .bind(&mapping.source_control_code)
        .fetch_optional(&mut *tx)
        .await?;

        let target_id: Option<Uuid> = sqlx::query_scalar(
            r#"
            SELECT fc.id
            FROM framework_controls fc
            JOIN compliance_frameworks cf ON cf.id = fc.framework_id
            WHERE cf.code = $1 AND fc.code = $2
            "#,
        )
        .bind(&mapping.target_framework_code)
        .bind(&mapping.target_control_code)
        .fetch_optional(&mut *tx)
        .await?;

        let (Some(src), Some(tgt)) = (source_id, target_id) else {
            return Err(AppError::Validation(vec![format!(
                "Mapping-Ziel nicht gefunden: {}:{} -> {}:{}",
                mapping.source_framework_code,
                mapping.source_control_code,
                mapping.target_framework_code,
                mapping.target_control_code
            )]));
        };

        sqlx::query(
            r#"
            INSERT INTO control_mappings (source_control_id, target_control_id, mapping_type)
            VALUES ($1, $2, $3)
            ON CONFLICT (source_control_id, target_control_id) DO UPDATE
            SET mapping_type = EXCLUDED.mapping_type
            "#,
        )
        .bind(src)
        .bind(tgt)
        .bind(mapping_type.as_str())
        .execute(&mut *tx)
        .await?;

        mappings_upserted += 1;
    }

    let summary = format!(
        "Katalog {} ({}) importiert: {} neu, {} aktualisiert, {} Mappings",
        catalog.framework_code,
        catalog.framework_version,
        created_controls,
        updated_controls,
        mappings_upserted
    );

    AuditService::log_event(
        &mut *tx,
        Some(user.id),
        Some(client_ip),
        "catalog.imported",
        "compliance_frameworks",
        &framework_id.to_string(),
        &summary,
        None,
        Some(json!({
            "framework_code": catalog.framework_code,
            "framework_version": catalog.framework_version,
            "created_controls": created_controls,
            "updated_controls": updated_controls,
            "mappings_upserted": mappings_upserted,
            "file_sha256": file_sha256,
        })),
    )
    .await?;

    tx.commit().await?;

    let tmpl = CatalogImportResultTemplate {
        framework_code: catalog.framework_code,
        framework_name: catalog.framework_name,
        framework_version: catalog.framework_version,
        created_controls,
        updated_controls,
        mappings_upserted,
        file_sha256,
    };
    let html = render_template(&tmpl)?;
    Ok(with_toast(
        axum::response::Html(html).into_response(),
        "success",
        "Compliance-Katalog erfolgreich importiert.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_placeholder_description_in_catalog() {
        let json_raw = br#"{
            "framework": { "code": "CUSTOM_1", "name": "Test", "version": "1.0" },
            "controls": [
                { "code": "C-1", "domain": "Org", "title": "Test", "description": "TODO", "sort_order": 1 }
            ]
        }"#;
        let payload = parse_catalog_bytes("test.json", json_raw).expect("JSON parse");
        let err = validate_catalog(payload).expect_err("Platzhalter muss abgelehnt werden");
        assert!(matches!(err, AppError::Validation(_)));
    }
}
