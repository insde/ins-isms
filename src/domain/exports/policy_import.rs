use std::str::FromStr;

use askama::Template;
use axum::{
    extract::{Multipart, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::{
    audit::AuditService,
    auth::rbac::{ClientIp, CurrentUser, RequireIsoOrAdmin},
    db::begin_audited_tx,
    domain::documents::DocType,
    error::AppError,
    seed::split_policy_frontmatter,
    state::AppState,
    web::{render_template, with_toast},
};

#[derive(Debug, Deserialize, Default)]
struct PolicyFrontmatter {
    doc_code: Option<String>,
    title: Option<String>,
    doc_type: Option<String>,
    classification_code: Option<String>,
    requires_acknowledgment: Option<bool>,
}

struct UploadedPolicyFile {
    filename: String,
    bytes: Vec<u8>,
}

struct ImportedPolicyItem {
    doc_code: String,
    title: String,
    version_number: String,
    outcome: String,
    file_sha256: String,
}

#[derive(Template)]
#[template(path = "exports/policy_result.html")]
struct PolicyImportResultTemplate {
    items: Vec<ImportedPolicyItem>,
}

fn derive_doc_code(filename: &str) -> String {
    let stem = std::path::Path::new(filename)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("POL-IMPORT");
    let raw_code = stem.split('_').next().unwrap_or(stem).trim();
    let cleaned: String = raw_code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
        .take(32)
        .collect();
    if cleaned.is_empty() {
        "POL-IMPORT".to_string()
    } else {
        cleaned.to_ascii_uppercase()
    }
}

fn derive_title(body: &str, filename: &str) -> String {
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(heading) = trimmed.strip_prefix("# ") {
            let clean = heading.trim();
            if !clean.is_empty() {
                return clean.chars().take(255).collect();
            }
        }
    }
    let stem = std::path::Path::new(filename)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Importierte Richtlinie");
    stem.split_once('_')
        .map(|(_, rest)| rest.replace(['_', '-'], " "))
        .unwrap_or_else(|| stem.to_string())
        .chars()
        .take(255)
        .collect()
}

fn next_draft_version(existing: &[String]) -> String {
    if existing.is_empty() {
        return "0.1".to_string();
    }
    let mut best_major = 0u32;
    let mut best_minor = 0u32;
    for v in existing {
        let mut parts = v.split('.');
        if let (Some(maj_s), Some(min_s)) = (parts.next(), parts.next())
            && let (Ok(maj), Ok(min)) = (maj_s.parse::<u32>(), min_s.parse::<u32>())
            && (maj > best_major || (maj == best_major && min >= best_minor))
        {
            best_major = maj;
            best_minor = min;
        }
    }
    let mut candidate_minor = best_minor + 1;
    loop {
        let candidate = format!("{best_major}.{candidate_minor}");
        if !existing.iter().any(|v| v == &candidate) {
            return candidate;
        }
        candidate_minor += 1;
    }
}

pub async fn import_policy_handler(
    State(state): State<AppState>,
    RequireIsoOrAdmin(user): RequireIsoOrAdmin,
    ClientIp(client_ip): ClientIp,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, AppError> {
    let mut files: Vec<UploadedPolicyFile> = Vec::new();
    let mut form_doc_code: Option<String> = None;
    let mut form_title: Option<String> = None;
    let mut form_doc_type: Option<String> = None;
    let mut form_classification_code: Option<String> = None;
    let mut form_requires_ack: Option<bool> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::Validation(vec![format!("Ungültiger Upload: {e}")]))?
    {
        let name = field.name().unwrap_or_default().to_string();
        match name.as_str() {
            "file" | "files" => {
                let filename = field.file_name().unwrap_or("richtlinie.md").to_string();
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|e| AppError::Validation(vec![format!("Upload-Fehler: {e}")]))?
                    .to_vec();
                if !bytes.is_empty() {
                    files.push(UploadedPolicyFile { filename, bytes });
                }
            }
            "doc_code" => {
                let v = field.text().await.unwrap_or_default();
                let t = v.trim().to_string();
                if !t.is_empty() {
                    form_doc_code = Some(t);
                }
            }
            "title" => {
                let v = field.text().await.unwrap_or_default();
                let t = v.trim().to_string();
                if !t.is_empty() {
                    form_title = Some(t);
                }
            }
            "doc_type" => {
                let v = field.text().await.unwrap_or_default();
                let t = v.trim().to_string();
                if !t.is_empty() {
                    form_doc_type = Some(t);
                }
            }
            "classification_code" => {
                let v = field.text().await.unwrap_or_default();
                let t = v.trim().to_string();
                if !t.is_empty() {
                    form_classification_code = Some(t);
                }
            }
            "requires_acknowledgment" => {
                let v = field.text().await.unwrap_or_default();
                let t = v.trim().to_ascii_lowercase();
                form_requires_ack = Some(matches!(t.as_str(), "true" | "1" | "on" | "yes"));
            }
            _ => {}
        }
    }

    if files.is_empty() {
        return Err(AppError::Validation(vec![
            "Bitte mindestens eine Markdown-Richtlinie (.md) auswählen.".to_string(),
        ]));
    }

    let multiple_files = files.len() > 1;
    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;
    let mut imported_items = Vec::with_capacity(files.len());

    for file in files {
        let lower_name = file.filename.to_ascii_lowercase();
        if !lower_name.ends_with(".md") && !lower_name.ends_with(".markdown") {
            return Err(AppError::Validation(vec![format!(
                "Datei '{}' hat keine gültige Markdown-Endung (.md).",
                file.filename
            )]));
        }

        let raw_text = std::str::from_utf8(&file.bytes).map_err(|_| {
            AppError::Validation(vec![format!(
                "Datei '{}' muss gültiges UTF-8 sein.",
                file.filename
            )])
        })?;

        let (frontmatter_yaml, body_markdown) = split_policy_frontmatter(raw_text)?;
        if body_markdown.trim().is_empty() {
            return Err(AppError::Validation(vec![format!(
                "Datei '{}' enthält keinen Markdown-Inhalt.",
                file.filename
            )]));
        }

        let fm: PolicyFrontmatter = match frontmatter_yaml {
            Some(yaml) => serde_yml::from_str(&yaml).map_err(|e| {
                AppError::Validation(vec![format!(
                    "Ungültiges YAML-Frontmatter in '{}': {e}",
                    file.filename
                )])
            })?,
            None => PolicyFrontmatter::default(),
        };

        let doc_code = fm
            .doc_code
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                if !multiple_files {
                    form_doc_code.clone()
                } else {
                    None
                }
            })
            .unwrap_or_else(|| derive_doc_code(&file.filename));

        if doc_code.len() > 32
            || !doc_code
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(AppError::Validation(vec![format!(
                "Ungültige Dokument-ID '{doc_code}' (max. 32 Zeichen, nur Buchstaben, Ziffern, -, _, .)."
            )]));
        }

        let title = fm
            .title
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                if !multiple_files {
                    form_title.clone()
                } else {
                    None
                }
            })
            .unwrap_or_else(|| derive_title(&body_markdown, &file.filename));

        if title.is_empty() || title.chars().count() > 255 {
            return Err(AppError::Validation(vec![format!(
                "Ungültiger Titel für '{doc_code}'."
            )]));
        }

        let doc_type_raw = fm
            .doc_type
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .or_else(|| form_doc_type.clone())
            .unwrap_or_else(|| "policy".to_string());
        let doc_type = DocType::from_str(&doc_type_raw)?;

        let class_code = fm
            .classification_code
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| form_classification_code.clone())
            .unwrap_or_else(|| "C2".to_string());

        let level_id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM classification_levels WHERE code = $1")
                .bind(&class_code)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(level_id) = level_id else {
            return Err(AppError::Validation(vec![format!(
                "Unbekannte Schutzstufe '{class_code}' für '{doc_code}'."
            )]));
        };

        let requires_ack = fm
            .requires_acknowledgment
            .or(form_requires_ack)
            .unwrap_or(true);

        let sha256_hex = hex::encode(Sha256::digest(&file.bytes));

        let existing_doc_id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM documents WHERE doc_code = $1")
                .bind(&doc_code)
                .fetch_optional(&mut *tx)
                .await?;

        let (doc_id, version_number, outcome) = match existing_doc_id {
            None => {
                let id: Uuid = sqlx::query_scalar(
                    r#"
                    INSERT INTO documents (
                        doc_code, title, doc_type, source_type,
                        classification_level_id, owner_user_id,
                        review_interval_months, requires_acknowledgment
                    )
                    VALUES ($1, $2, $3, 'markdown_editor', $4, $5, 12, $6)
                    RETURNING id
                    "#,
                )
                .bind(&doc_code)
                .bind(&title)
                .bind(doc_type.as_str())
                .bind(level_id)
                .bind(user.id)
                .bind(requires_ack)
                .fetch_one(&mut *tx)
                .await?;

                sqlx::query(
                    r#"
                    INSERT INTO document_versions (
                        document_id, version_number, status, content_markdown,
                        change_summary, author_id
                    )
                    VALUES ($1, '0.1', 'draft', $2, 'Importierte Richtlinie', $3)
                    "#,
                )
                .bind(id)
                .bind(&body_markdown)
                .bind(user.id)
                .execute(&mut *tx)
                .await?;

                (
                    id,
                    "0.1".to_string(),
                    "Neu angelegt (Entwurf 0.1)".to_string(),
                )
            }
            Some(id) => {
                let version_rows = sqlx::query(
                    r#"
                    SELECT version_number, status, COALESCE(content_markdown, '') AS content_markdown
                    FROM document_versions
                    WHERE document_id = $1
                    ORDER BY created_at ASC
                    "#,
                )
                .bind(id)
                .fetch_all(&mut *tx)
                .await?;

                let matching_draft = version_rows.iter().find(|r| {
                    let st: &str = r.get("status");
                    let md: &str = r.get("content_markdown");
                    matches!(st, "draft" | "in_review") && md == body_markdown
                });

                if let Some(row) = matching_draft {
                    let ver: String = row.get("version_number");
                    (
                        id,
                        ver.clone(),
                        format!("Übersprungen (Entwurf {ver} bereits aktuell)"),
                    )
                } else {
                    let existing_versions: Vec<String> = version_rows
                        .iter()
                        .map(|r| r.get::<String, _>("version_number"))
                        .collect();
                    let next_ver = next_draft_version(&existing_versions);

                    sqlx::query(
                        r#"
                        INSERT INTO document_versions (
                            document_id, version_number, status, content_markdown,
                            change_summary, author_id
                        )
                        VALUES ($1, $2, 'draft', $3, 'Aktualisierter Import als Entwurf', $4)
                        "#,
                    )
                    .bind(id)
                    .bind(&next_ver)
                    .bind(&body_markdown)
                    .bind(user.id)
                    .execute(&mut *tx)
                    .await?;

                    (
                        id,
                        next_ver.clone(),
                        format!("Neuer Entwurf {next_ver} angelegt (Freigaben unverändert)"),
                    )
                }
            }
        };

        AuditService::log_event(
            &mut *tx,
            Some(user.id),
            Some(client_ip),
            "policy.imported",
            "document",
            &doc_id.to_string(),
            &format!("Richtlinie '{doc_code}' importiert ({version_number})"),
            None,
            Some(json!({
                "doc_code": doc_code,
                "title": title,
                "version_number": version_number,
                "filename": file.filename,
                "file_sha256": sha256_hex,
            })),
        )
        .await?;

        imported_items.push(ImportedPolicyItem {
            doc_code,
            title,
            version_number,
            outcome,
            file_sha256: sha256_hex,
        });
    }

    tx.commit().await?;

    let count = imported_items.len();
    let html = render_template(&PolicyImportResultTemplate {
        items: imported_items,
    })?;
    Ok(with_toast(
        html.into_response(),
        "success",
        &format!("{count} Richtlinie(n) als Entwurf importiert."),
    ))
}

pub async fn example_catalog_template_handler(user: CurrentUser) -> Result<Response, AppError> {
    if !user.role.is_iso_or_admin() && !user.role.is_auditor() {
        return Err(AppError::Forbidden(
            "Nur Administratoren, ISB und Auditoren dürfen die Beispielvorlage herunterladen."
                .to_string(),
        ));
    }

    let payload = json!({
        "framework": {
            "code": "DEMO_ISMS",
            "name": "Beispiel-Regelwerk (Format-Referenz)",
            "version": "1.0-EXAMPLE"
        },
        "controls": [
            {
                "code": "DEMO-01",
                "domain": "Governance",
                "sort_order": 1,
                "title": "Beispiel-Anforderung: Sicherheitsverantwortung benennen",
                "description": "Fiktiver Beispiel-Eintrag zur Demonstration des Katalog-JSON-Formats.",
                "audit_question": "Ist eine verantwortliche Person schriftlich benannt?"
            },
            {
                "code": "DEMO-02",
                "domain": "Technik",
                "sort_order": 2,
                "title": "Beispiel-Anforderung: Regelmäßige Datensicherung",
                "description": "Fiktiver Beispiel-Eintrag zur Demonstration des Katalog-JSON-Formats.",
                "audit_question": "Werden Sicherungskopien regelmäßig auf Wiederherstellbarkeit geprüft?"
            }
        ],
        "mappings": []
    });

    let body = serde_json::to_vec_pretty(&payload)
        .map_err(|e| AppError::Internal(format!("JSON-Serialisierung fehlgeschlagen: {e}")))?;

    let mut resp = Response::new(axum::body::Body::from(body));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    resp.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static(r#"attachment; filename="example-catalog.json""#),
    );
    resp.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    Ok(resp)
}
