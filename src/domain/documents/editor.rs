use std::str::FromStr;

use askama::Template;
use axum::{
    extract::{Form, Multipart, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    auth::rbac::{ClientIp, CurrentUser, ensure_owner_scope, forbid_auditor},
    db::begin_audited_tx,
    domain::documents::{SourceType, VersionStatus, can_view_version, validate_external_url},
    error::AppError,
    markdown::render_markdown_safe,
    pdf::{PdfDocumentMetadata, PdfRenderer, TypstCliRenderer},
    state::AppState,
    web::{ShellContext, hx_redirect_or_303, render_page, with_toast},
};

#[derive(Debug, Deserialize)]
pub struct PreviewMarkdownForm {
    pub content_markdown: Option<String>,
}

#[derive(Template)]
#[template(path = "documents/edit.html")]
struct DocumentEditTemplate {
    doc_id: Uuid,
    version_id: Uuid,
    doc_code: String,
    title: String,
    source_type_str: &'static str,
    version_number: String,
    status_label: &'static str,
    status_css: &'static str,
    content_markdown: String,
    preview_html: String,
    external_url: String,
    original_filename: String,
    change_summary: String,
    can_approve: bool,
}

pub async fn preview_markdown_handler(
    _user: CurrentUser,
    axum::extract::Form(form): axum::extract::Form<PreviewMarkdownForm>,
) -> Result<impl IntoResponse, AppError> {
    let md = form.content_markdown.unwrap_or_default();
    let html = render_markdown_safe(&md);
    Ok(Html(html))
}

pub async fn edit_version_page_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Path((doc_id, version_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;

    let row = sqlx::query(
        r#"
        SELECT
            d.doc_code, d.title, d.source_type, d.owner_unit_id, d.owner_user_id,
            dv.version_number, dv.status,
            COALESCE(dv.content_markdown, '') AS content_markdown,
            COALESCE(dv.external_url, '') AS external_url,
            COALESCE(dv.original_filename, '') AS original_filename,
            dv.change_summary
        FROM document_versions dv
        JOIN documents d ON d.id = dv.document_id
        WHERE dv.id = $1 AND dv.document_id = $2
        "#,
    )
    .bind(version_id)
    .bind(doc_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Dokumentversion nicht gefunden.".to_string()))?;

    let owner_unit_id: Option<Uuid> = row.get("owner_unit_id");
    let owner_user_id: Option<Uuid> = row.get("owner_user_id");
    ensure_owner_scope(&user, owner_unit_id, owner_user_id)?;

    let status = VersionStatus::from_str(row.get::<&str, _>("status"))?;
    if matches!(status, VersionStatus::Approved | VersionStatus::Archived) {
        return Err(AppError::Conflict(
            "Freigegebene oder archivierte Versionen sind unveränderlich. Bitte legen Sie eine neue Entwurfsversion an.".to_string(),
        ));
    }

    let source_type = SourceType::from_str(row.get::<&str, _>("source_type"))?;
    let content_markdown: String = row.get("content_markdown");
    let preview_html = if source_type == SourceType::MarkdownEditor {
        render_markdown_safe(&content_markdown)
    } else {
        String::new()
    };

    let doc_code: String = row.get("doc_code");
    let title: String = row.get("title");
    let version_number: String = row.get("version_number");
    let shell = ShellContext::from_user(
        &user,
        format!("Bearbeiten: {doc_code} v{version_number}"),
        "Dokumente & Richtlinien",
        "documents",
    );

    render_page(
        &headers,
        shell,
        &DocumentEditTemplate {
            doc_id,
            version_id,
            doc_code,
            title,
            source_type_str: source_type.as_str(),
            version_number,
            status_label: status.label(),
            status_css: status.badge_class(),
            content_markdown,
            preview_html,
            external_url: row.get("external_url"),
            original_filename: row.get("original_filename"),
            change_summary: row.get("change_summary"),
            can_approve: user.role.is_iso_or_admin(),
        },
    )
}

#[derive(Debug, Default)]
struct UpdateVersionInput {
    version_number: Option<String>,
    content_markdown: Option<String>,
    external_url: Option<String>,
    change_summary: Option<String>,
    upload_bytes: Option<Vec<u8>>,
    upload_filename: Option<String>,
    upload_content_type: Option<String>,
}

async fn parse_multipart_update_request(mut mp: Multipart) -> Result<UpdateVersionInput, AppError> {
    let mut input = UpdateVersionInput::default();
    while let Some(field) = mp
        .next_field()
        .await
        .map_err(|err| AppError::Validation(vec![format!("Ungültiger Upload: {err}")]))?
    {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "version_number" => input.version_number = Some(field.text().await.unwrap_or_default()),
            "content_markdown" => {
                input.content_markdown = Some(field.text().await.unwrap_or_default())
            }
            "external_url" => input.external_url = Some(field.text().await.unwrap_or_default()),
            "change_summary" => input.change_summary = Some(field.text().await.unwrap_or_default()),
            "file" => {
                let fname = field.file_name().map(str::to_string);
                let ftype = field.content_type().map(str::to_string);
                let data = field
                    .bytes()
                    .await
                    .map_err(|err| AppError::Validation(vec![format!("Upload-Fehler: {err}")]))?;
                if !data.is_empty() {
                    input.upload_bytes = Some(data.to_vec());
                    input.upload_filename = fname;
                    input.upload_content_type = ftype;
                }
            }
            _ => {}
        }
    }
    Ok(input)
}

#[derive(Deserialize)]
struct UpdateFormBody {
    version_number: Option<String>,
    content_markdown: Option<String>,
    external_url: Option<String>,
    change_summary: Option<String>,
}

impl From<UpdateFormBody> for UpdateVersionInput {
    fn from(form: UpdateFormBody) -> Self {
        Self {
            version_number: form.version_number,
            content_markdown: form.content_markdown,
            external_url: form.external_url,
            change_summary: form.change_summary,
            ..Default::default()
        }
    }
}

pub async fn update_version_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Path((doc_id, version_id)): Path<(Uuid, Uuid)>,
    request: axum::extract::Request,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;

    let is_multipart = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("multipart/form-data"));

    let input = if is_multipart {
        let mp = <Multipart as axum::extract::FromRequest<AppState>>::from_request(request, &state)
            .await
            .map_err(|err| AppError::Validation(vec![format!("Multipart-Fehler: {err}")]))?;
        parse_multipart_update_request(mp).await?
    } else {
        let Form(form) =
            <Form<UpdateFormBody> as axum::extract::FromRequest<AppState>>::from_request(
                request, &state,
            )
            .await
            .map_err(|err| AppError::Validation(vec![format!("Ungültige Formulardaten: {err}")]))?;
        form.into()
    };

    let row = sqlx::query(
        r#"
        SELECT
            d.source_type, d.owner_unit_id, d.owner_user_id,
            dv.status, dv.version_number, dv.content_markdown,
            dv.attached_file_key, dv.original_filename, dv.file_sha256, dv.external_url, dv.change_summary
        FROM document_versions dv
        JOIN documents d ON d.id = dv.document_id
        WHERE dv.id = $1 AND dv.document_id = $2
        "#,
    )
    .bind(version_id)
    .bind(doc_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Dokumentversion nicht gefunden.".to_string()))?;

    let owner_unit_id: Option<Uuid> = row.get("owner_unit_id");
    let owner_user_id: Option<Uuid> = row.get("owner_user_id");
    ensure_owner_scope(&user, owner_unit_id, owner_user_id)?;

    let status = VersionStatus::from_str(row.get::<&str, _>("status"))?;
    if matches!(status, VersionStatus::Approved | VersionStatus::Archived) {
        return Err(AppError::Conflict(
            "Freigegebene oder archivierte Versionen dürfen gemäß ISO 7.5.3 nicht verändert werden."
                .to_string(),
        ));
    }

    let source_type = SourceType::from_str(row.get::<&str, _>("source_type"))?;
    let current_version_number: String = row.get("version_number");
    let new_version_number = input
        .version_number
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&current_version_number)
        .to_string();

    let current_summary: String = row.get("change_summary");
    let new_summary = input
        .change_summary
        .as_deref()
        .map(str::trim)
        .unwrap_or(&current_summary)
        .to_string();

    let mut content_markdown: Option<String> = row.get("content_markdown");
    let mut attached_file_key: Option<String> = row.get("attached_file_key");
    let mut original_filename: Option<String> = row.get("original_filename");
    let mut file_sha256: Option<String> = row.get("file_sha256");
    let mut external_url: Option<String> = row.get("external_url");

    match source_type {
        SourceType::MarkdownEditor => {
            if let Some(md) = input.content_markdown {
                content_markdown = Some(md);
            }
        }
        SourceType::ExternalLink => {
            if let Some(raw_url) = input.external_url {
                external_url = Some(validate_external_url(
                    &raw_url,
                    state.config.is_production(),
                )?);
            }
        }
        SourceType::UploadedFile => {
            if let Some(bytes) = input.upload_bytes {
                let stored = state
                    .storage
                    .put(&bytes, input.upload_content_type.as_deref())
                    .await?;
                attached_file_key = Some(stored.storage_key);
                file_sha256 = Some(stored.sha256_hex);
                original_filename = input
                    .upload_filename
                    .filter(|s| !s.trim().is_empty())
                    .or(original_filename);
            }
        }
    }

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;
    sqlx::query(
        r#"
        UPDATE document_versions
        SET version_number = $2,
            content_markdown = $3,
            attached_file_key = $4,
            original_filename = $5,
            file_sha256 = $6,
            external_url = $7,
            change_summary = $8
        WHERE id = $1
        "#,
    )
    .bind(version_id)
    .bind(&new_version_number)
    .bind(&content_markdown)
    .bind(&attached_file_key)
    .bind(&original_filename)
    .bind(&file_sha256)
    .bind(&external_url)
    .bind(&new_summary)
    .execute(&mut *tx)
    .await
    .map_err(|err| {
        if let sqlx::Error::Database(db_err) = &err
            && db_err.code().as_deref() == Some("23505")
        {
            return AppError::Conflict(format!(
                "Versionsnummer {new_version_number} existiert bereits."
            ));
        }
        AppError::Database(err)
    })?;
    tx.commit().await?;

    Ok(with_toast(
        hx_redirect_or_303(
            &headers,
            &format!("/documents/{doc_id}?version={version_id}"),
        ),
        "success",
        "Entwurf gespeichert.",
    ))
}

pub async fn submit_review_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Path((doc_id, version_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;

    let row = sqlx::query(
        r#"
        SELECT d.owner_unit_id, d.owner_user_id, dv.status
        FROM document_versions dv
        JOIN documents d ON d.id = dv.document_id
        WHERE dv.id = $1 AND dv.document_id = $2
        "#,
    )
    .bind(version_id)
    .bind(doc_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Dokumentversion nicht gefunden.".to_string()))?;

    let owner_unit_id: Option<Uuid> = row.get("owner_unit_id");
    let owner_user_id: Option<Uuid> = row.get("owner_user_id");
    ensure_owner_scope(&user, owner_unit_id, owner_user_id)?;

    let status = VersionStatus::from_str(row.get::<&str, _>("status"))?;
    if status != VersionStatus::Draft {
        return Err(AppError::Conflict(
            "Nur Entwürfe können zur Prüfung eingereicht werden.".to_string(),
        ));
    }

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;
    sqlx::query("UPDATE document_versions SET status = 'in_review' WHERE id = $1")
        .bind(version_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(with_toast(
        hx_redirect_or_303(
            &headers,
            &format!("/documents/{doc_id}?version={version_id}"),
        ),
        "success",
        "Version zur Prüfung eingereicht.",
    ))
}

pub async fn approve_version_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Path((doc_id, version_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, AppError> {
    if !user.role.is_iso_or_admin() {
        return Err(AppError::Forbidden(
            "Nur ISB oder Administrator dürfen Dokumentversionen freigeben.".to_string(),
        ));
    }

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;

    let row = sqlx::query(
        r#"
        SELECT dv.status, d.review_interval_months
        FROM document_versions dv
        JOIN documents d ON d.id = dv.document_id
        WHERE dv.id = $1 AND dv.document_id = $2
        FOR UPDATE OF dv
        "#,
    )
    .bind(version_id)
    .bind(doc_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::NotFound("Dokumentversion nicht gefunden.".to_string()))?;

    let status = VersionStatus::from_str(row.get::<&str, _>("status"))?;
    if matches!(status, VersionStatus::Approved | VersionStatus::Archived) {
        return Err(AppError::Conflict(
            "Diese Dokumentversion ist bereits freigegeben oder archiviert.".to_string(),
        ));
    }
    let review_interval_months: i32 = row.get("review_interval_months");

    sqlx::query(
        r#"
        UPDATE document_versions
        SET status = 'archived'
        WHERE document_id = $1 AND status = 'approved' AND id <> $2
        "#,
    )
    .bind(doc_id)
    .bind(version_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        UPDATE document_versions
        SET status = 'approved',
            approved_by_id = $2,
            approved_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(version_id)
    .bind(user.id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        UPDATE documents
        SET next_review_due_at = NOW() + make_interval(months => $2),
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(doc_id)
    .bind(review_interval_months)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(with_toast(
        hx_redirect_or_303(
            &headers,
            &format!("/documents/{doc_id}?version={version_id}"),
        ),
        "success",
        "Dokumentversion freigegeben.",
    ))
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
        "dokument.bin".to_string()
    } else {
        cleaned
    }
}

pub async fn download_version_file_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    Path((doc_id, version_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, AppError> {
    let row = sqlx::query(
        r#"
        SELECT dv.status, dv.attached_file_key, dv.original_filename
        FROM document_versions dv
        WHERE dv.id = $1 AND dv.document_id = $2
        "#,
    )
    .bind(version_id)
    .bind(doc_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Dokumentversion nicht gefunden.".to_string()))?;

    let status = VersionStatus::from_str(row.get::<&str, _>("status"))?;
    if !can_view_version(user.role, status) {
        return Err(AppError::Forbidden(
            "Keine Berechtigung zum Herunterladen dieser Dokumentversion.".to_string(),
        ));
    }

    let key: String = row
        .get::<Option<String>, _>("attached_file_key")
        .ok_or_else(|| AppError::NotFound("Keine Datei an diese Version angehängt.".to_string()))?;
    let raw_name: String = row
        .get::<Option<String>, _>("original_filename")
        .unwrap_or_else(|| "dokument.bin".to_string());

    let bytes = state.storage.get(&key).await?;
    let safe_name = sanitize_download_filename(&raw_name);

    let mut resp = Response::new(axum::body::Body::from(bytes));
    *resp.status_mut() = StatusCode::OK;
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(disp) = HeaderValue::from_str(&format!("attachment; filename=\"{safe_name}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, disp);
    }

    Ok(resp)
}

pub async fn render_document_version_pdf_bytes(
    pool: &sqlx::PgPool,
    config: &crate::config::Config,
    doc_id: Uuid,
    version_id: Uuid,
) -> Result<(String, String, VersionStatus, Vec<u8>), AppError> {
    let row = sqlx::query(
        r#"
        SELECT
            d.doc_code, d.title, d.source_type, d.next_review_due_at,
            cl.code AS level_code, cl.name AS level_name,
            COALESCE(ou.name, 'Gesamtorganisation') AS owner_unit_name,
            dv.version_number, dv.status,
            COALESCE(dv.content_markdown, '') AS content_markdown,
            COALESCE(dv.external_url, '') AS external_url,
            COALESCE(dv.original_filename, '') AS original_filename,
            COALESCE(dv.file_sha256, '') AS file_sha256,
            COALESCE(ap.full_name, '–') AS approved_by_name,
            dv.approved_at
        FROM document_versions dv
        JOIN documents d ON d.id = dv.document_id
        JOIN classification_levels cl ON cl.id = d.classification_level_id
        LEFT JOIN organization_units ou ON ou.id = d.owner_unit_id
        LEFT JOIN users ap ON ap.id = dv.approved_by_id
        WHERE dv.id = $1 AND dv.document_id = $2
        "#,
    )
    .bind(version_id)
    .bind(doc_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Dokumentversion nicht gefunden.".to_string()))?;

    let status = VersionStatus::from_str(row.get::<&str, _>("status"))?;

    let company_name: String =
        sqlx::query_scalar("SELECT company_name FROM organization_profile WHERE id = 1")
            .fetch_optional(pool)
            .await?
            .unwrap_or_else(|| "Meine Organisation".to_string());

    let doc_code: String = row.get("doc_code");
    let title: String = row.get("title");
    let version_number: String = row.get("version_number");
    let approved_at: Option<DateTime<Utc>> = row.get("approved_at");
    let next_review: Option<DateTime<Utc>> = row.get("next_review_due_at");
    let level_code: String = row.get("level_code");
    let level_name: String = row.get("level_name");

    let source_type = SourceType::from_str(row.get::<&str, _>("source_type"))?;
    let markdown_body = match source_type {
        SourceType::MarkdownEditor => row.get::<String, _>("content_markdown"),
        SourceType::ExternalLink => {
            let url: String = row.get("external_url");
            format!(
                "# {title}\n\nDieses Dokument wird extern gepflegt:\n\n- **Externe URL:** {url}\n"
            )
        }
        SourceType::UploadedFile => {
            let fname: String = row.get("original_filename");
            let sha: String = row.get("file_sha256");
            format!(
                "# {title}\n\nDieses Dokument liegt als geprüfter Dateianhang vor:\n\n- **Dateiname:** {fname}\n- **SHA-256:** `{sha}`\n"
            )
        }
    };

    let meta = PdfDocumentMetadata {
        organization_name: company_name,
        doc_code: doc_code.clone(),
        title,
        version: version_number.clone(),
        status: status.label().to_string(),
        classification: format!("{level_code} · {level_name}"),
        owner_unit: row.get("owner_unit_name"),
        approved_by: row.get("approved_by_name"),
        approved_at: approved_at
            .map(|d| d.format("%d.%m.%Y").to_string())
            .unwrap_or_else(|| "Noch nicht freigegeben".to_string()),
        next_review_at: next_review
            .map(|d| d.format("%d.%m.%Y").to_string())
            .unwrap_or_else(|| "–".to_string()),
    };

    let renderer = TypstCliRenderer::from_config(config);
    let pdf_bytes = renderer
        .render_markdown_document(&meta, &markdown_body)
        .await?;

    Ok((doc_code, version_number, status, pdf_bytes))
}

pub async fn export_version_pdf_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    Path((doc_id, version_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, AppError> {
    let (doc_code, version_number, status, pdf_bytes) =
        render_document_version_pdf_bytes(&state.pool, &state.config, doc_id, version_id).await?;

    if !can_view_version(user.role, status) {
        return Err(AppError::Forbidden(
            "Keine Berechtigung für den PDF-Export dieser Dokumentversion.".to_string(),
        ));
    }

    let safe_filename = sanitize_download_filename(&format!("{doc_code}_v{version_number}.pdf"));
    let mut resp = Response::new(axum::body::Body::from(pdf_bytes));
    *resp.status_mut() = StatusCode::OK;
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/pdf"),
    );
    if let Ok(disp) = HeaderValue::from_str(&format!("attachment; filename=\"{safe_filename}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, disp);
    }

    Ok(resp)
}
