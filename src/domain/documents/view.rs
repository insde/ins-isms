use std::str::FromStr;

use askama::Template;
use axum::{
    extract::{Form, Path, Query, State},
    http::HeaderMap,
    response::IntoResponse,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    audit::AuditService,
    auth::rbac::{ClientIp, CurrentUser, Role, ensure_owner_scope, forbid_auditor},
    db::begin_audited_tx,
    domain::documents::{
        DocType, SourceType, VersionStatus, can_edit_document, can_view_version,
        next_version_number,
    },
    error::AppError,
    markdown::{is_valid_anchor_id, render_markdown_safe},
    state::AppState,
    web::{ShellContext, hx_redirect_or_303, render_page, with_toast},
};

#[derive(Debug, Deserialize, Default)]
pub struct ViewDocumentQuery {
    pub version: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct TocEntry {
    pub anchor: String,
    pub title: String,
}

#[derive(Debug, Clone)]
pub struct VersionHistoryItem {
    pub id: Uuid,
    pub version_number: String,
    pub status_str: &'static str,
    pub status_label: &'static str,
    pub status_css: &'static str,
    pub change_summary: String,
    pub author_name: String,
    pub approved_by_name: String,
    pub approved_at_label: String,
    pub created_at_label: String,
    pub is_selected: bool,
    pub can_edit_version: bool,
}

#[derive(Template)]
#[template(path = "documents/view.html")]
struct DocumentViewTemplate {
    doc_id: Uuid,
    doc_code: String,
    title: String,
    doc_type_label: &'static str,
    source_type_label: &'static str,
    source_type_str: &'static str,
    level_code: String,
    badge_css_class: String,
    owner_unit_name: String,
    owner_user_name: String,
    review_interval_months: i32,
    next_review_label: String,
    selected_version_id: Uuid,
    selected_version_number: String,
    selected_status_str: &'static str,
    selected_status_label: &'static str,
    selected_status_css: &'static str,
    selected_approved_by: String,
    selected_approved_at: String,
    selected_change_summary: String,
    rendered_html: String,
    toc: Vec<TocEntry>,
    original_filename: String,
    file_sha256: String,
    external_url: String,
    versions: Vec<VersionHistoryItem>,
    can_edit: bool,
    can_approve: bool,
    can_acknowledge: bool,
    user_acknowledged: bool,
    ack_count: i64,
    active_user_count: i64,
}

pub fn extract_toc(markdown: &str) -> Vec<TocEntry> {
    let mut toc = Vec::new();
    let mut pending_anchor: Option<String> = None;

    for line in markdown.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(r#"<a id=""#)
            && let Some((id, _)) = rest.split_once(r#""></a>"#)
            && is_valid_anchor_id(id)
        {
            pending_anchor = Some(id.to_string());
            continue;
        }

        if let Some(heading) = trimmed.strip_prefix("## ") {
            if let Some(anchor) = pending_anchor.take() {
                toc.push(TocEntry {
                    anchor,
                    title: heading.trim().to_string(),
                });
            }
        } else if !trimmed.is_empty() {
            pending_anchor = None;
        }
    }

    toc
}

pub async fn view_document_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Path(doc_id): Path<Uuid>,
    Query(query): Query<ViewDocumentQuery>,
) -> Result<impl IntoResponse, AppError> {
    let doc_row = sqlx::query(
        r#"
        SELECT
            d.id, d.doc_code, d.title, d.doc_type, d.source_type,
            d.owner_unit_id, d.owner_user_id, d.review_interval_months,
            d.next_review_due_at, d.requires_acknowledgment,
            cl.code AS level_code, cl.badge_color,
            COALESCE(ou.name, '–') AS owner_unit_name,
            COALESCE(u.full_name, '–') AS owner_user_name
        FROM documents d
        JOIN classification_levels cl ON cl.id = d.classification_level_id
        LEFT JOIN organization_units ou ON ou.id = d.owner_unit_id
        LEFT JOIN users u ON u.id = d.owner_user_id
        WHERE d.id = $1
        "#,
    )
    .bind(doc_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Dokument nicht gefunden.".to_string()))?;

    let version_rows = sqlx::query(
        r#"
        SELECT
            dv.id, dv.version_number, dv.status,
            COALESCE(dv.content_markdown, '') AS content_markdown,
            COALESCE(dv.original_filename, '') AS original_filename,
            COALESCE(dv.file_sha256, '') AS file_sha256,
            COALESCE(dv.external_url, '') AS external_url,
            dv.change_summary,
            dv.approved_at,
            dv.created_at,
            COALESCE(au.full_name, 'System') AS author_name,
            COALESCE(ap.full_name, '–') AS approved_by_name
        FROM document_versions dv
        LEFT JOIN users au ON au.id = dv.author_id
        LEFT JOIN users ap ON ap.id = dv.approved_by_id
        WHERE dv.document_id = $1
        ORDER BY (dv.status = 'approved') DESC, dv.created_at DESC
        "#,
    )
    .bind(doc_id)
    .fetch_all(&state.pool)
    .await?;

    if let Some(requested_vid) = query.version {
        let found = version_rows
            .iter()
            .find(|r| r.get::<Uuid, _>("id") == requested_vid)
            .ok_or_else(|| AppError::NotFound("Dokumentversion nicht gefunden.".to_string()))?;
        let st = VersionStatus::from_str(found.get::<&str, _>("status"))?;
        if !can_view_version(user.role, st) {
            return Err(AppError::Forbidden(
                "Diese Dokumentversion ist für Ihre Rolle nicht freigegeben.".to_string(),
            ));
        }
    }

    let visible_rows: Vec<_> = version_rows
        .into_iter()
        .filter(|r| {
            VersionStatus::from_str(r.get::<&str, _>("status"))
                .map(|st| can_view_version(user.role, st))
                .unwrap_or(false)
        })
        .collect();

    if visible_rows.is_empty() {
        return Err(AppError::NotFound(
            "Dokument nicht gefunden oder noch nicht freigegeben.".to_string(),
        ));
    }

    let selected_row = if let Some(requested_vid) = query.version {
        visible_rows
            .iter()
            .find(|r| r.get::<Uuid, _>("id") == requested_vid)
            .ok_or_else(|| AppError::NotFound("Dokumentversion nicht gefunden.".to_string()))?
    } else {
        &visible_rows[0]
    };

    let owner_unit_id: Option<Uuid> = doc_row.get("owner_unit_id");
    let owner_user_id: Option<Uuid> = doc_row.get("owner_user_id");
    let can_edit = can_edit_document(&user, owner_unit_id, owner_user_id);
    let can_approve = user.role.is_iso_or_admin();

    let selected_vid: Uuid = selected_row.get("id");
    let selected_status = VersionStatus::from_str(selected_row.get::<&str, _>("status"))?;
    let source_type = SourceType::from_str(doc_row.get::<&str, _>("source_type"))?;
    let doc_type = DocType::from_str(doc_row.get::<&str, _>("doc_type"))?;

    let md: String = selected_row.get("content_markdown");
    let (rendered_html, toc) = if source_type == SourceType::MarkdownEditor {
        (render_markdown_safe(&md), extract_toc(&md))
    } else {
        (String::new(), Vec::new())
    };

    let requires_acknowledgment: bool = doc_row.get("requires_acknowledgment");
    let user_acknowledged: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM document_acknowledgments WHERE document_version_id = $1 AND user_id = $2)",
    )
    .bind(selected_vid)
    .bind(user.id)
    .fetch_one(&state.pool)
    .await?;

    let ack_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM document_acknowledgments WHERE document_version_id = $1",
    )
    .bind(selected_vid)
    .fetch_one(&state.pool)
    .await?;

    let active_user_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_active = TRUE")
            .fetch_one(&state.pool)
            .await?;

    let can_acknowledge = requires_acknowledgment
        && selected_status == VersionStatus::Approved
        && user.role != Role::Auditor;

    let mut versions = Vec::with_capacity(visible_rows.len());
    for r in &visible_rows {
        let vid: Uuid = r.get("id");
        let st = VersionStatus::from_str(r.get::<&str, _>("status"))?;
        let approved_at: Option<DateTime<Utc>> = r.get("approved_at");
        let created_at: DateTime<Utc> = r.get("created_at");
        versions.push(VersionHistoryItem {
            id: vid,
            version_number: r.get("version_number"),
            status_str: st.as_str(),
            status_label: st.label(),
            status_css: st.badge_class(),
            change_summary: r.get("change_summary"),
            author_name: r.get("author_name"),
            approved_by_name: r.get("approved_by_name"),
            approved_at_label: approved_at
                .map(|d| d.format("%d.%m.%Y").to_string())
                .unwrap_or_else(|| "–".to_string()),
            created_at_label: created_at.format("%d.%m.%Y %H:%M").to_string(),
            is_selected: vid == selected_vid,
            can_edit_version: can_edit
                && matches!(st, VersionStatus::Draft | VersionStatus::InReview),
        });
    }

    let badge_css_class = match doc_row.get::<&str, _>("badge_color") {
        "neutral" => "badge-c1",
        "info" => "badge-c2",
        "warning" => "badge-c3",
        "danger" => "badge-c4",
        _ => "badge-c2",
    }
    .to_string();

    let next_review_due_at: Option<DateTime<Utc>> = doc_row.get("next_review_due_at");
    let next_review_label = next_review_due_at
        .map(|d| d.format("%d.%m.%Y").to_string())
        .unwrap_or_else(|| "–".to_string());

    let selected_approved_at: Option<DateTime<Utc>> = selected_row.get("approved_at");
    let doc_code: String = doc_row.get("doc_code");
    let title: String = doc_row.get("title");

    let shell = ShellContext::from_user(
        &user,
        format!("{doc_code} · {title}"),
        "Dokumente & Richtlinien",
        "documents",
    );

    render_page(
        &headers,
        shell,
        &DocumentViewTemplate {
            doc_id,
            doc_code,
            title,
            doc_type_label: doc_type.label(),
            source_type_label: source_type.label(),
            source_type_str: source_type.as_str(),
            level_code: doc_row.get("level_code"),
            badge_css_class,
            owner_unit_name: doc_row.get("owner_unit_name"),
            owner_user_name: doc_row.get("owner_user_name"),
            review_interval_months: doc_row.get("review_interval_months"),
            next_review_label,
            selected_version_id: selected_vid,
            selected_version_number: selected_row.get("version_number"),
            selected_status_str: selected_status.as_str(),
            selected_status_label: selected_status.label(),
            selected_status_css: selected_status.badge_class(),
            selected_approved_by: selected_row.get("approved_by_name"),
            selected_approved_at: selected_approved_at
                .map(|d| d.format("%d.%m.%Y").to_string())
                .unwrap_or_else(|| "–".to_string()),
            selected_change_summary: selected_row.get("change_summary"),
            rendered_html,
            toc,
            original_filename: selected_row.get("original_filename"),
            file_sha256: selected_row.get("file_sha256"),
            external_url: selected_row.get("external_url"),
            versions,
            can_edit,
            can_approve,
            can_acknowledge,
            user_acknowledged,
            ack_count,
            active_user_count,
        },
    )
}

pub async fn acknowledge_document_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Path(doc_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;

    let row = sqlx::query(
        r#"
        SELECT dv.id AS version_id, dv.version_number, d.doc_code
        FROM document_versions dv
        JOIN documents d ON d.id = dv.document_id
        WHERE dv.document_id = $1 AND dv.status = 'approved'
        LIMIT 1
        "#,
    )
    .bind(doc_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| {
        AppError::Validation(vec![
            "Nur freigegebene Dokumentversionen können bestätigt werden.".to_string(),
        ])
    })?;

    let version_id: Uuid = row.get("version_id");
    let version_number: String = row.get("version_number");
    let doc_code: String = row.get("doc_code");

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;
    sqlx::query(
        r#"
        INSERT INTO document_acknowledgments (document_version_id, user_id)
        VALUES ($1, $2)
        ON CONFLICT (document_version_id, user_id) DO NOTHING
        "#,
    )
    .bind(version_id)
    .bind(user.id)
    .execute(&mut *tx)
    .await?;

    AuditService::log_event(
        &mut *tx,
        Some(user.id),
        Some(client_ip),
        "document.acknowledged",
        "document_versions",
        &version_id.to_string(),
        &format!("Lesebestätigung für {doc_code} v{version_number}"),
        None,
        Some(json!({
            "document_id": doc_id,
            "doc_code": doc_code,
            "version_number": version_number,
        })),
    )
    .await?;

    tx.commit().await?;

    Ok(with_toast(
        hx_redirect_or_303(&headers, &format!("/documents/{doc_id}")),
        "success",
        "Kenntnisnahme protokolliert.",
    ))
}

#[derive(Debug, Deserialize, Default)]
pub struct DeriveVersionForm {
    pub version_number: Option<String>,
    pub change_summary: Option<String>,
}

pub async fn derive_version_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Path(doc_id): Path<Uuid>,
    Form(form): Form<DeriveVersionForm>,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;

    let doc_row = sqlx::query(
        "SELECT source_type, owner_unit_id, owner_user_id FROM documents WHERE id = $1",
    )
    .bind(doc_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Dokument nicht gefunden.".to_string()))?;

    let owner_unit_id: Option<Uuid> = doc_row.get("owner_unit_id");
    let owner_user_id: Option<Uuid> = doc_row.get("owner_user_id");
    ensure_owner_scope(&user, owner_unit_id, owner_user_id)?;

    let latest = sqlx::query(
        r#"
        SELECT version_number, content_markdown, attached_file_key, original_filename, file_sha256, external_url
        FROM document_versions
        WHERE document_id = $1
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(doc_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Keine Basisversion gefunden.".to_string()))?;

    let current_ver: String = latest.get("version_number");
    let new_ver = form
        .version_number
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| next_version_number(&current_ver));

    let change_summary = form
        .change_summary
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("Neue Entwurfsversion");

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;
    let new_vid: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO document_versions (
            document_id, version_number, status,
            content_markdown, attached_file_key, original_filename, file_sha256, external_url,
            change_summary, author_id
        )
        VALUES ($1, $2, 'draft', $3, $4, $5, $6, $7, $8, $9)
        RETURNING id
        "#,
    )
    .bind(doc_id)
    .bind(&new_ver)
    .bind(latest.get::<Option<String>, _>("content_markdown"))
    .bind(latest.get::<Option<String>, _>("attached_file_key"))
    .bind(latest.get::<Option<String>, _>("original_filename"))
    .bind(latest.get::<Option<String>, _>("file_sha256"))
    .bind(latest.get::<Option<String>, _>("external_url"))
    .bind(change_summary)
    .bind(user.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| {
        if let sqlx::Error::Database(db_err) = &err
            && db_err.code().as_deref() == Some("23505")
        {
            return AppError::Conflict(format!(
                "Version {new_ver} existiert für dieses Dokument bereits."
            ));
        }
        AppError::Database(err)
    })?;
    tx.commit().await?;

    let source_type = SourceType::from_str(doc_row.get::<&str, _>("source_type"))?;
    let target = if source_type == SourceType::MarkdownEditor {
        format!("/documents/{doc_id}/versions/{new_vid}/edit")
    } else {
        format!("/documents/{doc_id}?version={new_vid}")
    };

    Ok(with_toast(
        hx_redirect_or_303(&headers, &target),
        "success",
        &format!("Entwurfsversion {new_ver} angelegt."),
    ))
}
