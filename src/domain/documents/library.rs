use std::str::FromStr;

use askama::Template;
use axum::{
    extract::{Form, Multipart, Path, Query, State},
    http::{HeaderMap, header},
    response::IntoResponse,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    auth::rbac::{ClientIp, CurrentUser, Role, ensure_owner_scope, forbid_auditor},
    db::begin_audited_tx,
    domain::{
        classification::assets::SelectOption,
        documents::{DocType, SourceType, VersionStatus, can_edit_document, validate_external_url},
        organization::profile::parse_optional_uuid,
    },
    error::AppError,
    state::AppState,
    web::{ShellContext, hx_redirect_or_303, render_page, render_template, with_toast},
};

#[derive(Debug, Clone)]
pub struct DocumentRowView {
    pub id: Uuid,
    pub doc_code: String,
    pub title: String,
    pub doc_type_label: &'static str,
    pub source_type_label: &'static str,
    pub source_type_str: &'static str,
    pub level_code: String,
    pub badge_css_class: String,
    pub owner_unit_name: String,
    pub owner_user_name: String,
    pub active_version_id: Uuid,
    pub active_version_number: String,
    pub active_status_label: &'static str,
    pub active_status_css: &'static str,
    pub next_review_label: String,
    pub is_review_due: bool,
    pub requires_acknowledgment: bool,
    pub user_acknowledged: bool,
    pub ack_summary: String,
    pub file_sha256_short: String,
    pub original_filename: String,
    pub external_url: String,
    pub can_edit: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct DocumentFilter {
    pub q: Option<String>,
    pub doc_type: Option<String>,
    pub source_type: Option<String>,
    pub status: Option<String>,
    pub pending_ack: Option<String>,
}

#[derive(Template)]
#[template(path = "documents/library.html")]
struct DocumentsLibraryTemplate {
    documents: Vec<DocumentRowView>,
    filter_q: String,
    filter_doc_type: String,
    filter_source_type: String,
    filter_status: String,
    filter_pending_ack: bool,
    can_create: bool,
    is_restricted_viewer: bool,
}

#[derive(Template)]
#[template(path = "documents/drawer.html")]
struct DocumentDrawerTemplate {
    doc: DocumentRowView,
    full_sha256: String,
    can_edit: bool,
}

#[derive(Template)]
#[template(path = "documents/new.html")]
struct NewDocumentTemplate {
    levels: Vec<SelectOption>,
    units: Vec<SelectOption>,
    users: Vec<SelectOption>,
    default_owner_unit_id: String,
    default_owner_user_id: String,
}

fn format_review_date(dt: Option<DateTime<Utc>>) -> (String, bool) {
    match dt {
        Some(d) => (d.format("%d.%m.%Y").to_string(), d <= Utc::now()),
        None => ("–".to_string(), false),
    }
}

pub async fn load_select_options(
    pool: &sqlx::PgPool,
) -> Result<(Vec<SelectOption>, Vec<SelectOption>, Vec<SelectOption>), AppError> {
    let level_rows =
        sqlx::query("SELECT id, code, name FROM classification_levels ORDER BY rank ASC")
            .fetch_all(pool)
            .await?;
    let levels = level_rows
        .into_iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            let code: String = r.get("code");
            let name: String = r.get("name");
            SelectOption {
                id: id.to_string(),
                label: format!("{code} · {name}"),
            }
        })
        .collect();

    let unit_rows = sqlx::query("SELECT id, name FROM organization_units ORDER BY name ASC")
        .fetch_all(pool)
        .await?;
    let units = unit_rows
        .into_iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            SelectOption {
                id: id.to_string(),
                label: r.get("name"),
            }
        })
        .collect();

    let user_rows = sqlx::query(
        "SELECT id, full_name FROM users WHERE is_active = TRUE ORDER BY full_name ASC",
    )
    .fetch_all(pool)
    .await?;
    let users = user_rows
        .into_iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            SelectOption {
                id: id.to_string(),
                label: r.get("full_name"),
            }
        })
        .collect();

    Ok((levels, units, users))
}

pub async fn list_documents_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Query(filter): Query<DocumentFilter>,
) -> Result<impl IntoResponse, AppError> {
    let restricted_viewer = matches!(user.role, Role::Auditor | Role::Employee);

    let filter_q = filter.q.unwrap_or_default().trim().to_string();
    let filter_doc_type = filter.doc_type.unwrap_or_default().trim().to_string();
    let filter_source_type = filter.source_type.unwrap_or_default().trim().to_string();
    let filter_status = filter.status.unwrap_or_default().trim().to_string();
    let filter_pending_ack = matches!(filter.pending_ack.as_deref(), Some("1" | "true" | "on"));

    let active_user_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_active = TRUE")
            .fetch_one(&state.pool)
            .await?;

    let rows = sqlx::query(
        r#"
        SELECT
            d.id,
            d.doc_code,
            d.title,
            d.doc_type,
            d.source_type,
            d.owner_unit_id,
            d.owner_user_id,
            d.next_review_due_at,
            d.requires_acknowledgment,
            cl.code AS level_code,
            cl.badge_color,
            COALESCE(ou.name, '–') AS owner_unit_name,
            COALESCE(u.full_name, '–') AS owner_user_name,
            dv.id AS version_id,
            dv.version_number,
            dv.status AS version_status,
            COALESCE(dv.file_sha256, '') AS file_sha256,
            COALESCE(dv.original_filename, '') AS original_filename,
            COALESCE(dv.external_url, '') AS external_url,
            EXISTS(
                SELECT 1 FROM document_acknowledgments da
                WHERE da.document_version_id = dv.id AND da.user_id = $1
            ) AS user_acknowledged,
            (
                SELECT COUNT(*) FROM document_acknowledgments da
                WHERE da.document_version_id = dv.id
            ) AS ack_count
        FROM documents d
        JOIN classification_levels cl ON cl.id = d.classification_level_id
        LEFT JOIN organization_units ou ON ou.id = d.owner_unit_id
        LEFT JOIN users u ON u.id = d.owner_user_id
        JOIN LATERAL (
            SELECT v.*
            FROM document_versions v
            WHERE v.document_id = d.id
              AND (NOT $2 OR v.status = 'approved')
            ORDER BY (v.status = 'approved') DESC, v.created_at DESC
            LIMIT 1
        ) dv ON TRUE
        WHERE ($3 = '' OR d.doc_code ILIKE $4 OR d.title ILIKE $4)
          AND ($5 = '' OR d.doc_type = $5)
          AND ($6 = '' OR d.source_type = $6)
        ORDER BY d.doc_code ASC
        "#,
    )
    .bind(user.id)
    .bind(restricted_viewer)
    .bind(&filter_q)
    .bind(format!("%{filter_q}%"))
    .bind(&filter_doc_type)
    .bind(&filter_source_type)
    .fetch_all(&state.pool)
    .await?;

    let mut documents = Vec::with_capacity(rows.len());
    for r in rows {
        let doc_type = DocType::from_str(r.get::<&str, _>("doc_type"))?;
        let source_type = SourceType::from_str(r.get::<&str, _>("source_type"))?;
        let version_status = VersionStatus::from_str(r.get::<&str, _>("version_status"))?;
        let next_review_due_at: Option<DateTime<Utc>> = r.get("next_review_due_at");
        let (next_review_label, is_review_due) = format_review_date(next_review_due_at);

        if !filter_status.is_empty() {
            let matches_status = match filter_status.as_str() {
                "review_due" => is_review_due,
                other => version_status.as_str() == other,
            };
            if !matches_status {
                continue;
            }
        }

        let requires_ack: bool = r.get("requires_acknowledgment");
        let user_acknowledged: bool = r.get("user_acknowledged");
        if filter_pending_ack
            && (!requires_ack || version_status != VersionStatus::Approved || user_acknowledged)
        {
            continue;
        }

        let owner_unit_id: Option<Uuid> = r.get("owner_unit_id");
        let owner_user_id: Option<Uuid> = r.get("owner_user_id");
        let ack_count: i64 = r.get("ack_count");
        let ack_summary = if requires_ack && version_status == VersionStatus::Approved {
            format!("{ack_count} / {active_user_count}")
        } else {
            "–".to_string()
        };

        let sha: String = r.get("file_sha256");
        let file_sha256_short = if sha.len() >= 12 {
            format!("{}…", &sha[..12])
        } else {
            sha
        };

        let badge_css_class = match r.get::<&str, _>("badge_color") {
            "neutral" => "badge-c1",
            "info" => "badge-c2",
            "warning" => "badge-c3",
            "danger" => "badge-c4",
            _ => "badge-c2",
        }
        .to_string();

        documents.push(DocumentRowView {
            id: r.get("id"),
            doc_code: r.get("doc_code"),
            title: r.get("title"),
            doc_type_label: doc_type.label(),
            source_type_label: source_type.label(),
            source_type_str: source_type.as_str(),
            level_code: r.get("level_code"),
            badge_css_class,
            owner_unit_name: r.get("owner_unit_name"),
            owner_user_name: r.get("owner_user_name"),
            active_version_id: r.get("version_id"),
            active_version_number: r.get("version_number"),
            active_status_label: version_status.label(),
            active_status_css: version_status.badge_class(),
            next_review_label,
            is_review_due,
            requires_acknowledgment: requires_ack,
            user_acknowledged,
            ack_summary,
            file_sha256_short,
            original_filename: r.get("original_filename"),
            external_url: r.get("external_url"),
            can_edit: can_edit_document(&user, owner_unit_id, owner_user_id),
        });
    }

    let can_create = matches!(user.role, Role::Admin | Role::Iso | Role::Owner);
    let shell = ShellContext::from_user(
        &user,
        "Dokumente & Richtlinien",
        "Governance & Compliance",
        "documents",
    );

    render_page(
        &headers,
        shell,
        &DocumentsLibraryTemplate {
            documents,
            filter_q,
            filter_doc_type,
            filter_source_type,
            filter_status,
            filter_pending_ack,
            can_create,
            is_restricted_viewer: restricted_viewer,
        },
    )
}

pub async fn document_drawer_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(doc_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let restricted_viewer = matches!(user.role, Role::Auditor | Role::Employee);
    let active_user_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_active = TRUE")
            .fetch_one(&state.pool)
            .await?;

    let row = sqlx::query(
        r#"
        SELECT
            d.id, d.doc_code, d.title, d.doc_type, d.source_type,
            d.owner_unit_id, d.owner_user_id, d.next_review_due_at, d.requires_acknowledgment,
            cl.code AS level_code, cl.badge_color,
            COALESCE(ou.name, '–') AS owner_unit_name,
            COALESCE(u.full_name, '–') AS owner_user_name,
            dv.id AS version_id, dv.version_number, dv.status AS version_status,
            COALESCE(dv.file_sha256, '') AS file_sha256,
            COALESCE(dv.original_filename, '') AS original_filename,
            COALESCE(dv.external_url, '') AS external_url,
            EXISTS(
                SELECT 1 FROM document_acknowledgments da
                WHERE da.document_version_id = dv.id AND da.user_id = $2
            ) AS user_acknowledged,
            (
                SELECT COUNT(*) FROM document_acknowledgments da
                WHERE da.document_version_id = dv.id
            ) AS ack_count
        FROM documents d
        JOIN classification_levels cl ON cl.id = d.classification_level_id
        LEFT JOIN organization_units ou ON ou.id = d.owner_unit_id
        LEFT JOIN users u ON u.id = d.owner_user_id
        JOIN LATERAL (
            SELECT v.*
            FROM document_versions v
            WHERE v.document_id = d.id
              AND (NOT $3 OR v.status = 'approved')
            ORDER BY (v.status = 'approved') DESC, v.created_at DESC
            LIMIT 1
        ) dv ON TRUE
        WHERE d.id = $1
        "#,
    )
    .bind(doc_id)
    .bind(user.id)
    .bind(restricted_viewer)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| {
        AppError::NotFound("Dokument nicht gefunden oder noch nicht freigegeben.".to_string())
    })?;

    let doc_type = DocType::from_str(row.get::<&str, _>("doc_type"))?;
    let source_type = SourceType::from_str(row.get::<&str, _>("source_type"))?;
    let version_status = VersionStatus::from_str(row.get::<&str, _>("version_status"))?;
    let next_review_due_at: Option<DateTime<Utc>> = row.get("next_review_due_at");
    let (next_review_label, is_review_due) = format_review_date(next_review_due_at);
    let requires_ack: bool = row.get("requires_acknowledgment");
    let ack_count: i64 = row.get("ack_count");
    let full_sha256: String = row.get("file_sha256");
    let owner_unit_id: Option<Uuid> = row.get("owner_unit_id");
    let owner_user_id: Option<Uuid> = row.get("owner_user_id");
    let can_edit = can_edit_document(&user, owner_unit_id, owner_user_id);

    let badge_css_class = match row.get::<&str, _>("badge_color") {
        "neutral" => "badge-c1",
        "info" => "badge-c2",
        "warning" => "badge-c3",
        "danger" => "badge-c4",
        _ => "badge-c2",
    }
    .to_string();

    let doc = DocumentRowView {
        id: row.get("id"),
        doc_code: row.get("doc_code"),
        title: row.get("title"),
        doc_type_label: doc_type.label(),
        source_type_label: source_type.label(),
        source_type_str: source_type.as_str(),
        level_code: row.get("level_code"),
        badge_css_class,
        owner_unit_name: row.get("owner_unit_name"),
        owner_user_name: row.get("owner_user_name"),
        active_version_id: row.get("version_id"),
        active_version_number: row.get("version_number"),
        active_status_label: version_status.label(),
        active_status_css: version_status.badge_class(),
        next_review_label,
        is_review_due,
        requires_acknowledgment: requires_ack,
        user_acknowledged: row.get("user_acknowledged"),
        ack_summary: if requires_ack && version_status == VersionStatus::Approved {
            format!("{ack_count} / {active_user_count}")
        } else {
            "–".to_string()
        },
        file_sha256_short: if full_sha256.len() >= 12 {
            format!("{}…", &full_sha256[..12])
        } else {
            full_sha256.clone()
        },
        original_filename: row.get("original_filename"),
        external_url: row.get("external_url"),
        can_edit,
    };

    render_template(&DocumentDrawerTemplate {
        doc,
        full_sha256,
        can_edit,
    })
}

pub async fn new_document_form_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Keine Berechtigung zum Anlegen von Dokumenten.".to_string(),
        ));
    }

    let (levels, units, users) = load_select_options(&state.pool).await?;
    let shell = ShellContext::from_user(
        &user,
        "Neues Dokument",
        "Governance & Compliance",
        "documents",
    );

    render_page(
        &headers,
        shell,
        &NewDocumentTemplate {
            levels,
            units,
            users,
            default_owner_unit_id: user
                .organization_unit_id
                .map(|u| u.to_string())
                .unwrap_or_default(),
            default_owner_user_id: user.id.to_string(),
        },
    )
}

#[derive(Debug, Default)]
struct CreateDocumentInput {
    doc_code: String,
    title: String,
    doc_type: String,
    source_type: String,
    classification_level_id: String,
    owner_unit_id: Option<String>,
    owner_user_id: Option<String>,
    review_interval_months: i32,
    requires_acknowledgment: bool,
    content_markdown: Option<String>,
    external_url: Option<String>,
    upload_bytes: Option<Vec<u8>>,
    upload_filename: Option<String>,
    upload_content_type: Option<String>,
}

async fn parse_multipart_create_request(
    mut mp: Multipart,
) -> Result<CreateDocumentInput, AppError> {
    let mut input = CreateDocumentInput {
        review_interval_months: 12,
        ..Default::default()
    };
    while let Some(field) = mp
        .next_field()
        .await
        .map_err(|err| AppError::Validation(vec![format!("Ungültiger Upload: {err}")]))?
    {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "doc_code" => input.doc_code = field.text().await.unwrap_or_default(),
            "title" => input.title = field.text().await.unwrap_or_default(),
            "doc_type" => input.doc_type = field.text().await.unwrap_or_default(),
            "source_type" => input.source_type = field.text().await.unwrap_or_default(),
            "classification_level_id" => {
                input.classification_level_id = field.text().await.unwrap_or_default()
            }
            "owner_unit_id" => input.owner_unit_id = Some(field.text().await.unwrap_or_default()),
            "owner_user_id" => input.owner_user_id = Some(field.text().await.unwrap_or_default()),
            "review_interval_months" => {
                let raw = field.text().await.unwrap_or_default();
                input.review_interval_months = raw.trim().parse::<i32>().unwrap_or(12);
            }
            "requires_acknowledgment" => {
                let raw = field.text().await.unwrap_or_default();
                input.requires_acknowledgment = matches!(raw.trim(), "1" | "true" | "on");
            }
            "content_markdown" => {
                input.content_markdown = Some(field.text().await.unwrap_or_default())
            }
            "external_url" => input.external_url = Some(field.text().await.unwrap_or_default()),
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
struct CreateFormBody {
    doc_code: String,
    title: String,
    doc_type: String,
    source_type: Option<String>,
    classification_level_id: String,
    owner_unit_id: Option<String>,
    owner_user_id: Option<String>,
    review_interval_months: Option<i32>,
    requires_acknowledgment: Option<String>,
    content_markdown: Option<String>,
    external_url: Option<String>,
}

impl From<CreateFormBody> for CreateDocumentInput {
    fn from(form: CreateFormBody) -> Self {
        Self {
            doc_code: form.doc_code,
            title: form.title,
            doc_type: form.doc_type,
            source_type: form
                .source_type
                .unwrap_or_else(|| "markdown_editor".to_string()),
            classification_level_id: form.classification_level_id,
            owner_unit_id: form.owner_unit_id,
            owner_user_id: form.owner_user_id,
            review_interval_months: form.review_interval_months.unwrap_or(12),
            requires_acknowledgment: matches!(
                form.requires_acknowledgment.as_deref(),
                Some("1" | "true" | "on")
            ),
            content_markdown: form.content_markdown,
            external_url: form.external_url,
            ..Default::default()
        }
    }
}

pub async fn create_document_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    request: axum::extract::Request,
) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Keine Berechtigung zum Anlegen von Dokumenten.".to_string(),
        ));
    }

    let is_multipart = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("multipart/form-data"));

    let input = if is_multipart {
        let mp = <Multipart as axum::extract::FromRequest<AppState>>::from_request(request, &state)
            .await
            .map_err(|err| AppError::Validation(vec![format!("Multipart-Fehler: {err}")]))?;
        parse_multipart_create_request(mp).await?
    } else {
        let Form(form) =
            <Form<CreateFormBody> as axum::extract::FromRequest<AppState>>::from_request(
                request, &state,
            )
            .await
            .map_err(|err| AppError::Validation(vec![format!("Ungültige Formulardaten: {err}")]))?;
        form.into()
    };

    let doc_code = input.doc_code.trim().to_ascii_uppercase();
    let title = input.title.trim().to_string();
    if doc_code.is_empty() || doc_code.len() > 32 {
        return Err(AppError::Validation(vec![
            "Dokument-Code muss zwischen 1 und 32 Zeichen lang sein.".to_string(),
        ]));
    }
    if title.is_empty() || title.len() > 255 {
        return Err(AppError::Validation(vec![
            "Titel darf nicht leer sein und maximal 255 Zeichen umfassen.".to_string(),
        ]));
    }
    if !(1..=60).contains(&input.review_interval_months) {
        return Err(AppError::Validation(vec![
            "Prüfintervall muss zwischen 1 und 60 Monaten liegen.".to_string(),
        ]));
    }

    let doc_type = DocType::from_str(&input.doc_type)?;
    let source_type = SourceType::from_str(&input.source_type)?;
    let classification_level_id = Uuid::parse_str(input.classification_level_id.trim())
        .map_err(|_| AppError::Validation(vec!["Ungültige Schutzstufe.".to_string()]))?;

    let owner_unit_id = parse_optional_uuid(input.owner_unit_id.as_deref())?;
    let mut owner_user_id = parse_optional_uuid(input.owner_user_id.as_deref())?;
    if user.role == Role::Owner && owner_unit_id.is_none() && owner_user_id.is_none() {
        owner_user_id = Some(user.id);
    }
    ensure_owner_scope(&user, owner_unit_id, owner_user_id)?;

    let (content_markdown, attached_file_key, original_filename, file_sha256, external_url) =
        match source_type {
            SourceType::MarkdownEditor => {
                let md = input
                    .content_markdown
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| {
                        format!("# {title}\n\n<a id=\"einleitung\"></a>\n## 1. Geltungsbereich\n")
                    });
                (Some(md), None, None, None, None)
            }
            SourceType::UploadedFile => {
                let bytes = input.upload_bytes.ok_or_else(|| {
                    AppError::Validation(vec![
                        "Für den Quelltyp 'Hochgeladene Datei' muss eine Datei ausgewählt werden."
                            .to_string(),
                    ])
                })?;
                let stored = state
                    .storage
                    .put(&bytes, input.upload_content_type.as_deref())
                    .await?;
                let fname = input
                    .upload_filename
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| format!("{doc_code}.bin"));
                (
                    None,
                    Some(stored.storage_key),
                    Some(fname),
                    Some(stored.sha256_hex),
                    None,
                )
            }
            SourceType::ExternalLink => {
                let raw = input.external_url.unwrap_or_default();
                let validated = validate_external_url(&raw, state.config.is_production())?;
                (None, None, None, None, Some(validated))
            }
        };

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;

    let doc_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO documents (
            doc_code, title, doc_type, source_type,
            classification_level_id, owner_unit_id, owner_user_id,
            review_interval_months, requires_acknowledgment
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id
        "#,
    )
    .bind(&doc_code)
    .bind(&title)
    .bind(doc_type.as_str())
    .bind(source_type.as_str())
    .bind(classification_level_id)
    .bind(owner_unit_id)
    .bind(owner_user_id)
    .bind(input.review_interval_months)
    .bind(input.requires_acknowledgment)
    .fetch_one(&mut *tx)
    .await
    .map_err(|err| {
        if let sqlx::Error::Database(db_err) = &err
            && db_err.code().as_deref() == Some("23505")
        {
            return AppError::Conflict(format!(
                "Ein Dokument mit dem Code '{doc_code}' existiert bereits."
            ));
        }
        AppError::Database(err)
    })?;

    let version_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO document_versions (
            document_id, version_number, status,
            content_markdown, attached_file_key, original_filename, file_sha256, external_url,
            change_summary, author_id
        )
        VALUES ($1, '0.1', 'draft', $2, $3, $4, $5, $6, 'Erstentwurf', $7)
        RETURNING id
        "#,
    )
    .bind(doc_id)
    .bind(content_markdown)
    .bind(attached_file_key)
    .bind(original_filename)
    .bind(file_sha256)
    .bind(external_url)
    .bind(user.id)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    let target = if source_type == SourceType::MarkdownEditor {
        format!("/documents/{doc_id}/versions/{version_id}/edit")
    } else {
        format!("/documents/{doc_id}")
    };

    Ok(with_toast(
        hx_redirect_or_303(&headers, &target),
        "success",
        "Dokument als Entwurf 0.1 angelegt.",
    ))
}
