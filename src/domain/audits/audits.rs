use std::str::FromStr;

use askama::Template;
use axum::{
    extract::{Form, Multipart, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::NaiveDate;
use serde::Deserialize;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{
    audit::AuditService,
    auth::rbac::{ClientIp, CurrentUser, Role, forbid_auditor},
    db::begin_audited_tx,
    domain::audits::{
        AuditStatus, FindingStatus, FindingType, ensure_audit_read_access, ensure_finding_closable,
    },
    error::AppError,
    state::AppState,
    web::{ShellContext, hx_redirect_or_303, render_page, render_template, with_toast},
};

#[derive(Debug, Deserialize)]
pub struct AuditFilterQuery {
    pub status: Option<String>,
    pub finding_type: Option<String>,
    pub finding_status: Option<String>,
    pub q: Option<String>,
}

struct SelectOption {
    id: String,
    label: String,
}

struct AuditRowView {
    id: Uuid,
    audit_code: String,
    title: String,
    auditor_name: String,
    audit_date_label: String,
    status_label: &'static str,
    status_css: &'static str,
    open_findings_count: i64,
    has_report: bool,
}

struct FindingRowView {
    id: Uuid,
    audit_id: Uuid,
    audit_code: String,
    finding_code: String,
    finding_type_label: &'static str,
    finding_type_css: &'static str,
    status_str: String,
    status_label: &'static str,
    status_css: &'static str,
    control_code: String,
    unit_name: String,
    description: String,
}

#[derive(Template)]
#[template(path = "audits/list.html")]
struct AuditListTemplate {
    audits: Vec<AuditRowView>,
    findings: Vec<FindingRowView>,
    filter_status: String,
    filter_finding_type: String,
    filter_finding_status: String,
    filter_q: String,
    open_nc_count: usize,
    can_manage: bool,
    is_owner: bool,
}

#[derive(Template)]
#[template(path = "audits/new_drawer.html")]
struct NewAuditDrawerTemplate {
    default_date: String,
}

#[derive(Template)]
#[template(path = "audits/drawer.html")]
struct AuditDrawerTemplate {
    id: Uuid,
    audit_code: String,
    title: String,
    scope: String,
    auditor_name: String,
    audit_date_label: String,
    status_label: &'static str,
    status_css: &'static str,
    has_report: bool,
    attached_report_filename: String,
    findings: Vec<FindingRowView>,
}

#[derive(Template)]
#[template(path = "audits/detail.html")]
struct AuditDetailTemplate {
    id: Uuid,
    audit_code: String,
    title: String,
    scope: String,
    auditor_name: String,
    audit_date_input: String,
    audit_date_label: String,
    status: String,
    status_label: &'static str,
    status_css: &'static str,
    summary_report: String,
    has_report: bool,
    attached_report_filename: String,
    attached_report_sha256: String,
    findings: Vec<FindingRowView>,
    controls: Vec<SelectOption>,
    units: Vec<SelectOption>,
    can_manage: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateAuditForm {
    pub audit_code: Option<String>,
    pub title: String,
    pub scope: String,
    pub auditor_name: String,
    pub audit_date: String,
    pub status: Option<String>,
    pub summary_report: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAuditForm {
    pub title: String,
    pub scope: String,
    pub auditor_name: String,
    pub audit_date: String,
    pub status: String,
    pub summary_report: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateFindingForm {
    pub finding_code: Option<String>,
    pub finding_type: String,
    pub related_control_id: Option<String>,
    pub owner_unit_id: Option<String>,
    pub description: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateFindingStatusForm {
    pub status: String,
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

fn parse_required_date(raw: &str) -> Result<NaiveDate, AppError> {
    NaiveDate::parse_from_str(raw.trim(), "%Y-%m-%d").map_err(|_| {
        AppError::Validation(vec![
            "Ungültiges Datum (Format JJJJ-MM-TT erwartet).".to_string(),
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
        "auditbericht.pdf".to_string()
    } else {
        cleaned
    }
}

async fn ensure_audit_visible_to_user(
    pool: &PgPool,
    user: &CurrentUser,
    audit_id: Uuid,
) -> Result<(), AppError> {
    ensure_audit_read_access(user)?;
    if user.role != Role::Owner {
        return Ok(());
    }
    let Some(unit_id) = user.organization_unit_id else {
        return Err(AppError::Forbidden(
            "Keine Berechtigung für diese Aktion.".to_string(),
        ));
    };
    let has_own_finding: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM audit_findings WHERE audit_id = $1 AND owner_unit_id = $2)",
    )
    .bind(audit_id)
    .bind(unit_id)
    .fetch_one(pool)
    .await?;

    if !has_own_finding {
        return Err(AppError::Forbidden(
            "Keine Berechtigung für diese Aktion.".to_string(),
        ));
    }
    Ok(())
}

async fn load_findings_for_audit(
    pool: &PgPool,
    user: &CurrentUser,
    audit_id: Uuid,
) -> Result<Vec<FindingRowView>, AppError> {
    let owner_unit_filter = if user.role == Role::Owner {
        Some(user.organization_unit_id.unwrap_or_else(Uuid::nil))
    } else {
        None
    };

    let rows = sqlx::query(
        r#"
        SELECT
            af.id,
            af.audit_id,
            ia.audit_code,
            af.finding_code,
            af.finding_type,
            af.status,
            af.description,
            COALESCE(fc.code, '–') AS control_code,
            COALESCE(ou.name, 'Nicht zugewiesen') AS unit_name
        FROM audit_findings af
        JOIN internal_audits ia ON ia.id = af.audit_id
        LEFT JOIN framework_controls fc ON fc.id = af.related_control_id
        LEFT JOIN organization_units ou ON ou.id = af.owner_unit_id
        WHERE af.audit_id = $1
          AND ($2::uuid IS NULL OR af.owner_unit_id = $2)
        ORDER BY af.finding_code ASC
        "#,
    )
    .bind(audit_id)
    .bind(owner_unit_filter)
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let ftype = FindingType::from_str(r.get::<&str, _>("finding_type"))?;
        let fstatus = FindingStatus::from_str(r.get::<&str, _>("status"))?;
        out.push(FindingRowView {
            id: r.get("id"),
            audit_id: r.get("audit_id"),
            audit_code: r.get("audit_code"),
            finding_code: r.get("finding_code"),
            finding_type_label: ftype.short_label(),
            finding_type_css: ftype.css_class(),
            status_str: fstatus.as_str().to_string(),
            status_label: fstatus.label(),
            status_css: fstatus.css_class(),
            control_code: r.get("control_code"),
            unit_name: r.get("unit_name"),
            description: r.get("description"),
        });
    }
    Ok(out)
}

pub async fn list_audits_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Query(filter): Query<AuditFilterQuery>,
) -> Result<impl IntoResponse, AppError> {
    ensure_audit_read_access(&user)?;

    let filter_status = filter.status.unwrap_or_default().trim().to_string();
    let filter_finding_type = filter.finding_type.unwrap_or_default().trim().to_string();
    let filter_finding_status = filter.finding_status.unwrap_or_default().trim().to_string();
    let filter_q = filter.q.unwrap_or_default().trim().to_string();
    let like_q = format!("%{filter_q}%");

    let owner_unit_filter = if user.role == Role::Owner {
        Some(user.organization_unit_id.unwrap_or_else(Uuid::nil))
    } else {
        None
    };

    let audit_rows = sqlx::query(
        r#"
        SELECT
            ia.id,
            ia.audit_code,
            ia.title,
            ia.auditor_name,
            ia.audit_date,
            ia.status,
            ia.attached_report_key,
            (
                SELECT COUNT(*)
                FROM audit_findings af
                WHERE af.audit_id = ia.id
                  AND af.status <> 'verified_closed'
                  AND ($1::uuid IS NULL OR af.owner_unit_id = $1)
            ) AS open_findings_count
        FROM internal_audits ia
        WHERE ($2 = '' OR ia.status = $2)
          AND ($3 = '' OR ia.audit_code ILIKE $4 OR ia.title ILIKE $4 OR ia.auditor_name ILIKE $4)
          AND (
              $1::uuid IS NULL
              OR EXISTS (
                  SELECT 1 FROM audit_findings af
                  WHERE af.audit_id = ia.id AND af.owner_unit_id = $1
              )
          )
        ORDER BY ia.audit_date DESC, ia.audit_code DESC
        "#,
    )
    .bind(owner_unit_filter)
    .bind(&filter_status)
    .bind(&filter_q)
    .bind(&like_q)
    .fetch_all(&state.pool)
    .await?;

    let mut audits = Vec::with_capacity(audit_rows.len());
    for r in audit_rows {
        let status = AuditStatus::from_str(r.get::<&str, _>("status"))?;
        let audit_date: NaiveDate = r.get("audit_date");
        let report_key: Option<String> = r.get("attached_report_key");
        audits.push(AuditRowView {
            id: r.get("id"),
            audit_code: r.get("audit_code"),
            title: r.get("title"),
            auditor_name: r.get("auditor_name"),
            audit_date_label: audit_date.format("%d.%m.%Y").to_string(),
            status_label: status.label(),
            status_css: status.css_class(),
            open_findings_count: r.get("open_findings_count"),
            has_report: report_key.is_some(),
        });
    }

    let finding_rows = sqlx::query(
        r#"
        SELECT
            af.id,
            af.audit_id,
            ia.audit_code,
            af.finding_code,
            af.finding_type,
            af.status,
            af.description,
            COALESCE(fc.code, '–') AS control_code,
            COALESCE(ou.name, 'Nicht zugewiesen') AS unit_name
        FROM audit_findings af
        JOIN internal_audits ia ON ia.id = af.audit_id
        LEFT JOIN framework_controls fc ON fc.id = af.related_control_id
        LEFT JOIN organization_units ou ON ou.id = af.owner_unit_id
        WHERE ($1::uuid IS NULL OR af.owner_unit_id = $1)
          AND ($2 = '' OR af.finding_type = $2)
          AND ($3 = '' OR af.status = $3)
          AND ($4 = '' OR af.finding_code ILIKE $5 OR af.description ILIKE $5 OR ia.audit_code ILIKE $5)
        ORDER BY (af.status = 'verified_closed') ASC,
                 (af.finding_type = 'major_nc') DESC,
                 af.created_at DESC
        "#,
    )
    .bind(owner_unit_filter)
    .bind(&filter_finding_type)
    .bind(&filter_finding_status)
    .bind(&filter_q)
    .bind(&like_q)
    .fetch_all(&state.pool)
    .await?;

    let mut findings = Vec::with_capacity(finding_rows.len());
    let mut open_nc_count = 0usize;
    for r in finding_rows {
        let ftype = FindingType::from_str(r.get::<&str, _>("finding_type"))?;
        let fstatus = FindingStatus::from_str(r.get::<&str, _>("status"))?;
        if fstatus != FindingStatus::VerifiedClosed && ftype.requires_capa_verification() {
            open_nc_count += 1;
        }
        findings.push(FindingRowView {
            id: r.get("id"),
            audit_id: r.get("audit_id"),
            audit_code: r.get("audit_code"),
            finding_code: r.get("finding_code"),
            finding_type_label: ftype.short_label(),
            finding_type_css: ftype.css_class(),
            status_str: fstatus.as_str().to_string(),
            status_label: fstatus.label(),
            status_css: fstatus.css_class(),
            control_code: r.get("control_code"),
            unit_name: r.get("unit_name"),
            description: r.get("description"),
        });
    }

    let shell = ShellContext::from_user(
        &user,
        "Interne Audits & Findings",
        "Betrieb (PDCA & NIS2)",
        "audits",
    );
    render_page(
        &headers,
        shell,
        &AuditListTemplate {
            audits,
            findings,
            filter_status,
            filter_finding_type,
            filter_finding_status,
            filter_q,
            open_nc_count,
            can_manage: user.role.is_iso_or_admin(),
            is_owner: user.role == Role::Owner,
        },
    )
}

pub async fn new_audit_drawer_handler(user: CurrentUser) -> Result<impl IntoResponse, AppError> {
    forbid_auditor(&user)?;
    if !user.role.is_iso_or_admin() {
        return Err(AppError::Forbidden(
            "Keine Berechtigung für diese Aktion.".to_string(),
        ));
    }
    let default_date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    render_template(&NewAuditDrawerTemplate { default_date })
}

pub async fn create_audit_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Form(form): Form<CreateAuditForm>,
) -> Result<Response, AppError> {
    forbid_auditor(&user)?;
    if !user.role.is_iso_or_admin() {
        return Err(AppError::Forbidden(
            "Keine Berechtigung für diese Aktion.".to_string(),
        ));
    }

    let title = form.title.trim();
    let scope = form.scope.trim();
    let auditor_name = form.auditor_name.trim();
    if title.is_empty() || scope.is_empty() || auditor_name.is_empty() {
        return Err(AppError::Validation(vec![
            "Titel, Audit-Scope und Lead-Auditor sind Pflichtfelder.".to_string(),
        ]));
    }
    let audit_date = parse_required_date(&form.audit_date)?;
    let status = match form
        .status
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => AuditStatus::from_str(raw)?,
        None => AuditStatus::Planned,
    };

    let raw_code = form.audit_code.as_deref().map(str::trim).unwrap_or("");
    let audit_code = if raw_code.is_empty() {
        let short = Uuid::new_v4().simple().to_string();
        format!(
            "AUD-{}-{}",
            audit_date.format("%Y"),
            short[..6].to_ascii_uppercase()
        )
    } else {
        if raw_code.len() > 32 {
            return Err(AppError::Validation(vec![
                "Audit-Code darf maximal 32 Zeichen lang sein.".to_string(),
            ]));
        }
        raw_code.to_string()
    };

    let summary_report = form
        .summary_report
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;
    let audit_id = Uuid::new_v4();
    let res = sqlx::query(
        r#"
        INSERT INTO internal_audits (
            id, audit_code, title, scope, auditor_name, audit_date, status, summary_report
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(audit_id)
    .bind(&audit_code)
    .bind(title)
    .bind(scope)
    .bind(auditor_name)
    .bind(audit_date)
    .bind(status.as_str())
    .bind(summary_report)
    .execute(&mut *tx)
    .await;

    if let Err(sqlx::Error::Database(ref db_err)) = res
        && db_err.is_unique_violation()
    {
        return Err(AppError::Validation(vec![format!(
            "Audit-Code '{audit_code}' ist bereits vergeben."
        )]));
    }
    res?;
    tx.commit().await?;

    let resp = hx_redirect_or_303(&headers, &format!("/audits/{audit_id}"));
    Ok(with_toast(resp, "success", "Internes Audit angelegt."))
}

pub async fn audit_drawer_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(audit_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    ensure_audit_visible_to_user(&state.pool, &user, audit_id).await?;

    let row = sqlx::query(
        r#"
        SELECT id, audit_code, title, scope, auditor_name, audit_date, status,
               attached_report_key, attached_report_filename
        FROM internal_audits
        WHERE id = $1
        "#,
    )
    .bind(audit_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Internes Audit nicht gefunden.".to_string()))?;

    let status = AuditStatus::from_str(row.get::<&str, _>("status"))?;
    let audit_date: NaiveDate = row.get("audit_date");
    let report_key: Option<String> = row.get("attached_report_key");
    let findings = load_findings_for_audit(&state.pool, &user, audit_id).await?;

    render_template(&AuditDrawerTemplate {
        id: row.get("id"),
        audit_code: row.get("audit_code"),
        title: row.get("title"),
        scope: row.get("scope"),
        auditor_name: row.get("auditor_name"),
        audit_date_label: audit_date.format("%d.%m.%Y").to_string(),
        status_label: status.label(),
        status_css: status.css_class(),
        has_report: report_key.is_some(),
        attached_report_filename: row
            .get::<Option<String>, _>("attached_report_filename")
            .unwrap_or_default(),
        findings,
    })
}

pub async fn audit_detail_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Path(audit_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    ensure_audit_visible_to_user(&state.pool, &user, audit_id).await?;

    let row = sqlx::query(
        r#"
        SELECT id, audit_code, title, scope, auditor_name, audit_date, status,
               summary_report, attached_report_key, attached_report_filename, attached_report_sha256
        FROM internal_audits
        WHERE id = $1
        "#,
    )
    .bind(audit_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Internes Audit nicht gefunden.".to_string()))?;

    let status = AuditStatus::from_str(row.get::<&str, _>("status"))?;
    let audit_date: NaiveDate = row.get("audit_date");
    let audit_code: String = row.get("audit_code");
    let title: String = row.get("title");
    let report_key: Option<String> = row.get("attached_report_key");
    let findings = load_findings_for_audit(&state.pool, &user, audit_id).await?;

    let control_rows = sqlx::query(
        r#"
        SELECT fc.id, fc.code, fc.title
        FROM framework_controls fc
        JOIN compliance_frameworks cf ON cf.id = fc.framework_id
        WHERE cf.is_active = TRUE
        ORDER BY (cf.code = 'ISO27001_2022_STARTER') DESC, fc.sort_order ASC, fc.code ASC
        "#,
    )
    .fetch_all(&state.pool)
    .await?;
    let controls = control_rows
        .into_iter()
        .map(|r| SelectOption {
            id: r.get::<Uuid, _>("id").to_string(),
            label: format!(
                "{} · {}",
                r.get::<&str, _>("code"),
                r.get::<&str, _>("title")
            ),
        })
        .collect();

    let unit_rows = sqlx::query("SELECT id, name FROM organization_units ORDER BY name ASC")
        .fetch_all(&state.pool)
        .await?;
    let units = unit_rows
        .into_iter()
        .map(|r| SelectOption {
            id: r.get::<Uuid, _>("id").to_string(),
            label: r.get("name"),
        })
        .collect();

    let page_title = format!("{audit_code} · {title}");
    let shell = ShellContext::from_user(&user, &page_title, "Interne Audits", "audits");
    render_page(
        &headers,
        shell,
        &AuditDetailTemplate {
            id: row.get("id"),
            audit_code,
            title,
            scope: row.get("scope"),
            auditor_name: row.get("auditor_name"),
            audit_date_input: audit_date.format("%Y-%m-%d").to_string(),
            audit_date_label: audit_date.format("%d.%m.%Y").to_string(),
            status: status.as_str().to_string(),
            status_label: status.label(),
            status_css: status.css_class(),
            summary_report: row
                .get::<Option<String>, _>("summary_report")
                .unwrap_or_default(),
            has_report: report_key.is_some(),
            attached_report_filename: row
                .get::<Option<String>, _>("attached_report_filename")
                .unwrap_or_default(),
            attached_report_sha256: row
                .get::<Option<String>, _>("attached_report_sha256")
                .unwrap_or_default(),
            findings,
            controls,
            units,
            can_manage: user.role.is_iso_or_admin(),
        },
    )
}

pub async fn update_audit_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Path(audit_id): Path<Uuid>,
    Form(form): Form<UpdateAuditForm>,
) -> Result<Response, AppError> {
    forbid_auditor(&user)?;
    if !user.role.is_iso_or_admin() {
        return Err(AppError::Forbidden(
            "Keine Berechtigung für diese Aktion.".to_string(),
        ));
    }

    let title = form.title.trim();
    let scope = form.scope.trim();
    let auditor_name = form.auditor_name.trim();
    if title.is_empty() || scope.is_empty() || auditor_name.is_empty() {
        return Err(AppError::Validation(vec![
            "Titel, Audit-Scope und Lead-Auditor dürfen nicht leer sein.".to_string(),
        ]));
    }
    let audit_date = parse_required_date(&form.audit_date)?;
    let status = AuditStatus::from_str(&form.status)?;
    let summary_report = form
        .summary_report
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;
    let res = sqlx::query(
        r#"
        UPDATE internal_audits
        SET title = $2,
            scope = $3,
            auditor_name = $4,
            audit_date = $5,
            status = $6,
            summary_report = $7,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(audit_id)
    .bind(title)
    .bind(scope)
    .bind(auditor_name)
    .bind(audit_date)
    .bind(status.as_str())
    .bind(summary_report)
    .execute(&mut *tx)
    .await?;

    if res.rows_affected() == 0 {
        return Err(AppError::NotFound(
            "Internes Audit nicht gefunden.".to_string(),
        ));
    }
    tx.commit().await?;

    let resp = hx_redirect_or_303(&headers, &format!("/audits/{audit_id}"));
    Ok(with_toast(resp, "success", "Auditdaten aktualisiert."))
}

pub async fn upload_audit_report_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Path(audit_id): Path<Uuid>,
    mut multipart: Multipart,
) -> Result<Response, AppError> {
    forbid_auditor(&user)?;
    if !user.role.is_iso_or_admin() {
        return Err(AppError::Forbidden(
            "Keine Berechtigung für diese Aktion.".to_string(),
        ));
    }

    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM internal_audits WHERE id = $1)")
            .bind(audit_id)
            .fetch_one(&state.pool)
            .await?;
    if !exists {
        return Err(AppError::NotFound(
            "Internes Audit nicht gefunden.".to_string(),
        ));
    }

    let mut file_bytes: Option<Vec<u8>> = None;
    let mut file_name = String::from("auditbericht.pdf");
    let mut declared_mime: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| AppError::Validation(vec!["Ungültiges Upload-Formular.".to_string()]))?
    {
        if field.name() == Some("report_file") {
            if let Some(name) = field.file_name() {
                let trimmed = name.trim();
                if !trimmed.is_empty() {
                    file_name = trimmed.to_string();
                }
            }
            declared_mime = field.content_type().map(ToString::to_string);
            let data = field.bytes().await.map_err(|_| {
                AppError::Validation(vec![
                    "Hochgeladene Datei konnte nicht gelesen werden.".to_string(),
                ])
            })?;
            if data.len() > state.config.max_upload_bytes {
                return Err(AppError::Validation(vec![
                    "Der hochgeladene Bericht überschreitet die maximale Dateigröße.".to_string(),
                ]));
            }
            if !data.is_empty() {
                file_bytes = Some(data.to_vec());
            }
        }
    }

    let bytes = file_bytes
        .ok_or_else(|| AppError::Validation(vec!["Bitte eine PDF-Datei auswählen.".to_string()]))?;

    let stored = state.storage.put(&bytes, declared_mime.as_deref()).await?;

    if stored.content_type != "application/pdf" {
        let _ = state.storage.delete(&stored.storage_key).await;
        return Err(AppError::Validation(vec![
            "Als externer Auditbericht sind ausschließlich gültige PDF-Dateien zulässig."
                .to_string(),
        ]));
    }

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;
    sqlx::query(
        r#"
        UPDATE internal_audits
        SET attached_report_key = $2,
            attached_report_filename = $3,
            attached_report_sha256 = $4,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(audit_id)
    .bind(&stored.storage_key)
    .bind(&file_name)
    .bind(&stored.sha256_hex)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let resp = hx_redirect_or_303(&headers, &format!("/audits/{audit_id}"));
    Ok(with_toast(
        resp,
        "success",
        "Auditbericht (PDF) revisionssicher gespeichert.",
    ))
}

pub async fn download_audit_report_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    Path(audit_id): Path<Uuid>,
) -> Result<Response, AppError> {
    ensure_audit_visible_to_user(&state.pool, &user, audit_id).await?;

    let row = sqlx::query(
        r#"
        SELECT audit_code, attached_report_key, attached_report_filename
        FROM internal_audits
        WHERE id = $1
        "#,
    )
    .bind(audit_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Internes Audit nicht gefunden.".to_string()))?;

    let storage_key: String = row
        .get::<Option<String>, _>("attached_report_key")
        .ok_or_else(|| AppError::NotFound("Kein externer Auditbericht hinterlegt.".to_string()))?;
    let audit_code: String = row.get("audit_code");
    let filename = sanitize_download_filename(
        row.get::<Option<String>, _>("attached_report_filename")
            .as_deref()
            .unwrap_or("auditbericht.pdf"),
    );

    let bytes = state.storage.get(&storage_key).await?;

    AuditService::log_event(
        &state.pool,
        Some(user.id),
        Some(client_ip),
        "internal_audit.report_downloaded",
        "internal_audits",
        &audit_id.to_string(),
        &format!("Auditbericht zu {audit_code} heruntergeladen."),
        None,
        None,
    )
    .await?;

    let disposition = format!("attachment; filename=\"{filename}\"");
    let mut resp = (StatusCode::OK, bytes).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/pdf"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(val) = HeaderValue::from_str(&disposition) {
        h.insert(header::CONTENT_DISPOSITION, val);
    }
    Ok(resp)
}

pub async fn create_finding_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Path(audit_id): Path<Uuid>,
    Form(form): Form<CreateFindingForm>,
) -> Result<Response, AppError> {
    forbid_auditor(&user)?;
    if !user.role.is_iso_or_admin() {
        return Err(AppError::Forbidden(
            "Keine Berechtigung für diese Aktion.".to_string(),
        ));
    }

    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM internal_audits WHERE id = $1)")
            .bind(audit_id)
            .fetch_one(&state.pool)
            .await?;
    if !exists {
        return Err(AppError::NotFound(
            "Internes Audit nicht gefunden.".to_string(),
        ));
    }

    let description = form.description.trim();
    if description.is_empty() {
        return Err(AppError::Validation(vec![
            "Beschreibung der Feststellung darf nicht leer sein.".to_string(),
        ]));
    }
    let finding_type = FindingType::from_str(&form.finding_type)?;
    let related_control_id = parse_optional_uuid(form.related_control_id.as_deref())?;
    let owner_unit_id = parse_optional_uuid(form.owner_unit_id.as_deref())?;

    let raw_code = form.finding_code.as_deref().map(str::trim).unwrap_or("");
    let finding_code = if raw_code.is_empty() {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_findings WHERE audit_id = $1")
                .bind(audit_id)
                .fetch_one(&state.pool)
                .await?;
        format!("FND-{:02}", count + 1)
    } else {
        if raw_code.len() > 32 {
            return Err(AppError::Validation(vec![
                "Finding-Code darf maximal 32 Zeichen lang sein.".to_string(),
            ]));
        }
        raw_code.to_string()
    };

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;
    let res = sqlx::query(
        r#"
        INSERT INTO audit_findings (
            audit_id, finding_code, finding_type, related_control_id, owner_unit_id, description, status
        )
        VALUES ($1, $2, $3, $4, $5, $6, 'open')
        "#,
    )
    .bind(audit_id)
    .bind(&finding_code)
    .bind(finding_type.as_str())
    .bind(related_control_id)
    .bind(owner_unit_id)
    .bind(description)
    .execute(&mut *tx)
    .await;

    if let Err(sqlx::Error::Database(ref db_err)) = res
        && db_err.is_unique_violation()
    {
        return Err(AppError::Validation(vec![format!(
            "Finding-Code '{finding_code}' existiert in diesem Audit bereits."
        )]));
    }
    res?;
    tx.commit().await?;

    let resp = hx_redirect_or_303(&headers, &format!("/audits/{audit_id}"));
    Ok(with_toast(resp, "success", "Audit-Feststellung erfasst."))
}

pub async fn update_finding_status_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    Path(finding_id): Path<Uuid>,
    Form(form): Form<UpdateFindingStatusForm>,
) -> Result<Response, AppError> {
    forbid_auditor(&user)?;
    if !user.role.is_iso_or_admin() {
        return Err(AppError::Forbidden(
            "Keine Berechtigung für diese Aktion.".to_string(),
        ));
    }

    let target_status = FindingStatus::from_str(&form.status)?;

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(client_ip)).await?;
    let row =
        sqlx::query("SELECT audit_id, finding_type FROM audit_findings WHERE id = $1 FOR UPDATE")
            .bind(finding_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| AppError::NotFound("Audit-Feststellung nicht gefunden.".to_string()))?;

    let audit_id: Uuid = row.get("audit_id");
    let finding_type = FindingType::from_str(row.get::<&str, _>("finding_type"))?;

    ensure_finding_closable(&mut tx, &user, finding_id, finding_type, target_status).await?;

    sqlx::query("UPDATE audit_findings SET status = $2, updated_at = NOW() WHERE id = $1")
        .bind(finding_id)
        .bind(target_status.as_str())
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    let resp = hx_redirect_or_303(&headers, &format!("/audits/{audit_id}"));
    Ok(with_toast(resp, "success", "Finding-Status aktualisiert."))
}
