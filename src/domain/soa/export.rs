use std::str::FromStr;

use axum::{
    extract::{Query, State},
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use chrono::Utc;
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    audit::AuditService,
    auth::rbac::{ClientIp, CurrentUser, Role},
    domain::soa::{ImplementationStatus, domain_display_label},
    error::AppError,
    pdf::{PdfDocumentMetadata, PdfRenderer, TypstCliRenderer},
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct SoaExportQuery {
    pub framework: Option<String>,
    pub delimiter: Option<String>,
}

struct SoaExportRow {
    code: String,
    domain: String,
    title: String,
    is_applicable: bool,
    justification: String,
    status: ImplementationStatus,
    owner_label: String,
    evidences_summary: String,
}

async fn load_export_rows(
    pool: &sqlx::PgPool,
    requested_framework: Option<&str>,
) -> Result<(String, String, Vec<SoaExportRow>), AppError> {
    let fw_rows = sqlx::query(
        r#"
        SELECT id, code, name
        FROM compliance_frameworks
        WHERE is_active = TRUE
        ORDER BY (code = 'ISO27001_2022_STARTER') DESC, name ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    if fw_rows.is_empty() {
        return Err(AppError::NotFound(
            "Kein aktives Compliance-Framework gefunden.".to_string(),
        ));
    }

    let req = requested_framework.unwrap_or("").trim();
    let mut fw_id: Uuid = fw_rows[0].get("id");
    let mut fw_code: String = fw_rows[0].get("code");
    let mut fw_name: String = fw_rows[0].get("name");
    for r in &fw_rows {
        let c: &str = r.get("code");
        if !req.is_empty() && c.eq_ignore_ascii_case(req) {
            fw_id = r.get("id");
            fw_code = c.to_string();
            fw_name = r.get("name");
            break;
        }
    }

    let rows = sqlx::query(
        r#"
        SELECT
            fc.code,
            fc.domain,
            fc.title,
            se.is_applicable,
            se.justification,
            se.implementation_status,
            COALESCE(u.full_name, ou.name, 'Nicht zugewiesen') AS owner_label,
            COALESCE(
                (
                    SELECT string_agg(ce.title, '; ' ORDER BY ce.created_at DESC)
                    FROM control_evidences ce
                    WHERE ce.soa_entry_id = se.id
                ),
                ''
            ) AS evidences_summary
        FROM framework_controls fc
        JOIN soa_entries se ON se.control_id = fc.id
        LEFT JOIN users u ON u.id = se.owner_user_id
        LEFT JOIN organization_units ou ON ou.id = se.owner_unit_id
        WHERE fc.framework_id = $1
        ORDER BY fc.sort_order ASC, fc.code ASC
        "#,
    )
    .bind(fw_id)
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let status = ImplementationStatus::from_str(r.get::<&str, _>("implementation_status"))?;
        out.push(SoaExportRow {
            code: r.get("code"),
            domain: domain_display_label(r.get::<&str, _>("domain")).to_string(),
            title: r.get("title"),
            is_applicable: r.get("is_applicable"),
            justification: r.get("justification"),
            status,
            owner_label: r.get("owner_label"),
            evidences_summary: r.get("evidences_summary"),
        });
    }

    Ok((fw_code, fw_name, out))
}

fn escape_md_cell(s: &str) -> String {
    s.replace('|', "\\|")
        .replace(['\r', '\n'], " ")
        .trim()
        .to_string()
}

fn csv_cell(s: &str, sep: char) -> String {
    let needs_quotes = s.contains(sep) || s.contains('"') || s.contains('\n') || s.contains('\r');
    if needs_quotes {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

pub async fn render_soa_pdf_bytes(
    pool: &sqlx::PgPool,
    config: &crate::config::Config,
    requested_framework: Option<&str>,
    actor_name: &str,
) -> Result<(String, usize, Vec<u8>), AppError> {
    let (fw_code, fw_name, rows) = load_export_rows(pool, requested_framework).await?;

    let company_name: String =
        sqlx::query_scalar("SELECT company_name FROM organization_profile WHERE id = 1")
            .fetch_optional(pool)
            .await?
            .unwrap_or_else(|| "Meine Organisation".to_string());

    let total = rows.len();
    let applicable = rows.iter().filter(|r| r.is_applicable).count();
    let not_applicable = total - applicable;
    let implemented = rows
        .iter()
        .filter(|r| {
            r.is_applicable
                && matches!(
                    r.status,
                    ImplementationStatus::Implemented | ImplementationStatus::Verified
                )
        })
        .count();
    let verified = rows
        .iter()
        .filter(|r| r.is_applicable && r.status == ImplementationStatus::Verified)
        .count();

    let mut md = String::new();
    md.push_str("# 1. Zusammenfassung der Anwendbarkeit\n\n");
    md.push_str(&format!("- **Framework:** {fw_name} (`{fw_code}`)\n"));
    md.push_str(&format!("- **Controls gesamt:** {total}\n"));
    md.push_str(&format!("- **Anwendbar:** {applicable}\n"));
    md.push_str(&format!("- **Ausgeschlossen (N/A):** {not_applicable}\n"));
    md.push_str(&format!(
        "- **Umgesetzt / Verifiziert:** {implemented} (davon verifiziert: {verified})\n\n"
    ));

    md.push_str("# 2. Statement of Applicability (Einzelbewertung)\n\n");
    md.push_str("| Code | Domäne | Control | Anwendbar | Status | Begründung & Nachweise |\n");
    md.push_str("|---|---|---|---|---|---|\n");

    for row in &rows {
        let app_label = if row.is_applicable { "Ja" } else { "Nein" };
        let mut details = Vec::new();
        if !row.justification.trim().is_empty() {
            details.push(format!(
                "Begründung: {}",
                escape_md_cell(&row.justification)
            ));
        }
        if !row.evidences_summary.trim().is_empty() {
            details.push(format!(
                "Nachweise: {}",
                escape_md_cell(&row.evidences_summary)
            ));
        }
        if details.is_empty() {
            details.push("–".to_string());
        }
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            escape_md_cell(&row.code),
            escape_md_cell(&row.domain),
            escape_md_cell(&row.title),
            app_label,
            row.status.label(),
            details.join(" · "),
        ));
    }

    let today = Utc::now().format("%d.%m.%Y").to_string();
    let meta = PdfDocumentMetadata {
        organization_name: company_name,
        doc_code: format!("SOA-{fw_code}"),
        title: format!("Statement of Applicability – {fw_name}"),
        version: Utc::now().format("%Y-%m-%d").to_string(),
        status: "Berichtsstand".to_string(),
        classification: "C2 – Intern".to_string(),
        owner_unit: "Informationssicherheit (ISB)".to_string(),
        approved_by: actor_name.to_string(),
        approved_at: today,
        next_review_at: "Gemäß ISMS-Zyklus".to_string(),
    };

    let renderer = TypstCliRenderer::from_config(config);
    let pdf_bytes = renderer.render_markdown_document(&meta, &md).await?;
    Ok((fw_code, total, pdf_bytes))
}

pub async fn export_soa_pdf_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    Query(query): Query<SoaExportQuery>,
) -> Result<Response, AppError> {
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Kein Zugriff auf den SoA-Export.".to_string(),
        ));
    }

    let (fw_code, total, pdf_bytes) = render_soa_pdf_bytes(
        &state.pool,
        &state.config,
        query.framework.as_deref(),
        &user.full_name,
    )
    .await?;

    let _ = AuditService::log_event(
        &state.pool,
        Some(user.id),
        Some(client_ip),
        "soa.exported_pdf",
        "compliance_frameworks",
        &fw_code,
        &format!("SoA-PDF-Export für {fw_code} ({total} Controls)"),
        None,
        Some(serde_json::json!({ "framework": fw_code, "count": total })),
    )
    .await;

    let mut resp = Response::new(axum::body::Body::from(pdf_bytes));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/pdf"),
    );
    resp.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(disp) = HeaderValue::from_str(&format!("attachment; filename=\"soa-{fw_code}.pdf\""))
    {
        resp.headers_mut().insert(header::CONTENT_DISPOSITION, disp);
    }
    Ok(resp)
}

pub async fn render_soa_csv_bytes(
    pool: &sqlx::PgPool,
    requested_framework: Option<&str>,
    sep: char,
) -> Result<(String, usize, Vec<u8>), AppError> {
    let (fw_code, _fw_name, rows) = load_export_rows(pool, requested_framework).await?;
    let total = rows.len();

    let mut csv = String::new();
    // UTF-8 BOM für reibungslosen Excel-Import mit deutschen Umlauten
    csv.push('\u{FEFF}');
    let headers = [
        "Framework",
        "Code",
        "Domäne",
        "Titel",
        "Anwendbar",
        "Umsetzungsstatus",
        "Verantwortlich",
        "Begründung",
        "Nachweise",
    ];
    csv.push_str(
        &headers
            .iter()
            .map(|h| csv_cell(h, sep))
            .collect::<Vec<_>>()
            .join(&sep.to_string()),
    );
    csv.push('\n');

    for row in &rows {
        let app = if row.is_applicable { "Ja" } else { "Nein" };
        let line = [
            csv_cell(&fw_code, sep),
            csv_cell(&row.code, sep),
            csv_cell(&row.domain, sep),
            csv_cell(&row.title, sep),
            csv_cell(app, sep),
            csv_cell(row.status.label(), sep),
            csv_cell(&row.owner_label, sep),
            csv_cell(&row.justification, sep),
            csv_cell(&row.evidences_summary, sep),
        ]
        .join(&sep.to_string());
        csv.push_str(&line);
        csv.push('\n');
    }

    Ok((fw_code, total, csv.into_bytes()))
}

pub async fn export_soa_csv_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(client_ip): ClientIp,
    Query(query): Query<SoaExportQuery>,
) -> Result<Response, AppError> {
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Kein Zugriff auf den SoA-Export.".to_string(),
        ));
    }

    let sep = match query.delimiter.as_deref().map(str::trim) {
        Some("comma" | ",") => ',',
        _ => ';',
    };

    let (fw_code, total, csv_bytes) =
        render_soa_csv_bytes(&state.pool, query.framework.as_deref(), sep).await?;

    let _ = AuditService::log_event(
        &state.pool,
        Some(user.id),
        Some(client_ip),
        "soa.exported_csv",
        "compliance_frameworks",
        &fw_code,
        &format!("SoA-CSV-Export für {fw_code} ({total} Controls)"),
        None,
        Some(serde_json::json!({ "framework": fw_code, "count": total })),
    )
    .await;

    let mut resp = Response::new(axum::body::Body::from(csv_bytes));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    resp.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(disp) = HeaderValue::from_str(&format!("attachment; filename=\"soa-{fw_code}.csv\""))
    {
        resp.headers_mut().insert(header::CONTENT_DISPOSITION, disp);
    }
    Ok(resp)
}
