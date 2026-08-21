use std::str::FromStr;

use axum::{
    extract::{Query, State},
    http::{HeaderValue, StatusCode, header},
    response::Response,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::Row;

use crate::{
    audit::AuditService,
    auth::rbac::{ClientIp, CurrentUser, Role},
    domain::risks::{RiskRating, RiskStatus, TreatmentStrategy, risk_score},
    error::AppError,
    pdf::{
        PdfDocumentMetadata, PdfRenderer, TypstCliRenderer, build_iso_document_typst, escape_typst,
    },
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct RiskExportQuery {
    pub delimiter: Option<String>,
}

struct RiskExportRow {
    reference_code: String,
    title: String,
    asset_label: String,
    owner_label: String,
    inherent_likelihood: i16,
    inherent_impact: i16,
    inherent_score: i16,
    inherent_rating: RiskRating,
    residual_likelihood: i16,
    residual_impact: i16,
    residual_score: i16,
    residual_rating: RiskRating,
    strategy: TreatmentStrategy,
    status: RiskStatus,
    treatment_plan: String,
    acceptance_justification: String,
    accepted_by_name: String,
    accepted_at: Option<DateTime<Utc>>,
    controls_summary: String,
}

async fn load_export_rows(pool: &sqlx::PgPool) -> Result<Vec<RiskExportRow>, AppError> {
    let rows = sqlx::query(
        r#"
        SELECT
            rs.reference_code,
            rs.title,
            rs.inherent_likelihood,
            rs.inherent_impact,
            rs.residual_likelihood,
            rs.residual_impact,
            rs.treatment_strategy,
            rs.status,
            COALESCE(rs.treatment_plan, '') AS treatment_plan,
            COALESCE(rs.acceptance_justification, '') AS acceptance_justification,
            COALESCE(au.full_name, '') AS accepted_by_name,
            rs.accepted_at,
            COALESCE(
                NULLIF(CONCAT_WS(' / ', ia.name, sa.asset_code), ''),
                'Allgemein'
            ) AS asset_label,
            COALESCE(u.full_name, ou.name, 'Nicht zugewiesen') AS owner_label,
            COALESCE(
                (
                    SELECT string_agg(fc.code, ', ' ORDER BY fc.code ASC)
                    FROM risk_control_links rcl
                    JOIN soa_entries se ON se.id = rcl.soa_entry_id
                    JOIN framework_controls fc ON fc.id = se.control_id
                    WHERE rcl.risk_id = rs.id
                ),
                ''
            ) AS controls_summary
        FROM risk_scenarios rs
        LEFT JOIN information_assets ia ON ia.id = rs.affected_information_asset_id
        LEFT JOIN system_assets sa ON sa.id = rs.affected_system_asset_id
        LEFT JOIN users u ON u.id = rs.owner_user_id
        LEFT JOIN organization_units ou ON ou.id = rs.owner_unit_id
        LEFT JOIN users au ON au.id = rs.accepted_by_user_id
        ORDER BY (rs.residual_likelihood * rs.residual_impact) DESC, rs.reference_code ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let inh_l: i16 = r.get("inherent_likelihood");
        let inh_i: i16 = r.get("inherent_impact");
        let res_l: i16 = r.get("residual_likelihood");
        let res_i: i16 = r.get("residual_impact");
        let inh_score = risk_score(inh_l, inh_i);
        let res_score = risk_score(res_l, res_i);
        out.push(RiskExportRow {
            reference_code: r.get("reference_code"),
            title: r.get("title"),
            asset_label: r.get("asset_label"),
            owner_label: r.get("owner_label"),
            inherent_likelihood: inh_l,
            inherent_impact: inh_i,
            inherent_score: inh_score,
            inherent_rating: RiskRating::from_score(inh_score),
            residual_likelihood: res_l,
            residual_impact: res_i,
            residual_score: res_score,
            residual_rating: RiskRating::from_score(res_score),
            strategy: TreatmentStrategy::from_str(r.get::<&str, _>("treatment_strategy"))?,
            status: RiskStatus::from_str(r.get::<&str, _>("status"))?,
            treatment_plan: r.get("treatment_plan"),
            acceptance_justification: r.get("acceptance_justification"),
            accepted_by_name: r.get("accepted_by_name"),
            accepted_at: r.get("accepted_at"),
            controls_summary: r.get("controls_summary"),
        });
    }
    Ok(out)
}

fn csv_escape(val: &str, sep: char) -> String {
    let needs_quotes =
        val.contains(sep) || val.contains('"') || val.contains('\n') || val.contains('\r');
    if needs_quotes {
        format!("\"{}\"", val.replace('"', "\"\""))
    } else {
        val.to_string()
    }
}

pub async fn render_risks_csv_bytes(
    pool: &sqlx::PgPool,
    sep: char,
) -> Result<(usize, Vec<u8>), AppError> {
    let rows = load_export_rows(pool).await?;
    let total = rows.len();

    let mut csv = String::from("\u{FEFF}");
    let headers = [
        "Code",
        "Titel",
        "Betroffenes Asset",
        "Verantwortlich",
        "Brutto W",
        "Brutto A",
        "Brutto Score",
        "Brutto Einstufung",
        "Strategie",
        "Netto W",
        "Netto A",
        "Netto Score",
        "Netto Einstufung",
        "Status",
        "Controls",
        "Behandlungsplan",
        "Akzeptanzbegründung",
        "Akzeptiert durch",
        "Akzeptiert am",
    ];
    csv.push_str(&headers.join(&sep.to_string()));
    csv.push('\n');

    for r in &rows {
        let acc_date = r
            .accepted_at
            .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
            .unwrap_or_default();
        let line = [
            csv_escape(&r.reference_code, sep),
            csv_escape(&r.title, sep),
            csv_escape(&r.asset_label, sep),
            csv_escape(&r.owner_label, sep),
            r.inherent_likelihood.to_string(),
            r.inherent_impact.to_string(),
            r.inherent_score.to_string(),
            csv_escape(r.inherent_rating.label(), sep),
            csv_escape(r.strategy.label(), sep),
            r.residual_likelihood.to_string(),
            r.residual_impact.to_string(),
            r.residual_score.to_string(),
            csv_escape(r.residual_rating.label(), sep),
            csv_escape(r.status.label(), sep),
            csv_escape(&r.controls_summary, sep),
            csv_escape(&r.treatment_plan, sep),
            csv_escape(&r.acceptance_justification, sep),
            csv_escape(&r.accepted_by_name, sep),
            csv_escape(&acc_date, sep),
        ]
        .join(&sep.to_string());
        csv.push_str(&line);
        csv.push('\n');
    }

    Ok((total, csv.into_bytes()))
}

pub async fn export_risks_csv_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    client_ip: ClientIp,
    Query(query): Query<RiskExportQuery>,
) -> Result<Response, AppError> {
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Kein Zugriff auf den Risiko-Export.".to_string(),
        ));
    }

    let sep = match query.delimiter.as_deref() {
        Some("comma") => ',',
        _ => ';',
    };
    let (row_count, csv_bytes) = render_risks_csv_bytes(&state.pool, sep).await?;

    AuditService::log_event(
        &state.pool,
        Some(user.id),
        Some(client_ip.0),
        "risks.exported_csv",
        "risk_scenarios",
        "export-csv",
        "Risikoregister als CSV exportiert",
        None,
        Some(serde_json::json!({ "rows": row_count })),
    )
    .await?;

    let mut resp = Response::new(axum::body::Body::from(csv_bytes));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    resp.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"risikoregister.csv\""),
    );
    Ok(resp)
}

pub async fn render_risks_pdf_bytes(
    pool: &sqlx::PgPool,
    config: &crate::config::Config,
    actor_name: &str,
) -> Result<(usize, Vec<u8>), AppError> {
    let company_name: String =
        sqlx::query_scalar("SELECT company_name FROM organization_profile WHERE id = 1")
            .fetch_optional(pool)
            .await?
            .unwrap_or_else(|| "Meine Organisation".to_string());

    let rows = load_export_rows(pool).await?;
    let row_count = rows.len();
    let mut crit = 0usize;
    let mut high = 0usize;
    let mut med = 0usize;
    let mut low = 0usize;
    for r in &rows {
        match r.residual_rating {
            RiskRating::Critical => crit += 1,
            RiskRating::High => high += 1,
            RiskRating::Medium => med += 1,
            RiskRating::Low => low += 1,
        }
    }

    let mut body = String::new();
    body.push_str("= Zusammenfassung (Netto-Risikoverteilung)\n\n");
    body.push_str(&format!(
        "- Risikoszenarien gesamt: *{}*\n- Kritisch (16–25): *{}*\n- Hoch (10–15): *{}*\n- Mittel (5–9): *{}*\n- Gering (1–4): *{}*\n\n",
        row_count,
        crit,
        high,
        med,
        low
    ));

    body.push_str("= Risikobehandlungsplan (RTP)\n\n");
    body.push_str("#table(\n  columns: (auto, 2fr, auto, auto, auto, 1.5fr),\n  inset: 5pt,\n  stroke: 0.4pt + luma(190),\n");
    body.push_str("  [*Code*], [*Szenario & Asset*], [*Brutto*], [*Netto*], [*Status / Strategie*], [*Controls & Akzeptanz*],\n");

    for r in &rows {
        let acc_info = if r.status == RiskStatus::Accepted && !r.accepted_by_name.is_empty() {
            let dt = r
                .accepted_at
                .map(|d| d.format("%d.%m.%Y").to_string())
                .unwrap_or_default();
            format!(
                "Akzeptiert: {} ({}) — {}",
                r.accepted_by_name, dt, r.acceptance_justification
            )
        } else {
            r.treatment_plan.clone()
        };

        let controls_and_acc = if r.controls_summary.is_empty() {
            acc_info
        } else if acc_info.is_empty() {
            format!("Controls: {}", r.controls_summary)
        } else {
            format!("Controls: {}\n{}", r.controls_summary, acc_info)
        };

        body.push_str(&format!(
            "  [{}], [{} \\ _{}_], [{}×{} = {} ({})], [{}×{} = {} ({})], [{} / {}], [{}],\n",
            escape_typst(&r.reference_code),
            escape_typst(&r.title),
            escape_typst(&r.asset_label),
            r.inherent_likelihood,
            r.inherent_impact,
            r.inherent_score,
            escape_typst(r.inherent_rating.label()),
            r.residual_likelihood,
            r.residual_impact,
            r.residual_score,
            escape_typst(r.residual_rating.label()),
            escape_typst(r.status.label()),
            escape_typst(r.strategy.label()),
            escape_typst(&controls_and_acc),
        ));
    }
    body.push_str(")\n");

    let meta = PdfDocumentMetadata {
        organization_name: company_name,
        doc_code: "RTP-27001".to_string(),
        title: "Risikobehandlungsplan (RTP)".to_string(),
        version: Utc::now().format("%Y-%m-%d").to_string(),
        status: "Aktueller Registerstand".to_string(),
        classification: "C2 · Intern".to_string(),
        owner_unit: "ISMS / Informationssicherheit".to_string(),
        approved_by: actor_name.to_string(),
        approved_at: Utc::now().format("%d.%m.%Y").to_string(),
        next_review_at: "Jährlich / anlassbezogen".to_string(),
    };
    let typst_src = build_iso_document_typst(&meta, &body);
    let renderer = TypstCliRenderer::from_config(config);
    let pdf_bytes = renderer.render_raw_typst(&typst_src).await?;
    Ok((row_count, pdf_bytes))
}

pub async fn export_risks_pdf_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    client_ip: ClientIp,
) -> Result<Response, AppError> {
    if user.role == Role::Employee {
        return Err(AppError::Forbidden(
            "Kein Zugriff auf den RTP-Export.".to_string(),
        ));
    }

    let (row_count, pdf_bytes) =
        render_risks_pdf_bytes(&state.pool, &state.config, &user.full_name).await?;

    AuditService::log_event(
        &state.pool,
        Some(user.id),
        Some(client_ip.0),
        "risks.exported_pdf",
        "risk_scenarios",
        "export-pdf",
        "Risikobehandlungsplan (RTP) als PDF exportiert",
        None,
        Some(serde_json::json!({ "rows": row_count })),
    )
    .await?;

    let mut resp = Response::new(axum::body::Body::from(pdf_bytes));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/pdf"),
    );
    resp.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"risikobehandlungsplan.pdf\""),
    );
    Ok(resp)
}
