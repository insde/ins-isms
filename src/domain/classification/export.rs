use askama::Template;
use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::Utc;

use crate::{
    auth::rbac::CurrentUser,
    domain::classification::levels::{CategoryRowView, LevelMatrixView, load_levels_with_rules},
    error::AppError,
    pdf::{PdfDocumentMetadata, PdfRenderer, TypstCliRenderer},
    state::AppState,
    web::{ShellContext, render_page},
};

#[derive(Template)]
#[template(path = "classification/cheatsheet.html")]
struct CheatsheetTemplate {
    company_name: String,
    levels: Vec<LevelMatrixView>,
    categories: Vec<CategoryRowView>,
}

async fn load_company_name(pool: &sqlx::PgPool) -> Result<String, AppError> {
    let name: Option<String> =
        sqlx::query_scalar("SELECT company_name FROM organization_profile WHERE id = 1")
            .fetch_optional(pool)
            .await?;
    Ok(name.unwrap_or_else(|| "Meine Organisation".to_string()))
}

fn pdf_response(bytes: Vec<u8>, filename: &str) -> Response {
    let mut resp = Response::new(axum::body::Body::from(bytes));
    *resp.status_mut() = StatusCode::OK;
    let headers = resp.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/pdf"),
    );
    if let Ok(disp) = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\"")) {
        headers.insert(header::CONTENT_DISPOSITION, disp);
    }
    resp
}

fn build_policy_markdown(levels: &[LevelMatrixView], categories: &[CategoryRowView]) -> String {
    let mut md = String::new();
    md.push_str("# 1. Ziel und Geltungsbereich\n\n");
    md.push_str("Diese Richtlinie legt verbindliche Regeln für die Klassifizierung, Kennzeichnung und sichere Handhabung von Informationen gemäß ISO/IEC 27001:2022 (Anhang A 5.12 und A 5.13) fest. Sie gilt für alle Mitarbeitenden, Führungskräfte und externen Dienstleister.\n\n");

    md.push_str("# 2. Schutzstufen (C1 bis C4)\n\n");
    for lvl in levels {
        md.push_str(&format!(
            "## {} – {}\n\n{}\n\n",
            lvl.code, lvl.name, lvl.description
        ));
    }

    md.push_str("# 3. Verbindliche Handling-Matrix\n\n");
    md.push_str("| Kategorie |");
    for lvl in levels {
        md.push_str(&format!(" {} ({}) |", lvl.code, lvl.name));
    }
    md.push('\n');

    md.push_str("|---|");
    for _ in levels {
        md.push_str("---|");
    }
    md.push('\n');

    for cat in categories {
        md.push_str(&format!("| **{}** |", cat.label));
        for cell in &cat.cells {
            let text = cell
                .as_ref()
                .map(|c| c.rule_text.replace('|', "\\|").replace('\n', " "))
                .unwrap_or_else(|| "–".to_string());
            md.push_str(&format!(" {text} |"));
        }
        md.push('\n');
    }

    md
}

fn build_cheatsheet_markdown(
    company_name: &str,
    levels: &[LevelMatrixView],
    categories: &[CategoryRowView],
) -> String {
    let mut md = String::new();
    md.push_str(&format!(
        "# Informationsklassifizierung – Kurzübersicht ({company_name})\n\n"
    ));
    md.push_str("**Grundsatz:** Im Zweifel immer die höhere Schutzstufe wählen und Informationen vor Weitergabe sichtbar kennzeichnen.\n\n");

    for lvl in levels {
        md.push_str(&format!(
            "- **{} ({})**: {}\n",
            lvl.code, lvl.name, lvl.description
        ));
    }
    md.push('\n');

    md.push_str("| Umgang |");
    for lvl in levels {
        md.push_str(&format!(" {} |", lvl.code));
    }
    md.push('\n');

    md.push_str("|---|");
    for _ in levels {
        md.push_str("---|");
    }
    md.push('\n');

    for cat in categories {
        md.push_str(&format!("| **{}** |", cat.label));
        for cell in &cat.cells {
            let text = cell
                .as_ref()
                .map(|c| c.rule_text.replace('|', "\\|").replace('\n', " "))
                .unwrap_or_else(|| "–".to_string());
            md.push_str(&format!(" {text} |"));
        }
        md.push('\n');
    }

    md
}

pub async fn policy_pdf_handler(
    State(state): State<AppState>,
    _user: CurrentUser,
) -> Result<impl IntoResponse, AppError> {
    let company_name = load_company_name(&state.pool).await?;
    let (levels, categories) = load_levels_with_rules(&state.pool).await?;
    let md = build_policy_markdown(&levels, &categories);

    let today = Utc::now().format("%d.%m.%Y").to_string();
    let meta = PdfDocumentMetadata {
        organization_name: company_name,
        doc_code: "POL-KLASS".to_string(),
        title: "Richtlinie zur Informationsklassifizierung und Kennzeichnung".to_string(),
        version: "1.0".to_string(),
        status: "Freigegeben".to_string(),
        classification: "C2 · Intern".to_string(),
        owner_unit: "Informationssicherheit (ISB)".to_string(),
        approved_by: "Geschäftsleitung".to_string(),
        approved_at: today,
        next_review_at: "Jährlich".to_string(),
    };

    let renderer = TypstCliRenderer::from_config(&state.config);
    let bytes = renderer.render_markdown_document(&meta, &md).await?;
    Ok(pdf_response(
        bytes,
        "Richtlinie_Informationsklassifizierung.pdf",
    ))
}

pub async fn cheatsheet_html_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let company_name = load_company_name(&state.pool).await?;
    let (levels, categories) = load_levels_with_rules(&state.pool).await?;

    let shell = ShellContext::from_user(
        &user,
        "Mitarbeiter-One-Pager",
        "Klassifizierung",
        "classification",
    );
    render_page(
        &headers,
        shell,
        &CheatsheetTemplate {
            company_name,
            levels,
            categories,
        },
    )
}

pub async fn cheatsheet_pdf_handler(
    State(state): State<AppState>,
    _user: CurrentUser,
) -> Result<impl IntoResponse, AppError> {
    let company_name = load_company_name(&state.pool).await?;
    let (levels, categories) = load_levels_with_rules(&state.pool).await?;
    let md = build_cheatsheet_markdown(&company_name, &levels, &categories);

    let today = Utc::now().format("%d.%m.%Y").to_string();
    let meta = PdfDocumentMetadata {
        organization_name: company_name,
        doc_code: "GUIDE-KLASS".to_string(),
        title: "Mitarbeiter-One-Pager: Informationsklassifizierung".to_string(),
        version: "1.0".to_string(),
        status: "Freigegeben".to_string(),
        classification: "C2 · Intern".to_string(),
        owner_unit: "Informationssicherheit (ISB)".to_string(),
        approved_by: "Informationssicherheitsbeauftragter".to_string(),
        approved_at: today,
        next_review_at: "Jährlich".to_string(),
    };

    let renderer = TypstCliRenderer::from_config(&state.config);
    let bytes = renderer.render_markdown_document(&meta, &md).await?;
    Ok(pdf_response(bytes, "Klassifizierung_OnePager.pdf"))
}
