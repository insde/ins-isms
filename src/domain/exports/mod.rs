pub mod auditor_zip;
pub mod catalog_import;
pub mod compendium_pdf;
pub mod csv_import;
pub mod full_backup;
pub mod policy_import;

use askama::Template;
use axum::{
    Router,
    extract::State,
    http::HeaderMap,
    response::IntoResponse,
    routing::{get, post},
};
use sqlx::Row;

use crate::{
    auth::rbac::CurrentUser,
    error::AppError,
    state::AppState,
    web::{ShellContext, render_page},
};

#[derive(Template)]
#[template(path = "exports/index.html")]
struct ExportsHubTemplate {
    can_import: bool,
    is_admin: bool,
    frameworks_count: i64,
    controls_count: i64,
    system_assets_count: i64,
    info_assets_count: i64,
    risks_count: i64,
    approved_docs_count: i64,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/exports", get(exports_hub_handler))
        .route(
            "/exports/import/catalog",
            post(catalog_import::import_catalog_handler),
        )
        .route(
            "/exports/import/policy",
            post(policy_import::import_policy_handler),
        )
        .route(
            "/exports/templates/example-catalog.json",
            get(policy_import::example_catalog_template_handler),
        )
        .route(
            "/exports/import/csv/preview",
            post(csv_import::preview_csv_handler),
        )
        .route(
            "/exports/import/csv/commit",
            post(csv_import::commit_csv_handler),
        )
        .route(
            "/exports/auditor-package.zip",
            get(auditor_zip::auditor_zip_handler),
        )
        .route(
            "/exports/audit-compendium.pdf",
            get(compendium_pdf::audit_compendium_pdf_handler),
        )
        .route(
            "/exports/full-backup.json",
            get(full_backup::full_backup_json_handler),
        )
}

pub async fn exports_hub_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    if !user.role.is_iso_or_admin() && !user.role.is_auditor() {
        return Err(AppError::Forbidden(
            "Nur Administratoren, ISB und Auditoren haben Zugriff auf Exporte und Importe."
                .to_string(),
        ));
    }

    let row = sqlx::query(
        r#"
        SELECT
            (SELECT COUNT(*) FROM compliance_frameworks WHERE is_active = TRUE) AS frameworks_count,
            (SELECT COUNT(*) FROM framework_controls) AS controls_count,
            (SELECT COUNT(*) FROM system_assets) AS system_assets_count,
            (SELECT COUNT(*) FROM information_assets) AS info_assets_count,
            (SELECT COUNT(*) FROM risk_scenarios) AS risks_count,
            (SELECT COUNT(DISTINCT document_id) FROM document_versions WHERE status = 'approved') AS approved_docs_count
        "#,
    )
    .fetch_one(&state.pool)
    .await?;

    let tmpl = ExportsHubTemplate {
        can_import: user.role.is_iso_or_admin(),
        is_admin: user.role.is_admin(),
        frameworks_count: row.get("frameworks_count"),
        controls_count: row.get("controls_count"),
        system_assets_count: row.get("system_assets_count"),
        info_assets_count: row.get("info_assets_count"),
        risks_count: row.get("risks_count"),
        approved_docs_count: row.get("approved_docs_count"),
    };

    let ctx = ShellContext::from_user(&user, "Exporte & Import", "Nachweis & System", "exports");
    render_page(&headers, ctx, &tmpl)
}
