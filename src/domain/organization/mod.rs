pub mod assets;
pub mod profile;
pub mod users;

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
    auth::rbac::{CurrentUser, Role},
    error::AppError,
    state::AppState,
    web::{ShellContext, render_page, role_label},
};

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    company_name: String,
    scope_statement: String,
    user_name: String,
    user_role_label: &'static str,
    asset_count: i64,
    info_asset_count: i64,
    unit_count: i64,
    active_user_count: i64,
    audit_count: i64,
    doc_total_count: i64,
    doc_approved_count: i64,
    soa_applicable_count: i64,
    soa_implemented_count: i64,
    risk_total_count: i64,
    risk_high_critical_count: i64,
    risk_overdue_count: i64,
    incident_open_count: i64,
    incident_nis2_open_count: i64,
    audit_open_nc_count: i64,
    action_open_count: i64,
    action_overdue_count: i64,
    can_view_assets: bool,
    can_view_audit: bool,
}

pub async fn dashboard_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let profile_row =
        sqlx::query("SELECT company_name, scope_statement FROM organization_profile WHERE id = 1")
            .fetch_optional(&state.pool)
            .await?;

    let (company_name, scope_statement) = match profile_row {
        Some(r) => (
            r.try_get::<String, _>("company_name")?,
            r.try_get::<String, _>("scope_statement")?,
        ),
        None => ("Meine Organisation".to_string(), String::new()),
    };

    let asset_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM system_assets")
        .fetch_one(&state.pool)
        .await?;
    let info_asset_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM information_assets")
        .fetch_one(&state.pool)
        .await?;
    let unit_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM organization_units")
        .fetch_one(&state.pool)
        .await?;
    let active_user_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_active = TRUE")
            .fetch_one(&state.pool)
            .await?;
    let audit_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs")
        .fetch_one(&state.pool)
        .await?;
    let doc_total_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM documents")
        .fetch_one(&state.pool)
        .await?;
    let doc_approved_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT document_id) FROM document_versions WHERE status = 'approved'",
    )
    .fetch_one(&state.pool)
    .await?;
    let soa_applicable_count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM soa_entries se
        JOIN framework_controls fc ON fc.id = se.control_id
        JOIN compliance_frameworks cf ON cf.id = fc.framework_id
        WHERE cf.code = 'ISO27001_2022_STARTER' AND se.is_applicable = TRUE
        "#,
    )
    .fetch_one(&state.pool)
    .await?;
    let soa_implemented_count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM soa_entries se
        JOIN framework_controls fc ON fc.id = se.control_id
        JOIN compliance_frameworks cf ON cf.id = fc.framework_id
        WHERE cf.code = 'ISO27001_2022_STARTER'
          AND se.is_applicable = TRUE
          AND se.implementation_status IN ('implemented', 'verified')
        "#,
    )
    .fetch_one(&state.pool)
    .await?;
    let risk_total_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM risk_scenarios")
        .fetch_one(&state.pool)
        .await?;
    let risk_high_critical_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM risk_scenarios WHERE (residual_likelihood * residual_impact) >= 10 AND status <> 'closed'",
    )
    .fetch_one(&state.pool)
    .await?;
    let risk_overdue_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM risk_scenarios WHERE next_review_due_at IS NOT NULL AND next_review_due_at <= NOW() AND status <> 'closed'",
    )
    .fetch_one(&state.pool)
    .await?;
    let incident_open_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM security_incidents WHERE status <> 'closed'")
            .fetch_one(&state.pool)
            .await?;
    let incident_nis2_open_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM security_incidents WHERE status <> 'closed' AND is_nis2_significant = TRUE",
    )
    .fetch_one(&state.pool)
    .await?;
    let audit_open_nc_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_findings WHERE status <> 'verified_closed' AND finding_type IN ('major_nc', 'minor_nc')",
    )
    .fetch_one(&state.pool)
    .await?;
    let action_open_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM action_items WHERE status IN ('open', 'in_progress', 'review')",
    )
    .fetch_one(&state.pool)
    .await?;
    let action_overdue_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM action_items WHERE status IN ('open', 'in_progress', 'review') AND due_date < CURRENT_DATE",
    )
    .fetch_one(&state.pool)
    .await?;

    let shell = ShellContext::from_user(&user, "Dashboard", "Übersicht", "dashboard");
    render_page(
        &headers,
        shell,
        &DashboardTemplate {
            company_name,
            scope_statement,
            user_name: user.full_name.clone(),
            user_role_label: role_label(user.role),
            asset_count,
            info_asset_count,
            unit_count,
            active_user_count,
            audit_count,
            doc_total_count,
            doc_approved_count,
            soa_applicable_count,
            soa_implemented_count,
            risk_total_count,
            risk_high_critical_count,
            risk_overdue_count,
            incident_open_count,
            incident_nis2_open_count,
            audit_open_nc_count,
            action_open_count,
            action_overdue_count,
            can_view_assets: user.role != Role::Employee,
            can_view_audit: matches!(user.role, Role::Admin | Role::Iso | Role::Auditor),
        },
    )
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/organization", get(profile::overview_handler))
        .route(
            "/organization/profile/edit",
            get(profile::edit_profile_form_handler),
        )
        .route(
            "/organization/profile",
            post(profile::update_profile_handler),
        )
        .route(
            "/organization/pdf-theme.typ",
            get(profile::download_pdf_theme_handler),
        )
        .route(
            "/organization/units/new",
            get(profile::new_unit_form_handler),
        )
        .route("/organization/units", post(profile::create_unit_handler))
        .route(
            "/organization/units/{id}/edit",
            get(profile::edit_unit_form_handler),
        )
        .route(
            "/organization/units/{id}",
            post(profile::update_unit_handler),
        )
        .route(
            "/organization/units/{id}/delete",
            post(profile::delete_unit_handler),
        )
        .route("/settings", get(users::list_users_handler))
        .route("/settings/users", get(users::list_users_handler))
        .route("/settings/users/new", get(users::new_user_form_handler))
        .route("/settings/users", post(users::create_user_handler))
        .route(
            "/settings/users/{id}/edit",
            get(users::edit_user_form_handler),
        )
        .route("/settings/users/{id}", post(users::update_user_handler))
        .route(
            "/settings/users/{id}/deactivate",
            post(users::deactivate_user_handler),
        )
        .route(
            "/settings/users/{id}/activate",
            post(users::activate_user_handler),
        )
        .route("/account", get(users::account_handler))
        .route(
            "/organization/assets",
            get(assets::list_assets_handler).post(assets::create_asset_handler),
        )
        .route(
            "/organization/assets/new",
            get(assets::new_asset_form_handler),
        )
        .route(
            "/organization/assets/{id}",
            get(assets::asset_detail_handler).post(assets::update_asset_handler),
        )
        .route(
            "/organization/assets/{id}/edit",
            get(assets::edit_asset_form_handler),
        )
        .route(
            "/organization/assets/{id}/delete",
            post(assets::delete_asset_handler),
        )
}
