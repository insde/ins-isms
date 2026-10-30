pub mod audit;
pub mod auth;
pub mod config;
pub mod db;
pub mod domain;
pub mod error;
pub mod mailer;
pub mod markdown;
pub mod pdf;
pub mod scheduler;
pub mod seed;
pub mod state;
pub mod storage;
pub mod web;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{get, post},
};
use serde::Serialize;

use crate::{
    audit::{audit_log_detail_handler, list_audit_logs_handler, verify_audit_logs_handler},
    auth::{
        admin_reset_password_handler, change_own_password_handler, login_page_handler,
        login_submit_handler, logout_handler,
        oidc::{oidc_callback_handler, oidc_login_handler},
    },
    domain::{
        actions, audits, classification, documents, exports, incidents,
        organization::{self, dashboard_handler},
        risks, soa,
    },
    state::AppState,
    web::{
        assets::static_asset_handler,
        middleware::{csrf_middleware, security_headers_middleware},
        palette::palette_search_handler,
    },
};

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

pub fn build_router(state: AppState) -> Router {
    let max_upload = state.config.max_upload_bytes;

    Router::new()
        .route("/healthz", get(healthz))
        .route("/static/{*path}", get(static_asset_handler))
        .route("/", get(dashboard_handler))
        .route("/search/palette", get(palette_search_handler))
        .route("/login", get(login_page_handler).post(login_submit_handler))
        .route("/logout", post(logout_handler))
        .route("/account/password", post(change_own_password_handler))
        .route(
            "/settings/users/{id}/reset-password",
            post(admin_reset_password_handler),
        )
        .route("/auth/oidc/login", get(oidc_login_handler))
        .route("/auth/oidc/callback", get(oidc_callback_handler))
        .route("/audit-logs", get(list_audit_logs_handler))
        .route("/audit-logs/verify", get(verify_audit_logs_handler))
        .route("/audit-logs/{id}", get(audit_log_detail_handler))
        .merge(organization::router())
        .merge(classification::router())
        .merge(documents::router())
        .merge(soa::router())
        .merge(risks::router())
        .merge(incidents::router())
        .merge(audits::router())
        .merge(actions::router())
        .merge(exports::router())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            csrf_middleware,
        ))
        .layer(middleware::from_fn(security_headers_middleware))
        .layer(DefaultBodyLimit::max(max_upload))
        .with_state(state)
}

async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
    {
        Ok(_) => (StatusCode::OK, Json(HealthResponse { status: "ok" })),
        Err(err) => {
            tracing::warn!(error = %err, "Healthcheck Datenbankfehler");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(HealthResponse { status: "error" }),
            )
        }
    }
}
