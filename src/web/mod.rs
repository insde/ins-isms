pub mod assets;
pub mod middleware;
pub mod palette;

use askama::Template;
use axum::{
    http::HeaderMap,
    response::{Html, IntoResponse},
};

use crate::{
    auth::rbac::{CurrentUser, Role, is_htmx_request},
    error::AppError,
};

#[derive(Debug, Clone)]
pub struct ShellContext {
    pub title: String,
    pub section: String,
    pub active_nav: &'static str,
    pub user_name: String,
    pub user_role_label: &'static str,
    pub csrf_token: String,
    pub is_admin: bool,
    pub is_iso_or_admin: bool,
}

impl ShellContext {
    pub fn from_user(
        user: &CurrentUser,
        title: impl Into<String>,
        section: impl Into<String>,
        active_nav: &'static str,
    ) -> Self {
        Self {
            title: title.into(),
            section: section.into(),
            active_nav,
            user_name: user.full_name.clone(),
            user_role_label: role_label(user.role),
            csrf_token: user.csrf_token.clone(),
            is_admin: user.role.is_admin(),
            is_iso_or_admin: user.role.is_iso_or_admin(),
        }
    }
}

pub fn role_label(role: Role) -> &'static str {
    match role {
        Role::Admin => "Admin",
        Role::Iso => "ISB",
        Role::Owner => "Verantwortlicher",
        Role::Auditor => "Prüfer",
        Role::Employee => "Mitarbeitende",
    }
}

#[derive(Template)]
#[template(path = "base.html")]
struct BaseTemplate {
    title: String,
    section: String,
    active_nav: &'static str,
    user_name: String,
    user_role_label: &'static str,
    csrf_token: String,
    content: String,
}

pub fn render_template<T: Template>(tpl: &T) -> Result<Html<String>, AppError> {
    let html = tpl
        .render()
        .map_err(|err| AppError::Internal(format!("Template-Rendering fehlgeschlagen: {err}")))?;
    Ok(Html(html))
}

pub fn render_page<T: Template>(
    headers: &HeaderMap,
    shell: ShellContext,
    content_tpl: &T,
) -> Result<Html<String>, AppError> {
    let inner = content_tpl
        .render()
        .map_err(|err| AppError::Internal(format!("Template-Rendering fehlgeschlagen: {err}")))?;

    if is_htmx_request(headers) {
        return Ok(Html(inner));
    }

    let full = BaseTemplate {
        title: shell.title,
        section: shell.section,
        active_nav: shell.active_nav,
        user_name: shell.user_name,
        user_role_label: shell.user_role_label,
        csrf_token: shell.csrf_token,
        content: inner,
    }
    .render()
    .map_err(|err| AppError::Internal(format!("Shell-Rendering fehlgeschlagen: {err}")))?;

    Ok(Html(full))
}

pub fn with_toast(
    mut response: axum::response::Response,
    level: &str,
    message: &str,
) -> axum::response::Response {
    let payload = serde_json::json!({
        "showToast": {
            "level": level,
            "message": message,
        }
    });
    if let Ok(val) = axum::http::HeaderValue::from_str(&payload.to_string()) {
        response.headers_mut().insert("HX-Trigger", val);
    }
    response
}

pub fn hx_redirect_or_303(headers: &HeaderMap, target: &str) -> axum::response::Response {
    if is_htmx_request(headers) {
        let mut resp = (axum::http::StatusCode::OK, "").into_response();
        if let Ok(val) = axum::http::HeaderValue::from_str(target) {
            resp.headers_mut().insert("HX-Redirect", val);
        }
        resp
    } else {
        axum::response::Redirect::to(target).into_response()
    }
}
