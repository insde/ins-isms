pub mod oidc;
pub mod password;
pub mod rate_limit;
pub mod rbac;
pub mod session;

use askama::Template;
use axum::{
    Form,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    audit::AuditService,
    auth::{
        password::{hash_password, validate_password_policy, verify_password},
        rate_limit::{check_rate_limit, clear_attempts, normalize_email, record_failed_attempt},
        rbac::{ClientIp, CurrentUser, RequireAdmin},
        session::{
            build_clear_session_cookie, build_session_cookie, create_session,
            delete_other_user_sessions, delete_session, delete_user_sessions,
            generate_random_token, sign_session_id,
        },
    },
    db::begin_audited_tx,
    error::AppError,
    state::AppState,
    web::render_template,
};

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    pub error: Option<String>,
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    has_oidc: bool,
    has_error: bool,
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordForm {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct AdminResetPasswordForm {
    pub new_password: Option<String>,
}

pub async fn login_page_handler(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
) -> Result<impl IntoResponse, AppError> {
    render_template(&LoginTemplate {
        has_oidc: state.config.oidc.is_some(),
        has_error: query.error.is_some(),
    })
}

pub async fn login_submit_handler(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Result<Response, AppError> {
    let email_norm = normalize_email(&form.email);

    if let Err(err) = check_rate_limit(&state.pool, &email_norm, ip).await {
        AuditService::log_login_locked(&state.pool, ip, &email_norm).await?;
        return Err(err);
    }

    let user_row = sqlx::query(
        r#"
        SELECT
            id,
            email,
            password_hash,
            is_active,
            (expires_at IS NOT NULL AND expires_at <= NOW()) AS is_expired
        FROM users
        WHERE LOWER(email) = $1
        "#,
    )
    .bind(&email_norm)
    .fetch_optional(&state.pool)
    .await?;

    let mut authenticated_user: Option<(Uuid, String)> = None;

    if let Some(row) = user_row {
        let is_active: bool = row.try_get("is_active")?;
        let is_expired: bool = row.try_get("is_expired")?;
        let password_hash: Option<String> = row.try_get("password_hash")?;

        if is_active
            && !is_expired
            && let Some(ref hash) = password_hash
            && verify_password(&form.password, hash).await?
        {
            authenticated_user = Some((row.try_get("id")?, row.try_get("email")?));
        }
    }

    let Some((user_id, canonical_email)) = authenticated_user else {
        record_failed_attempt(&state.pool, &email_norm, ip).await?;
        AuditService::log_login_failed(&state.pool, ip, &email_norm).await?;
        // Einheitliche Meldung gegen User-Enumeration.
        return Ok((
            StatusCode::UNAUTHORIZED,
            Html(
                r#"<div class="alert alert-error" role="alert">Anmeldung fehlgeschlagen. Bitte Zugangsdaten prüfen.</div>"#,
            ),
        )
            .into_response());
    };

    clear_attempts(&state.pool, &email_norm, ip).await?;

    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    let (session_id, _) = create_session(
        &state.pool,
        user_id,
        Some(ip),
        user_agent,
        state.config.session_ttl_hours,
    )
    .await?;

    AuditService::log_login_success(&state.pool, user_id, ip, &canonical_email).await?;

    let signed_cookie = sign_session_id(&session_id, &state.config.session_secret)?;
    let cookie = build_session_cookie(signed_cookie, &state.config);

    let mut resp = Redirect::to("/").into_response();
    if let Ok(val) = HeaderValue::from_str(&cookie.to_string()) {
        resp.headers_mut().append(header::SET_COOKIE, val);
    }
    Ok(resp)
}

pub async fn logout_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(ip): ClientIp,
) -> Result<Response, AppError> {
    delete_session(&state.pool, &user.session_id).await?;
    AuditService::log_logout(&state.pool, user.id, ip).await?;

    let clear_cookie = build_clear_session_cookie(&state.config);
    let mut resp = Redirect::to("/login").into_response();
    if let Ok(val) = HeaderValue::from_str(&clear_cookie.to_string()) {
        resp.headers_mut().append(header::SET_COOKIE, val);
    }
    Ok(resp)
}

pub async fn change_own_password_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    ClientIp(ip): ClientIp,
    Form(form): Form<ChangePasswordForm>,
) -> Result<impl IntoResponse, AppError> {
    let current_hash: Option<String> =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
            .bind(user.id)
            .fetch_optional(&state.pool)
            .await?
            .flatten();

    let Some(hash) = current_hash else {
        return Err(AppError::Forbidden(
            "Für OIDC-Konten ohne lokales Passwort nicht verfügbar.".to_string(),
        ));
    };

    if !verify_password(&form.current_password, &hash).await? {
        return Err(AppError::Validation(vec![
            "Das bisherige Passwort ist nicht korrekt.".to_string(),
        ]));
    }

    validate_password_policy(&form.new_password)?;
    let new_hash = hash_password(&form.new_password).await?;

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;
    sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
        .bind(&new_hash)
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    delete_other_user_sessions(&state.pool, user.id, &user.session_id).await?;
    AuditService::log_password_changed(&state.pool, user.id, ip).await?;

    Ok((
        StatusCode::OK,
        Html(r#"<div class="alert alert-success">Passwort erfolgreich geändert.</div>"#),
    ))
}

pub async fn admin_reset_password_handler(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    ClientIp(ip): ClientIp,
    Path(target_user_id): Path<Uuid>,
    Form(form): Form<AdminResetPasswordForm>,
) -> Result<impl IntoResponse, AppError> {
    let exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM users WHERE id = $1")
        .bind(target_user_id)
        .fetch_optional(&state.pool)
        .await?;

    if exists.is_none() {
        return Err(AppError::NotFound("Benutzer nicht gefunden.".to_string()));
    }

    let temp_password = match form.new_password.filter(|p| !p.is_empty()) {
        Some(pw) => {
            validate_password_policy(&pw)?;
            pw
        }
        None => generate_random_token(),
    };

    let new_hash = hash_password(&temp_password).await?;

    let mut tx = begin_audited_tx(&state.pool, Some(admin.id), Some(ip)).await?;
    sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
        .bind(&new_hash)
        .bind(target_user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    delete_user_sessions(&state.pool, target_user_id).await?;
    AuditService::log_password_reset(&state.pool, admin.id, target_user_id, ip).await?;

    Ok((
        StatusCode::OK,
        Html(
            r#"<div class="alert alert-success">Einmal-Passwort gesetzt. Alle aktiven Sitzungen des Benutzers wurden beendet.</div>"#
                .to_string(),
        ),
    ))
}
