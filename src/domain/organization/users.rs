use std::str::FromStr;

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::IntoResponse,
};
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    auth::{
        password::{hash_password, validate_password_policy},
        rbac::{ClientIp, CurrentUser, RequireAdmin, RequireIsoOrAdmin, Role},
        session::delete_user_sessions,
    },
    db::begin_audited_tx,
    domain::organization::profile::{SelectOption, parse_optional_uuid},
    error::AppError,
    state::AppState,
    web::{ShellContext, hx_redirect_or_303, render_page, render_template, role_label, with_toast},
};

#[derive(Debug, Clone)]
pub struct UserRowView {
    pub id: Uuid,
    pub email: String,
    pub full_name: String,
    pub role_code: String,
    pub role_label: &'static str,
    pub unit_name: String,
    pub is_active: bool,
    pub expires_display: String,
}

#[derive(Template)]
#[template(path = "organization/users.html")]
struct UsersTemplate {
    users: Vec<UserRowView>,
    can_manage: bool,
    current_user_id: Uuid,
    csrf_token: String,
}

#[derive(Template)]
#[template(path = "organization/user_form.html")]
struct UserFormTemplate {
    is_edit: bool,
    action_url: String,
    submit_label: &'static str,
    email: String,
    full_name: String,
    selected_role: String,
    selected_unit_id: String,
    expires_date: String,
    units: Vec<SelectOption>,
    csrf_token: String,
}

#[derive(Template)]
#[template(path = "organization/account.html")]
struct AccountTemplate {
    full_name: String,
    email: String,
    role_label: &'static str,
    unit_name: String,
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserForm {
    pub email: String,
    pub full_name: String,
    pub role: String,
    pub organization_unit_id: Option<String>,
    pub expires_at: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserForm {
    pub full_name: String,
    pub role: String,
    pub organization_unit_id: Option<String>,
    pub expires_at: Option<String>,
}

async fn load_unit_options(state: &AppState) -> Result<Vec<SelectOption>, AppError> {
    let rows = sqlx::query("SELECT id, name FROM organization_units ORDER BY name ASC")
        .fetch_all(&state.pool)
        .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(SelectOption {
            id: r.try_get("id")?,
            label: r.try_get("name")?,
        });
    }
    Ok(out)
}

fn parse_optional_expires_at(raw: Option<&str>) -> Result<Option<DateTime<Utc>>, AppError> {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let date = NaiveDate::parse_from_str(s, "%Y-%m-%d").map_err(|_| {
        AppError::Validation(vec![
            "Ungültiges Ablaufdatum (erwartetes Format: JJJJ-MM-TT).".to_string(),
        ])
    })?;
    let naive_dt = date
        .and_hms_opt(23, 59, 59)
        .ok_or_else(|| AppError::Internal("Zeitkonstruktion fehlgeschlagen.".to_string()))?;
    Ok(Some(Utc.from_utc_datetime(&naive_dt)))
}

pub async fn list_users_handler(
    State(state): State<AppState>,
    RequireIsoOrAdmin(user): RequireIsoOrAdmin,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let rows = sqlx::query(
        r#"
        SELECT
            u.id,
            u.email,
            u.full_name,
            u.role,
            COALESCE(ou.name, '–') AS unit_name,
            u.is_active,
            u.expires_at
        FROM users u
        LEFT JOIN organization_units ou ON ou.id = u.organization_unit_id
        ORDER BY u.is_active DESC, u.full_name ASC
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    let mut users = Vec::with_capacity(rows.len());
    for r in rows {
        let role_str: String = r.try_get("role")?;
        let parsed_role = Role::from_str(&role_str).unwrap_or(Role::Employee);
        let expires_at: Option<DateTime<Utc>> = r.try_get("expires_at")?;
        users.push(UserRowView {
            id: r.try_get("id")?,
            email: r.try_get("email")?,
            full_name: r.try_get("full_name")?,
            role_code: role_str,
            role_label: role_label(parsed_role),
            unit_name: r.try_get("unit_name")?,
            is_active: r.try_get("is_active")?,
            expires_display: expires_at
                .map(|dt| dt.format("%Y-%m-%d").to_string())
                .unwrap_or_else(|| "Unbefristet".to_string()),
        });
    }

    let shell = ShellContext::from_user(
        &user,
        "Benutzer & Einstellungen",
        "Nachweis & System",
        "settings",
    );
    render_page(
        &headers,
        shell,
        &UsersTemplate {
            users,
            can_manage: user.role.is_admin(),
            current_user_id: user.id,
            csrf_token: user.csrf_token,
        },
    )
}

pub async fn new_user_form_handler(
    State(state): State<AppState>,
    RequireAdmin(user): RequireAdmin,
) -> Result<impl IntoResponse, AppError> {
    let units = load_unit_options(&state).await?;
    render_template(&UserFormTemplate {
        is_edit: false,
        action_url: "/settings/users".to_string(),
        submit_label: "Benutzer anlegen",
        email: String::new(),
        full_name: String::new(),
        selected_role: "employee".to_string(),
        selected_unit_id: String::new(),
        expires_date: String::new(),
        units,
        csrf_token: user.csrf_token,
    })
}

pub async fn create_user_handler(
    State(state): State<AppState>,
    RequireAdmin(user): RequireAdmin,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Form(form): Form<CreateUserForm>,
) -> Result<impl IntoResponse, AppError> {
    let email = form.email.trim().to_ascii_lowercase();
    let full_name = form.full_name.trim().to_string();
    if email.is_empty() || !email.contains('@') || email.len() > 255 {
        return Err(AppError::Validation(vec![
            "Bitte eine gültige E-Mail-Adresse angeben.".to_string(),
        ]));
    }
    if full_name.is_empty() || full_name.len() > 255 {
        return Err(AppError::Validation(vec![
            "Der vollständige Name darf nicht leer sein.".to_string(),
        ]));
    }

    let role = Role::from_str(&form.role)?;
    let unit_id = parse_optional_uuid(form.organization_unit_id.as_deref())?;
    let expires_at = parse_optional_expires_at(form.expires_at.as_deref())?;

    let password_hash = match form
        .password
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(pw) => {
            validate_password_policy(pw)?;
            Some(hash_password(pw).await?)
        }
        None => None,
    };

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;
    let res = sqlx::query(
        r#"
        INSERT INTO users (email, full_name, password_hash, role, organization_unit_id, expires_at, is_active)
        VALUES ($1, $2, $3, $4, $5, $6, TRUE)
        "#,
    )
    .bind(&email)
    .bind(&full_name)
    .bind(&password_hash)
    .bind(role.as_str())
    .bind(unit_id)
    .bind(expires_at)
    .execute(&mut *tx)
    .await;

    if let Err(err) = res {
        if let sqlx::Error::Database(ref db_err) = err
            && db_err.is_unique_violation()
        {
            return Err(AppError::Conflict(
                "Ein Benutzer mit dieser E-Mail-Adresse existiert bereits.".to_string(),
            ));
        }
        return Err(AppError::Database(err));
    }
    tx.commit().await?;

    let resp = hx_redirect_or_303(&headers, "/settings/users");
    Ok(with_toast(resp, "success", "Benutzer angelegt."))
}

pub async fn edit_user_form_handler(
    State(state): State<AppState>,
    RequireAdmin(user): RequireAdmin,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let row = sqlx::query(
        "SELECT email, full_name, role, organization_unit_id, expires_at FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Benutzer nicht gefunden.".to_string()))?;

    let email: String = row.try_get("email")?;
    let full_name: String = row.try_get("full_name")?;
    let role: String = row.try_get("role")?;
    let unit_id: Option<Uuid> = row.try_get("organization_unit_id")?;
    let expires_at: Option<DateTime<Utc>> = row.try_get("expires_at")?;
    let units = load_unit_options(&state).await?;

    render_template(&UserFormTemplate {
        is_edit: true,
        action_url: format!("/settings/users/{id}"),
        submit_label: "Änderungen speichern",
        email,
        full_name,
        selected_role: role,
        selected_unit_id: unit_id.map(|u| u.to_string()).unwrap_or_default(),
        expires_date: expires_at
            .map(|dt| dt.format("%Y-%m-%d").to_string())
            .unwrap_or_default(),
        units,
        csrf_token: user.csrf_token,
    })
}

pub async fn update_user_handler(
    State(state): State<AppState>,
    RequireAdmin(user): RequireAdmin,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<UpdateUserForm>,
) -> Result<impl IntoResponse, AppError> {
    let full_name = form.full_name.trim().to_string();
    if full_name.is_empty() || full_name.len() > 255 {
        return Err(AppError::Validation(vec![
            "Der vollständige Name darf nicht leer sein.".to_string(),
        ]));
    }
    let role = Role::from_str(&form.role)?;
    let unit_id = parse_optional_uuid(form.organization_unit_id.as_deref())?;
    let expires_at = parse_optional_expires_at(form.expires_at.as_deref())?;

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;
    let res = sqlx::query(
        r#"
        UPDATE users
        SET full_name = $1,
            role = $2,
            organization_unit_id = $3,
            expires_at = $4,
            updated_at = NOW()
        WHERE id = $5
        "#,
    )
    .bind(&full_name)
    .bind(role.as_str())
    .bind(unit_id)
    .bind(expires_at)
    .bind(id)
    .execute(&mut *tx)
    .await?;

    if res.rows_affected() == 0 {
        return Err(AppError::NotFound("Benutzer nicht gefunden.".to_string()));
    }
    tx.commit().await?;

    let resp = hx_redirect_or_303(&headers, "/settings/users");
    Ok(with_toast(resp, "success", "Benutzer aktualisiert."))
}

pub async fn deactivate_user_handler(
    State(state): State<AppState>,
    RequireAdmin(user): RequireAdmin,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if id == user.id {
        return Err(AppError::Validation(vec![
            "Sie können Ihren eigenen Administrator-Account nicht deaktivieren.".to_string(),
        ]));
    }

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;
    let res = sqlx::query("UPDATE users SET is_active = FALSE, updated_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;

    if res.rows_affected() == 0 {
        return Err(AppError::NotFound("Benutzer nicht gefunden.".to_string()));
    }
    tx.commit().await?;

    delete_user_sessions(&state.pool, id).await?;

    let resp = hx_redirect_or_303(&headers, "/settings/users");
    Ok(with_toast(resp, "success", "Benutzer deaktiviert."))
}

pub async fn activate_user_handler(
    State(state): State<AppState>,
    RequireAdmin(user): RequireAdmin,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;
    let res = sqlx::query("UPDATE users SET is_active = TRUE, updated_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;

    if res.rows_affected() == 0 {
        return Err(AppError::NotFound("Benutzer nicht gefunden.".to_string()));
    }
    tx.commit().await?;

    let resp = hx_redirect_or_303(&headers, "/settings/users");
    Ok(with_toast(resp, "success", "Benutzer reaktiviert."))
}

pub async fn account_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let unit_name: String = if let Some(unit_id) = user.organization_unit_id {
        sqlx::query_scalar::<_, String>("SELECT name FROM organization_units WHERE id = $1")
            .bind(unit_id)
            .fetch_optional(&state.pool)
            .await?
            .unwrap_or_else(|| "–".to_string())
    } else {
        "–".to_string()
    };

    let shell = ShellContext::from_user(&user, "Mein Konto", "Nachweis & System", "settings");
    render_page(
        &headers,
        shell,
        &AccountTemplate {
            full_name: user.full_name,
            email: user.email,
            role_label: role_label(user.role),
            unit_name,
            csrf_token: user.csrf_token,
        },
    )
}
