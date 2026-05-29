use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    auth::rbac::{ClientIp, CurrentUser, RequireAdmin, RequireIsoOrAdmin, Role},
    db::begin_audited_tx,
    error::AppError,
    pdf::resolve_pdf_theme,
    state::AppState,
    web::{ShellContext, hx_redirect_or_303, render_page, render_template, with_toast},
};

#[derive(Debug, Clone)]
pub struct OrganizationProfileView {
    pub company_name: String,
    pub scope_statement: String,
    pub target_frameworks: Vec<String>,
    pub frameworks_display: String,
}

#[derive(Debug, Clone)]
pub struct OrganizationUnitView {
    pub id: Uuid,
    pub name: String,
    pub parent_id: Option<Uuid>,
    pub parent_name: String,
    pub lead_user_id: Option<Uuid>,
    pub lead_user_name: String,
}

#[derive(Debug, Clone)]
pub struct SelectOption {
    pub id: Uuid,
    pub label: String,
}

#[derive(Template)]
#[template(path = "organization/index.html")]
struct OrganizationOverviewTemplate {
    profile: OrganizationProfileView,
    units: Vec<OrganizationUnitView>,
    can_edit_profile: bool,
    can_manage_units: bool,
    can_view_units: bool,
}

#[derive(Template)]
#[template(path = "organization/profile_form.html")]
struct ProfileFormTemplate {
    company_name: String,
    scope_statement: String,
    has_iso27001: bool,
    has_nis2: bool,
    csrf_token: String,
}

#[derive(Template)]
#[template(path = "organization/unit_form.html")]
struct UnitFormTemplate {
    action_url: String,
    submit_label: &'static str,
    name: String,
    selected_parent_id: String,
    selected_lead_id: String,
    units: Vec<SelectOption>,
    users: Vec<SelectOption>,
    csrf_token: String,
}

#[derive(Debug, Deserialize)]
pub struct ProfileForm {
    pub company_name: String,
    pub scope_statement: String,
    pub fw_iso27001: Option<String>,
    pub fw_nis2: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UnitForm {
    pub name: String,
    pub parent_id: Option<String>,
    pub lead_user_id: Option<String>,
}

async fn load_profile(state: &AppState) -> Result<OrganizationProfileView, AppError> {
    let row = sqlx::query(
        "SELECT company_name, scope_statement, target_frameworks FROM organization_profile WHERE id = 1",
    )
    .fetch_optional(&state.pool)
    .await?;

    let (company_name, scope_statement, target_frameworks) = match row {
        Some(r) => {
            let fw_json: serde_json::Value = r.try_get("target_frameworks")?;
            let list: Vec<String> = serde_json::from_value(fw_json).unwrap_or_default();
            (
                r.try_get::<String, _>("company_name")?,
                r.try_get::<String, _>("scope_statement")?,
                list,
            )
        }
        None => (
            "Meine Organisation".to_string(),
            String::new(),
            vec!["ISO27001_2022".to_string()],
        ),
    };

    let frameworks_display = if target_frameworks.is_empty() {
        "Keine festgelegt".to_string()
    } else {
        target_frameworks.join(", ")
    };

    Ok(OrganizationProfileView {
        company_name,
        scope_statement,
        target_frameworks,
        frameworks_display,
    })
}

async fn load_units(state: &AppState) -> Result<Vec<OrganizationUnitView>, AppError> {
    let rows = sqlx::query(
        r#"
        SELECT
            u.id,
            u.name,
            u.parent_id,
            COALESCE(p.name, '–') AS parent_name,
            u.lead_user_id,
            COALESCE(usr.full_name, '–') AS lead_user_name
        FROM organization_units u
        LEFT JOIN organization_units p ON p.id = u.parent_id
        LEFT JOIN users usr ON usr.id = u.lead_user_id
        ORDER BY u.name ASC
        "#,
    )
    .fetch_all(&state.pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(OrganizationUnitView {
            id: r.try_get("id")?,
            name: r.try_get("name")?,
            parent_id: r.try_get("parent_id")?,
            parent_name: r.try_get("parent_name")?,
            lead_user_id: r.try_get("lead_user_id")?,
            lead_user_name: r.try_get("lead_user_name")?,
        });
    }
    Ok(out)
}

async fn load_active_user_options(state: &AppState) -> Result<Vec<SelectOption>, AppError> {
    let rows = sqlx::query(
        "SELECT id, full_name FROM users WHERE is_active = TRUE ORDER BY full_name ASC",
    )
    .fetch_all(&state.pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(SelectOption {
            id: r.try_get("id")?,
            label: r.try_get("full_name")?,
        });
    }
    Ok(out)
}

pub async fn overview_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let profile = load_profile(&state).await?;
    let can_view_units = user.role != Role::Employee;
    let units = if can_view_units {
        load_units(&state).await?
    } else {
        Vec::new()
    };

    let shell = ShellContext::from_user(
        &user,
        "Organisation & Einheiten",
        "Inventar & Schutzbedarf",
        "organization",
    );
    render_page(
        &headers,
        shell,
        &OrganizationOverviewTemplate {
            profile,
            units,
            can_edit_profile: user.role.is_iso_or_admin(),
            can_manage_units: user.role.is_admin(),
            can_view_units,
        },
    )
}

pub async fn download_pdf_theme_handler(
    State(state): State<AppState>,
    RequireIsoOrAdmin(_user): RequireIsoOrAdmin,
) -> Result<Response, AppError> {
    let (content, _is_custom) = resolve_pdf_theme(state.config.pdf_template_dir.as_deref()).await?;

    let mut resp = Response::new(axum::body::Body::from(content));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static(r#"attachment; filename="theme.typ""#),
    );
    resp.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    Ok(resp)
}

pub async fn edit_profile_form_handler(
    State(state): State<AppState>,
    RequireIsoOrAdmin(user): RequireIsoOrAdmin,
) -> Result<impl IntoResponse, AppError> {
    let profile = load_profile(&state).await?;
    render_template(&ProfileFormTemplate {
        company_name: profile.company_name,
        scope_statement: profile.scope_statement,
        has_iso27001: profile
            .target_frameworks
            .iter()
            .any(|f| f == "ISO27001_2022"),
        has_nis2: profile.target_frameworks.iter().any(|f| f == "NIS2_BSIG"),
        csrf_token: user.csrf_token,
    })
}

pub async fn update_profile_handler(
    State(state): State<AppState>,
    RequireIsoOrAdmin(user): RequireIsoOrAdmin,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Form(form): Form<ProfileForm>,
) -> Result<impl IntoResponse, AppError> {
    let company_name = form.company_name.trim().to_string();
    if company_name.is_empty() || company_name.len() > 255 {
        return Err(AppError::Validation(vec![
            "Der Organisationsname muss zwischen 1 und 255 Zeichen lang sein.".to_string(),
        ]));
    }

    let mut frameworks = Vec::new();
    if form.fw_iso27001.is_some() {
        frameworks.push("ISO27001_2022");
    }
    if form.fw_nis2.is_some() {
        frameworks.push("NIS2_BSIG");
    }
    if frameworks.is_empty() {
        frameworks.push("ISO27001_2022");
    }
    let fw_json = serde_json::to_value(&frameworks)
        .map_err(|e| AppError::Internal(format!("JSON-Serialisierung fehlgeschlagen: {e}")))?;

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;
    sqlx::query(
        r#"
        UPDATE organization_profile
        SET company_name = $1,
            scope_statement = $2,
            target_frameworks = $3,
            updated_at = NOW()
        WHERE id = 1
        "#,
    )
    .bind(&company_name)
    .bind(form.scope_statement.trim())
    .bind(fw_json)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let resp = hx_redirect_or_303(&headers, "/organization");
    Ok(with_toast(
        resp,
        "success",
        "Organisationsprofil gespeichert.",
    ))
}

pub async fn new_unit_form_handler(
    State(state): State<AppState>,
    RequireAdmin(user): RequireAdmin,
) -> Result<impl IntoResponse, AppError> {
    let units = load_units(&state)
        .await?
        .into_iter()
        .map(|u| SelectOption {
            id: u.id,
            label: u.name,
        })
        .collect();
    let users = load_active_user_options(&state).await?;

    render_template(&UnitFormTemplate {
        action_url: "/organization/units".to_string(),
        submit_label: "Einheit anlegen",
        name: String::new(),
        selected_parent_id: String::new(),
        selected_lead_id: String::new(),
        units,
        users,
        csrf_token: user.csrf_token,
    })
}

pub async fn create_unit_handler(
    State(state): State<AppState>,
    RequireAdmin(user): RequireAdmin,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Form(form): Form<UnitForm>,
) -> Result<impl IntoResponse, AppError> {
    let name = form.name.trim().to_string();
    if name.is_empty() || name.len() > 150 {
        return Err(AppError::Validation(vec![
            "Der Name der Einheit muss zwischen 1 und 150 Zeichen lang sein.".to_string(),
        ]));
    }
    let parent_id = parse_optional_uuid(form.parent_id.as_deref())?;
    let lead_user_id = parse_optional_uuid(form.lead_user_id.as_deref())?;

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;
    sqlx::query(
        r#"
        INSERT INTO organization_units (name, parent_id, lead_user_id)
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(&name)
    .bind(parent_id)
    .bind(lead_user_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let resp = hx_redirect_or_303(&headers, "/organization");
    Ok(with_toast(
        resp,
        "success",
        "Organisationseinheit angelegt.",
    ))
}

pub async fn edit_unit_form_handler(
    State(state): State<AppState>,
    RequireAdmin(user): RequireAdmin,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let row =
        sqlx::query("SELECT name, parent_id, lead_user_id FROM organization_units WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| {
                AppError::NotFound("Organisationseinheit nicht gefunden.".to_string())
            })?;

    let name: String = row.try_get("name")?;
    let parent_id: Option<Uuid> = row.try_get("parent_id")?;
    let lead_user_id: Option<Uuid> = row.try_get("lead_user_id")?;

    let units = load_units(&state)
        .await?
        .into_iter()
        .filter(|u| u.id != id)
        .map(|u| SelectOption {
            id: u.id,
            label: u.name,
        })
        .collect();
    let users = load_active_user_options(&state).await?;

    render_template(&UnitFormTemplate {
        action_url: format!("/organization/units/{id}"),
        submit_label: "Änderungen speichern",
        name,
        selected_parent_id: parent_id.map(|u| u.to_string()).unwrap_or_default(),
        selected_lead_id: lead_user_id.map(|u| u.to_string()).unwrap_or_default(),
        units,
        users,
        csrf_token: user.csrf_token,
    })
}

pub async fn update_unit_handler(
    State(state): State<AppState>,
    RequireAdmin(user): RequireAdmin,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Form(form): Form<UnitForm>,
) -> Result<impl IntoResponse, AppError> {
    let name = form.name.trim().to_string();
    if name.is_empty() || name.len() > 150 {
        return Err(AppError::Validation(vec![
            "Der Name der Einheit muss zwischen 1 und 150 Zeichen lang sein.".to_string(),
        ]));
    }
    let parent_id = parse_optional_uuid(form.parent_id.as_deref())?;
    if parent_id == Some(id) {
        return Err(AppError::Validation(vec![
            "Eine Einheit kann nicht sich selbst übergeordnet sein.".to_string(),
        ]));
    }
    let lead_user_id = parse_optional_uuid(form.lead_user_id.as_deref())?;

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;
    let res = sqlx::query(
        r#"
        UPDATE organization_units
        SET name = $1, parent_id = $2, lead_user_id = $3, updated_at = NOW()
        WHERE id = $4
        "#,
    )
    .bind(&name)
    .bind(parent_id)
    .bind(lead_user_id)
    .bind(id)
    .execute(&mut *tx)
    .await?;

    if res.rows_affected() == 0 {
        return Err(AppError::NotFound(
            "Organisationseinheit nicht gefunden.".to_string(),
        ));
    }
    tx.commit().await?;

    let resp = hx_redirect_or_303(&headers, "/organization");
    Ok(with_toast(
        resp,
        "success",
        "Organisationseinheit aktualisiert.",
    ))
}

pub async fn delete_unit_handler(
    State(state): State<AppState>,
    RequireAdmin(user): RequireAdmin,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;
    let res = sqlx::query("DELETE FROM organization_units WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;

    if res.rows_affected() == 0 {
        return Err(AppError::NotFound(
            "Organisationseinheit nicht gefunden.".to_string(),
        ));
    }
    tx.commit().await?;

    let resp = hx_redirect_or_303(&headers, "/organization");
    Ok(with_toast(
        resp,
        "success",
        "Organisationseinheit gelöscht.",
    ))
}

pub fn parse_optional_uuid(raw: Option<&str>) -> Result<Option<Uuid>, AppError> {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    Uuid::parse_str(s)
        .map(Some)
        .map_err(|_| AppError::BadRequest("Ungültige UUID übermittelt.".to_string()))
}
