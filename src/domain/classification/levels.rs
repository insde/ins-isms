use std::str::FromStr;

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::IntoResponse,
};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    auth::rbac::{ClientIp, CurrentUser, RequireIsoOrAdmin},
    db::begin_audited_tx,
    domain::classification::{BadgeColor, HandlingCategory},
    error::AppError,
    seed::seed_classification_defaults_tx,
    state::AppState,
    web::{ShellContext, hx_redirect_or_303, render_page, with_toast},
};

#[derive(Debug, Clone)]
pub struct RuleCellView {
    pub id: Uuid,
    pub category_code: &'static str,
    pub category_label: &'static str,
    pub rule_text: String,
}

#[derive(Debug, Clone)]
pub struct LevelMatrixView {
    pub id: Uuid,
    pub code: String,
    pub rank: i32,
    pub name: String,
    pub description: String,
    pub badge_color: String,
    pub badge_css_class: &'static str,
    pub rules: Vec<RuleCellView>,
    pub asset_count: i64,
}

#[derive(Debug, Clone)]
pub struct CategoryRowView {
    pub code: &'static str,
    pub label: &'static str,
    pub cells: Vec<Option<RuleCellView>>,
}

#[derive(Template)]
#[template(path = "classification/levels.html")]
struct LevelsTemplate {
    levels: Vec<LevelMatrixView>,
    categories: Vec<CategoryRowView>,
    can_edit: bool,
    can_view_assets: bool,
}

pub async fn load_levels_with_rules(
    pool: &sqlx::PgPool,
) -> Result<(Vec<LevelMatrixView>, Vec<CategoryRowView>), AppError> {
    let level_rows = sqlx::query(
        r#"
        SELECT
            cl.id,
            cl.code,
            cl.rank,
            cl.name,
            cl.description,
            cl.badge_color,
            (SELECT COUNT(*) FROM information_assets ia WHERE ia.classification_level_id = cl.id) AS asset_count
        FROM classification_levels cl
        ORDER BY cl.rank ASC, cl.code ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    let rule_rows = sqlx::query(
        r#"
        SELECT id, level_id, category, rule_text, sort_order
        FROM classification_handling_rules
        ORDER BY sort_order ASC, created_at ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    let mut rules_by_level: std::collections::HashMap<Uuid, Vec<RuleCellView>> =
        std::collections::HashMap::new();
    for r in rule_rows {
        let level_id: Uuid = r.try_get("level_id")?;
        let cat_str: String = r.try_get("category")?;
        let cat = HandlingCategory::from_str(&cat_str).unwrap_or(HandlingCategory::Storage);
        rules_by_level
            .entry(level_id)
            .or_default()
            .push(RuleCellView {
                id: r.try_get("id")?,
                category_code: cat.as_str(),
                category_label: cat.label(),
                rule_text: r.try_get("rule_text")?,
            });
    }

    let mut levels = Vec::with_capacity(level_rows.len());
    for row in level_rows {
        let id: Uuid = row.try_get("id")?;
        let badge_str: String = row.try_get("badge_color")?;
        let badge = BadgeColor::from_str(&badge_str).unwrap_or(BadgeColor::Neutral);

        levels.push(LevelMatrixView {
            id,
            code: row.try_get("code")?,
            rank: row.try_get("rank")?,
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            badge_color: badge_str,
            badge_css_class: badge.css_class(),
            rules: rules_by_level.remove(&id).unwrap_or_default(),
            asset_count: row.try_get("asset_count")?,
        });
    }

    let mut categories = Vec::with_capacity(HandlingCategory::ALL.len());
    for cat in HandlingCategory::ALL {
        let cells = levels
            .iter()
            .map(|lvl| {
                lvl.rules
                    .iter()
                    .find(|rule| rule.category_code == cat.as_str())
                    .cloned()
            })
            .collect();
        categories.push(CategoryRowView {
            code: cat.as_str(),
            label: cat.label(),
            cells,
        });
    }

    Ok((levels, categories))
}

pub async fn matrix_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let (levels, categories) = load_levels_with_rules(&state.pool).await?;
    let can_edit = user.role.is_iso_or_admin();
    let can_view_assets = user.role != crate::auth::rbac::Role::Employee;

    let shell = ShellContext::from_user(
        &user,
        "Schutzstufen & Handling-Matrix",
        "Klassifizierung",
        "classification",
    );
    render_page(
        &headers,
        shell,
        &LevelsTemplate {
            levels,
            categories,
            can_edit,
            can_view_assets,
        },
    )
}

#[derive(Debug, Deserialize)]
pub struct CreateLevelForm {
    pub code: String,
    pub rank: i32,
    pub name: String,
    pub description: String,
    pub badge_color: String,
}

pub async fn create_level_handler(
    State(state): State<AppState>,
    RequireIsoOrAdmin(user): RequireIsoOrAdmin,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Form(form): Form<CreateLevelForm>,
) -> Result<impl IntoResponse, AppError> {
    let code = form.code.trim().to_ascii_uppercase();
    let name = form.name.trim().to_string();
    let description = form.description.trim().to_string();
    let badge = BadgeColor::from_str(&form.badge_color)?;

    let mut errors = Vec::new();
    if code.is_empty() || code.len() > 16 {
        errors.push("Code muss zwischen 1 und 16 Zeichen lang sein.".to_string());
    }
    if form.rank < 1 {
        errors.push("Rang muss mindestens 1 sein.".to_string());
    }
    if name.is_empty() || name.len() > 100 {
        errors.push("Name muss zwischen 1 und 100 Zeichen lang sein.".to_string());
    }
    if description.is_empty() {
        errors.push("Beschreibung darf nicht leer sein.".to_string());
    }
    if !errors.is_empty() {
        return Err(AppError::Validation(errors));
    }

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;

    let dup: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM classification_levels WHERE code = $1 OR rank = $2 LIMIT 1",
    )
    .bind(&code)
    .bind(form.rank)
    .fetch_optional(&mut *tx)
    .await?;

    if dup.is_some() {
        return Err(AppError::Validation(vec![
            "Code oder Rang ist bereits vergeben.".to_string(),
        ]));
    }

    let level_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO classification_levels (code, rank, name, description, badge_color)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
        "#,
    )
    .bind(&code)
    .bind(form.rank)
    .bind(&name)
    .bind(&description)
    .bind(badge.as_str())
    .fetch_one(&mut *tx)
    .await?;

    for (idx, cat) in HandlingCategory::ALL.iter().enumerate() {
        sqlx::query(
            r#"
            INSERT INTO classification_handling_rules (level_id, category, rule_text, sort_order)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(level_id)
        .bind(cat.as_str())
        .bind("Noch zu definieren.")
        .bind((idx + 1) as i32)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    Ok(with_toast(
        hx_redirect_or_303(&headers, "/classification/levels"),
        "success",
        "Schutzstufe angelegt.",
    ))
}

#[derive(Debug, Deserialize)]
pub struct UpdateLevelForm {
    pub name: String,
    pub description: String,
    pub badge_color: String,
}

pub async fn update_level_handler(
    State(state): State<AppState>,
    RequireIsoOrAdmin(user): RequireIsoOrAdmin,
    ClientIp(ip): ClientIp,
    Path(id): Path<Uuid>,
    Form(form): Form<UpdateLevelForm>,
) -> Result<impl IntoResponse, AppError> {
    let name = form.name.trim().to_string();
    let description = form.description.trim().to_string();
    let badge = BadgeColor::from_str(&form.badge_color)?;

    let mut errors = Vec::new();
    if name.is_empty() || name.len() > 100 {
        errors.push("Name muss zwischen 1 und 100 Zeichen lang sein.".to_string());
    }
    if description.is_empty() {
        errors.push("Beschreibung darf nicht leer sein.".to_string());
    }
    if !errors.is_empty() {
        return Err(AppError::Validation(errors));
    }

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;
    let affected = sqlx::query(
        r#"
        UPDATE classification_levels
        SET name = $2,
            description = $3,
            badge_color = $4,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(&name)
    .bind(&description)
    .bind(badge.as_str())
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if affected == 0 {
        return Err(AppError::NotFound(
            "Schutzstufe nicht gefunden.".to_string(),
        ));
    }
    tx.commit().await?;

    Ok(with_toast(
        (axum::http::StatusCode::OK, "").into_response(),
        "success",
        "Schutzstufe gespeichert.",
    ))
}

pub async fn delete_level_handler(
    State(state): State<AppState>,
    RequireIsoOrAdmin(user): RequireIsoOrAdmin,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;
    let res = sqlx::query("DELETE FROM classification_levels WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await;

    match res {
        Ok(done) => {
            if done.rows_affected() == 0 {
                return Err(AppError::NotFound("Schutzstufe nicht gefunden.".to_string()));
            }
            tx.commit().await?;
            Ok(with_toast(
                hx_redirect_or_303(&headers, "/classification/levels"),
                "success",
                "Schutzstufe gelöscht.",
            ))
        }
        Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("23503") => {
            Err(AppError::Validation(vec![
                "Diese Schutzstufe kann nicht gelöscht werden, da noch Informationswerte darauf verweisen."
                    .to_string(),
            ]))
        }
        Err(err) => Err(AppError::Database(err)),
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateRuleForm {
    pub rule_text: String,
}

pub async fn update_rule_handler(
    State(state): State<AppState>,
    RequireIsoOrAdmin(user): RequireIsoOrAdmin,
    ClientIp(ip): ClientIp,
    Path(id): Path<Uuid>,
    Form(form): Form<UpdateRuleForm>,
) -> Result<impl IntoResponse, AppError> {
    let rule_text = form.rule_text.trim().to_string();
    if rule_text.is_empty() {
        return Err(AppError::Validation(vec![
            "Regeltext darf nicht leer sein.".to_string(),
        ]));
    }

    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;
    let affected = sqlx::query(
        r#"
        UPDATE classification_handling_rules
        SET rule_text = $2,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .bind(&rule_text)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if affected == 0 {
        return Err(AppError::NotFound(
            "Handling-Regel nicht gefunden.".to_string(),
        ));
    }
    tx.commit().await?;

    Ok(with_toast(
        (axum::http::StatusCode::OK, "").into_response(),
        "success",
        "Handling-Regel gespeichert.",
    ))
}

pub async fn restore_defaults_handler(
    State(state): State<AppState>,
    RequireIsoOrAdmin(user): RequireIsoOrAdmin,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let mut tx = begin_audited_tx(&state.pool, Some(user.id), Some(ip)).await?;
    seed_classification_defaults_tx(&mut tx, true).await?;
    tx.commit().await?;

    Ok(with_toast(
        hx_redirect_or_303(&headers, "/classification/levels"),
        "success",
        "Standard-Schutzstufen und Handling-Regeln wiederhergestellt.",
    ))
}
