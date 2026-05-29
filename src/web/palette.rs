use askama::Template;
use axum::{
    extract::{Query, State},
    response::IntoResponse,
};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use crate::{
    auth::rbac::{CurrentUser, Role},
    error::AppError,
    state::AppState,
    web::render_template,
};

#[derive(Debug, Deserialize)]
pub struct PaletteQuery {
    pub q: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PaletteItem {
    pub label: String,
    pub category: &'static str,
    pub href: String,
}

#[derive(Template)]
#[template(path = "partials/palette_results.html")]
struct PaletteResultsTemplate {
    items: Vec<PaletteItem>,
}

pub async fn palette_search_handler(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<PaletteQuery>,
) -> Result<impl IntoResponse, AppError> {
    let term = query.q.unwrap_or_default().trim().to_string();
    let lower_term = term.to_ascii_lowercase();
    let mut items = Vec::new();

    let mut nav_targets: Vec<(&str, &str)> = vec![
        ("Dashboard", "/"),
        ("Organisation & Einheiten", "/organization"),
        ("Schutzstufen & Handling-Matrix", "/classification/levels"),
        (
            "Klassifizierungs-One-Pager",
            "/classification/export/cheatsheet",
        ),
        ("Dokumente & Richtlinien", "/documents"),
        ("Maßnahmen & CAPA", "/actions"),
        ("Sicherheitsvorfälle & NIS2", "/incidents"),
        ("Mein Konto & Passwort", "/account"),
    ];
    if user.role != Role::Auditor {
        nav_targets.push(("Sicherheitsvorfall melden", "/incidents/report"));
    }
    if user.role != Role::Employee {
        nav_targets.push(("System-Assets", "/organization/assets"));
        nav_targets.push(("Informationswerte", "/classification/assets"));
        nav_targets.push(("Statement of Applicability (SoA)", "/soa"));
        nav_targets.push(("Risikomanagement & Heatmap", "/risks"));
        nav_targets.push(("Interne Audits & Findings", "/audits"));
        nav_targets.push(("Management-Bewertungen (ISO 9.3)", "/management-reviews"));
    }
    if matches!(user.role, Role::Admin | Role::Iso | Role::Auditor) {
        nav_targets.push(("Revisionssicheres Audit-Log", "/audit-logs"));
        nav_targets.push(("Exporte & Import", "/exports"));
    }
    if user.role.is_iso_or_admin() {
        nav_targets.push(("Benutzerverwaltung", "/settings/users"));
    }

    for (label, href) in nav_targets {
        if lower_term.is_empty() || label.to_ascii_lowercase().contains(&lower_term) {
            items.push(PaletteItem {
                label: label.to_string(),
                category: "Navigation",
                href: href.to_string(),
            });
        }
    }

    let like_pattern = format!("%{term}%");

    if user.role != Role::Employee {
        let unit_rows = sqlx::query(
            r#"
            SELECT id, name
            FROM organization_units
            WHERE $1 = '' OR name ILIKE $2
            ORDER BY name ASC
            LIMIT 5
            "#,
        )
        .bind(&term)
        .bind(&like_pattern)
        .fetch_all(&state.pool)
        .await?;

        for row in unit_rows {
            let _id: Uuid = row.try_get("id")?;
            let name: String = row.try_get("name")?;
            items.push(PaletteItem {
                label: name,
                category: "Einheit",
                href: "/organization".to_string(),
            });
        }

        let asset_rows = sqlx::query(
            r#"
            SELECT id, asset_code, name
            FROM system_assets
            WHERE $1 = '' OR asset_code ILIKE $2 OR name ILIKE $2 OR COALESCE(vendor_name, '') ILIKE $2
            ORDER BY asset_code ASC
            LIMIT 6
            "#,
        )
        .bind(&term)
        .bind(&like_pattern)
        .fetch_all(&state.pool)
        .await?;

        for row in asset_rows {
            let id: Uuid = row.try_get("id")?;
            let code: String = row.try_get("asset_code")?;
            let name: String = row.try_get("name")?;
            items.push(PaletteItem {
                label: format!("{code} · {name}"),
                category: "System-Asset",
                href: format!("/organization/assets?selected={id}"),
            });
        }

        let info_rows = sqlx::query(
            r#"
            SELECT ia.id, ia.name, cl.code AS level_code
            FROM information_assets ia
            JOIN classification_levels cl ON cl.id = ia.classification_level_id
            WHERE $1 = '' OR ia.name ILIKE $2 OR COALESCE(ia.description, '') ILIKE $2
            ORDER BY cl.rank DESC, ia.name ASC
            LIMIT 6
            "#,
        )
        .bind(&term)
        .bind(&like_pattern)
        .fetch_all(&state.pool)
        .await?;

        for row in info_rows {
            let id: Uuid = row.try_get("id")?;
            let name: String = row.try_get("name")?;
            let level_code: String = row.try_get("level_code")?;
            items.push(PaletteItem {
                label: format!("{level_code} · {name}"),
                category: "Informationswert",
                href: format!("/classification/assets?selected={id}"),
            });
        }

        let ctrl_rows = sqlx::query(
            r#"
            SELECT cf.code AS fw_code, fc.code AS ctrl_code, fc.title
            FROM framework_controls fc
            JOIN compliance_frameworks cf ON cf.id = fc.framework_id
            WHERE $1 = '' OR fc.code ILIKE $2 OR fc.title ILIKE $2
            ORDER BY (cf.code = 'ISO27001_2022_STARTER') DESC, fc.sort_order ASC
            LIMIT 6
            "#,
        )
        .bind(&term)
        .bind(&like_pattern)
        .fetch_all(&state.pool)
        .await?;

        for row in ctrl_rows {
            let fw_code: String = row.try_get("fw_code")?;
            let ctrl_code: String = row.try_get("ctrl_code")?;
            let title: String = row.try_get("title")?;
            items.push(PaletteItem {
                label: format!("{ctrl_code} · {title}"),
                category: "Control",
                href: format!("/soa?framework={fw_code}&q={ctrl_code}"),
            });
        }

        let risk_rows = sqlx::query(
            r#"
            SELECT reference_code, title
            FROM risk_scenarios
            WHERE $1 = '' OR reference_code ILIKE $2 OR title ILIKE $2
            ORDER BY (residual_likelihood * residual_impact) DESC, reference_code ASC
            LIMIT 6
            "#,
        )
        .bind(&term)
        .bind(&like_pattern)
        .fetch_all(&state.pool)
        .await?;

        for row in risk_rows {
            let code: String = row.try_get("reference_code")?;
            let title: String = row.try_get("title")?;
            items.push(PaletteItem {
                label: format!("{code} · {title}"),
                category: "Risiko",
                href: format!("/risks?q={code}"),
            });
        }

        let owner_unit_filter = if user.role == Role::Owner {
            Some(user.organization_unit_id.unwrap_or_else(Uuid::nil))
        } else {
            None
        };
        let audit_rows = sqlx::query(
            r#"
            SELECT ia.id, ia.audit_code, ia.title
            FROM internal_audits ia
            WHERE ($1 = '' OR ia.audit_code ILIKE $2 OR ia.title ILIKE $2)
              AND (
                  $3::uuid IS NULL
                  OR EXISTS (
                      SELECT 1 FROM audit_findings af
                      WHERE af.audit_id = ia.id AND af.owner_unit_id = $3
                  )
              )
            ORDER BY ia.audit_date DESC
            LIMIT 4
            "#,
        )
        .bind(&term)
        .bind(&like_pattern)
        .bind(owner_unit_filter)
        .fetch_all(&state.pool)
        .await?;

        for row in audit_rows {
            let id: Uuid = row.try_get("id")?;
            let code: String = row.try_get("audit_code")?;
            let title: String = row.try_get("title")?;
            items.push(PaletteItem {
                label: format!("{code} · {title}"),
                category: "Audit",
                href: format!("/audits/{id}"),
            });
        }

        let only_approved_reviews = !user.role.is_iso_or_admin();
        let review_rows = sqlx::query(
            r#"
            SELECT id, period_label
            FROM management_reviews
            WHERE (NOT $1 OR status = 'approved')
              AND ($2 = '' OR period_label ILIKE $3)
            ORDER BY review_date DESC
            LIMIT 4
            "#,
        )
        .bind(only_approved_reviews)
        .bind(&term)
        .bind(&like_pattern)
        .fetch_all(&state.pool)
        .await?;

        for row in review_rows {
            let id: Uuid = row.try_get("id")?;
            let period_label: String = row.try_get("period_label")?;
            items.push(PaletteItem {
                label: format!("Management-Bewertung · {period_label}"),
                category: "Review",
                href: format!("/management-reviews/{id}"),
            });
        }
    }

    let inc_scope_mode: i32 = match user.role {
        Role::Admin | Role::Iso | Role::Auditor => 0,
        Role::Owner => 1,
        Role::Employee => 2,
    };
    let inc_rows = sqlx::query(
        r#"
        SELECT id, reference_code, title
        FROM security_incidents
        WHERE (
            $1 = 0
            OR ($1 = 1 AND (owner_unit_id = $2 OR reported_by_user_id = $3 OR lead_handler_id = $3))
            OR ($1 = 2 AND reported_by_user_id = $3)
        )
          AND ($4 = '' OR reference_code ILIKE $5 OR title ILIKE $5)
        ORDER BY (status = 'closed') ASC, detected_at DESC
        LIMIT 6
        "#,
    )
    .bind(inc_scope_mode)
    .bind(user.organization_unit_id)
    .bind(user.id)
    .bind(&term)
    .bind(&like_pattern)
    .fetch_all(&state.pool)
    .await?;

    for row in inc_rows {
        let id: Uuid = row.try_get("id")?;
        let code: String = row.try_get("reference_code")?;
        let title: String = row.try_get("title")?;
        items.push(PaletteItem {
            label: format!("{code} · {title}"),
            category: "Vorfall",
            href: format!("/incidents/{id}"),
        });
    }

    let act_rows = sqlx::query(
        r#"
        SELECT reference_code, title
        FROM action_items
        WHERE (
            $1 = 0
            OR ($1 = 1 AND (owner_unit_id = $2 OR assignee_user_id = $3))
            OR ($1 = 2 AND assignee_user_id = $3)
        )
          AND ($4 = '' OR reference_code ILIKE $5 OR title ILIKE $5)
        ORDER BY (status IN ('done', 'cancelled')) ASC, due_date ASC NULLS LAST
        LIMIT 6
        "#,
    )
    .bind(inc_scope_mode)
    .bind(user.organization_unit_id)
    .bind(user.id)
    .bind(&term)
    .bind(&like_pattern)
    .fetch_all(&state.pool)
    .await?;

    for row in act_rows {
        let code: String = row.try_get("reference_code")?;
        let title: String = row.try_get("title")?;
        items.push(PaletteItem {
            label: format!("{code} · {title}"),
            category: "Maßnahme",
            href: format!("/actions?q={code}"),
        });
    }

    let restricted_viewer = matches!(user.role, Role::Auditor | Role::Employee);
    let doc_rows = sqlx::query(
        r#"
        SELECT d.id, d.doc_code, d.title
        FROM documents d
        WHERE ($1 = '' OR d.doc_code ILIKE $2 OR d.title ILIKE $2)
          AND (
              NOT $3
              OR EXISTS (
                  SELECT 1 FROM document_versions dv
                  WHERE dv.document_id = d.id AND dv.status = 'approved'
              )
          )
        ORDER BY d.doc_code ASC
        LIMIT 6
        "#,
    )
    .bind(&term)
    .bind(&like_pattern)
    .bind(restricted_viewer)
    .fetch_all(&state.pool)
    .await?;

    for row in doc_rows {
        let id: Uuid = row.try_get("id")?;
        let code: String = row.try_get("doc_code")?;
        let title: String = row.try_get("title")?;
        items.push(PaletteItem {
            label: format!("{code} · {title}"),
            category: "Dokument",
            href: format!("/documents/{id}"),
        });
    }

    if user.role.is_iso_or_admin() {
        let user_rows = sqlx::query(
            r#"
            SELECT full_name, email
            FROM users
            WHERE $1 = '' OR full_name ILIKE $2 OR email ILIKE $2
            ORDER BY full_name ASC
            LIMIT 5
            "#,
        )
        .bind(&term)
        .bind(&like_pattern)
        .fetch_all(&state.pool)
        .await?;

        for row in user_rows {
            let full_name: String = row.try_get("full_name")?;
            let email: String = row.try_get("email")?;
            items.push(PaletteItem {
                label: format!("{full_name} ({email})"),
                category: "Benutzer",
                href: "/settings/users".to_string(),
            });
        }
    }

    items.truncate(15);
    render_template(&PaletteResultsTemplate { items })
}
