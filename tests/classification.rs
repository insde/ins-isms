use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    body::{Body, to_bytes},
    http::{HeaderValue, Method, Request, StatusCode, header},
};
use chrono_tz::Europe::Berlin;
use ins_isms::{
    auth::{
        password::hash_password,
        rbac::Role,
        session::{create_session, sign_session_id},
    },
    build_router,
    config::{AppEnv, Config, StorageBackendConfig},
    domain::classification::{CiaLevel, load_effective_system_classification},
    seed::seed_initial_data,
    state::AppState,
    storage::LocalBlobStorage,
};
use sqlx::{PgPool, Row};
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

fn test_config() -> Arc<Config> {
    Arc::new(Config {
        app_env: AppEnv::Development,
        bind_addr: "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
        app_base_url: Url::parse("http://localhost:8080").unwrap(),
        app_timezone: Berlin,
        database_url: "postgres://unused".to_string(),
        migration_database_url: "postgres://unused".to_string(),
        session_secret: b"0123456789abcdef0123456789abcdef".to_vec(),
        session_ttl_hours: 12,
        cookie_secure: false,
        trust_proxy: false,
        init_admin_email: None,
        init_admin_password: None,
        oidc: None,
        storage: StorageBackendConfig::Local {
            path: PathBuf::from("./target/test-blobs"),
        },
        max_upload_bytes: 1024 * 1024,
        typst_bin_path: PathBuf::from("typst"),
        typst_font_paths: None,
        pdf_template_dir: None,
        seed_starter_content: true,
        seed_dir: PathBuf::from("./seeds"),
        smtp: None,
        rust_log: "warn".to_string(),
    })
}

fn test_state(pool: PgPool, config: Arc<Config>) -> AppState {
    AppState {
        pool,
        config,
        storage: Arc::new(LocalBlobStorage::new(PathBuf::from("./target/test-blobs"))),
    }
}

async fn create_user_with_session(
    pool: &PgPool,
    cfg: &Config,
    email: &str,
    role: Role,
    unit_id: Option<Uuid>,
) -> (Uuid, String, String) {
    let pw_hash = hash_password("SicheresTestPasswort123!").await.unwrap();
    let user_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO users (email, full_name, password_hash, role, organization_unit_id, is_active)
        VALUES ($1, $2, $3, $4, $5, TRUE)
        RETURNING id
        "#,
    )
    .bind(email)
    .bind(format!("User {email}"))
    .bind(pw_hash)
    .bind(role.as_str())
    .bind(unit_id)
    .fetch_one(pool)
    .await
    .unwrap();

    let (session_id, csrf) = create_session(pool, user_id, None, None, 12).await.unwrap();
    let signed = sign_session_id(&session_id, &cfg.session_secret).unwrap();
    (user_id, format!("ins_session={signed}"), csrf)
}

fn post_form(uri: &str, cookie: &str, csrf: &str, body: String) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::COOKIE, cookie)
        .header("X-CSRF-Token", csrf)
        .header("HX-Request", "true")
        .header(
            header::ORIGIN,
            HeaderValue::from_static("http://localhost:8080"),
        )
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn repeatabel_classification_seeding_and_restore_defaults(pool: PgPool) {
    let cfg = test_config();
    seed_initial_data(&pool, &cfg).await.unwrap();
    seed_initial_data(&pool, &cfg).await.unwrap();

    let level_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM classification_levels")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(level_count, 4);

    let rule_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM classification_handling_rules")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rule_count, 20);

    // Manuelle Änderung an C2 wird bei erneutem Startup-Seed nicht überschrieben
    sqlx::query("UPDATE classification_levels SET name = 'Intern (angepasst)' WHERE code = 'C2'")
        .execute(&pool)
        .await
        .unwrap();
    seed_initial_data(&pool, &cfg).await.unwrap();

    let c2_name: String =
        sqlx::query_scalar("SELECT name FROM classification_levels WHERE code = 'C2'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(c2_name, "Intern (angepasst)");

    let app = build_router(test_state(pool.clone(), cfg.clone()));
    let (_, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "isb@example.com", Role::Iso, None).await;

    let resp = app
        .oneshot(post_form(
            "/classification/levels/restore-defaults",
            &iso_cookie,
            &iso_csrf,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let c2_restored: String =
        sqlx::query_scalar("SELECT name FROM classification_levels WHERE code = 'C2'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(c2_restored, "Intern");
}

#[sqlx::test(migrations = "./migrations")]
async fn maximum_principle_and_system_linking_audit_work(pool: PgPool) {
    let cfg = test_config();
    seed_initial_data(&pool, &cfg).await.unwrap();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let (_, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "isb@example.com", Role::Iso, None).await;

    let sys_id: Uuid = sqlx::query_scalar(
        "INSERT INTO system_assets (asset_code, name, asset_type, criticality) VALUES ('SYS-01', 'ERP-System', 'application', 'high') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    let c2_id: Uuid = sqlx::query_scalar("SELECT id FROM classification_levels WHERE code = 'C2'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let c4_id: Uuid = sqlx::query_scalar("SELECT id FROM classification_levels WHERE code = 'C4'")
        .fetch_one(&pool)
        .await
        .unwrap();

    let body_1 = format!(
        "name=Projektplaene&classification_level_id={c2_id}&confidentiality=normal&integrity=high&availability=normal&review_interval_months=12&system_asset_ids={sys_id}"
    );
    let resp_1 = app
        .clone()
        .oneshot(post_form(
            "/classification/assets",
            &iso_cookie,
            &iso_csrf,
            body_1,
        ))
        .await
        .unwrap();
    assert_eq!(resp_1.status(), StatusCode::OK);

    let body_2 = format!(
        "name=Schluesselmaterial&classification_level_id={c4_id}&confidentiality=very_high&integrity=normal&availability=high&review_interval_months=6&system_asset_ids={sys_id}"
    );
    let resp_2 = app
        .clone()
        .oneshot(post_form(
            "/classification/assets",
            &iso_cookie,
            &iso_csrf,
            body_2,
        ))
        .await
        .unwrap();
    assert_eq!(resp_2.status(), StatusCode::OK);

    let eff = load_effective_system_classification(&pool, sys_id)
        .await
        .unwrap()
        .expect("Effektiver Schutzbedarf erwartet");
    assert_eq!(eff.level_code, "C4");
    assert_eq!(eff.confidentiality, CiaLevel::VeryHigh);
    assert_eq!(eff.integrity, CiaLevel::High);
    assert_eq!(eff.availability, CiaLevel::High);
    assert_eq!(eff.linked_info_count, 2);

    let sys_page = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/organization/assets")
                .header(header::COOKIE, &iso_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let sys_html = String::from_utf8(
        to_bytes(sys_page.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(sys_html.contains("C4"));

    let info2_id: Uuid =
        sqlx::query_scalar("SELECT id FROM information_assets WHERE name = 'Schluesselmaterial'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let unlink_body = format!(
        "name=Schluesselmaterial&classification_level_id={c4_id}&confidentiality=very_high&integrity=normal&availability=high&review_interval_months=6"
    );
    let resp_unlink = app
        .clone()
        .oneshot(post_form(
            &format!("/classification/assets/{info2_id}"),
            &iso_cookie,
            &iso_csrf,
            unlink_body,
        ))
        .await
        .unwrap();
    assert_eq!(resp_unlink.status(), StatusCode::OK);

    let eff_after = load_effective_system_classification(&pool, sys_id)
        .await
        .unwrap()
        .expect("Effektiver Schutzbedarf erwartet");
    assert_eq!(eff_after.level_code, "C2");
    assert_eq!(eff_after.confidentiality, CiaLevel::Normal);
    assert_eq!(eff_after.integrity, CiaLevel::High);
    assert_eq!(eff_after.linked_info_count, 1);

    let linked_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE action = 'information_asset_systems.linked'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let unlinked_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE action = 'information_asset_systems.unlinked'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(linked_count, 2);
    assert_eq!(unlinked_count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn delete_used_level_returns_422_and_review_workflow_updates_dates(pool: PgPool) {
    let cfg = test_config();
    seed_initial_data(&pool, &cfg).await.unwrap();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let (_, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "isb@example.com", Role::Iso, None).await;

    let c3_id: Uuid = sqlx::query_scalar("SELECT id FROM classification_levels WHERE code = 'C3'")
        .fetch_one(&pool)
        .await
        .unwrap();

    let asset_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO information_assets (name, classification_level_id, review_interval_months)
        VALUES ('Personalakten', $1, 6)
        RETURNING id
        "#,
    )
    .bind(c3_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    let del_resp = app
        .clone()
        .oneshot(post_form(
            &format!("/classification/levels/{c3_id}/delete"),
            &iso_cookie,
            &iso_csrf,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(del_resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let rev_resp = app
        .clone()
        .oneshot(post_form(
            &format!("/classification/assets/{asset_id}/review"),
            &iso_cookie,
            &iso_csrf,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(rev_resp.status(), StatusCode::OK);

    let row = sqlx::query(
        "SELECT last_reviewed_at, next_review_due_at FROM information_assets WHERE id = $1",
    )
    .bind(asset_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let last_rev: Option<chrono::DateTime<chrono::Utc>> = row.try_get("last_reviewed_at").unwrap();
    let next_rev: Option<chrono::DateTime<chrono::Utc>> =
        row.try_get("next_review_due_at").unwrap();
    assert!(last_rev.is_some());
    assert!(next_rev.is_some());
    assert!(next_rev.unwrap() > last_rev.unwrap());
}

#[sqlx::test(migrations = "./migrations")]
async fn rbac_enforces_owner_scope_auditor_readonly_and_employee_matrix_only(pool: PgPool) {
    let cfg = test_config();
    seed_initial_data(&pool, &cfg).await.unwrap();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let unit_a: Uuid = sqlx::query_scalar(
        "INSERT INTO organization_units (name) VALUES ('Abteilung A') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let unit_b: Uuid = sqlx::query_scalar(
        "INSERT INTO organization_units (name) VALUES ('Abteilung B') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    let c2_id: Uuid = sqlx::query_scalar("SELECT id FROM classification_levels WHERE code = 'C2'")
        .fetch_one(&pool)
        .await
        .unwrap();

    let asset_b_id: Uuid = sqlx::query_scalar(
        "INSERT INTO information_assets (name, owner_unit_id, classification_level_id) VALUES ('Verträge B', $1, $2) RETURNING id",
    )
    .bind(unit_b)
    .bind(c2_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    let (_, owner_cookie, owner_csrf) =
        create_user_with_session(&pool, &cfg, "owner@beispiel.de", Role::Owner, Some(unit_a)).await;
    let (_, auditor_cookie, auditor_csrf) =
        create_user_with_session(&pool, &cfg, "auditor@beispiel.de", Role::Auditor, None).await;
    let (_, emp_cookie, _) =
        create_user_with_session(&pool, &cfg, "emp@beispiel.de", Role::Employee, None).await;

    let owner_forbidden = app
        .clone()
        .oneshot(post_form(
            &format!("/classification/assets/{asset_b_id}/review"),
            &owner_cookie,
            &owner_csrf,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(owner_forbidden.status(), StatusCode::FORBIDDEN);

    let owner_ok = app
        .clone()
        .oneshot(post_form(
            "/classification/assets",
            &owner_cookie,
            &owner_csrf,
            format!("name=DokuA&classification_level_id={c2_id}&owner_unit_id={unit_a}&confidentiality=normal&integrity=normal&availability=normal&review_interval_months=12"),
        ))
        .await
        .unwrap();
    assert_eq!(owner_ok.status(), StatusCode::OK);

    let auditor_get = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/classification/assets")
                .header(header::COOKIE, &auditor_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(auditor_get.status(), StatusCode::OK);

    let auditor_post = app
        .clone()
        .oneshot(post_form(
            "/classification/assets",
            &auditor_cookie,
            &auditor_csrf,
            format!("name=Test&classification_level_id={c2_id}&review_interval_months=12"),
        ))
        .await
        .unwrap();
    assert_eq!(auditor_post.status(), StatusCode::FORBIDDEN);

    let emp_matrix = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/classification/levels")
                .header(header::COOKIE, &emp_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(emp_matrix.status(), StatusCode::OK);

    let emp_cheatsheet = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/classification/export/cheatsheet")
                .header(header::COOKIE, &emp_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(emp_cheatsheet.status(), StatusCode::OK);

    let emp_assets = app
        .oneshot(
            Request::builder()
                .uri("/classification/assets")
                .header(header::COOKIE, &emp_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(emp_assets.status(), StatusCode::FORBIDDEN);
}
