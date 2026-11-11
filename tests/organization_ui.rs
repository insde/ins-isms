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

#[sqlx::test(migrations = "./migrations")]
async fn static_assets_and_dual_mode_shell_work(pool: PgPool) {
    let cfg = test_config();
    seed_initial_data(&pool, &cfg).await.unwrap();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    for path in [
        "/static/app.css",
        "/static/keyboard.js",
        "/static/htmx.min.js",
    ] {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "Asset {path} fehlgeschlagen");
    }

    let (_, cookie, _) =
        create_user_with_session(&pool, &cfg, "dash@example.com", Role::Iso, None).await;

    let full_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(full_resp.status(), StatusCode::OK);
    let full_body = to_bytes(full_resp.into_body(), 256 * 1024).await.unwrap();
    let full_str = String::from_utf8(full_body.to_vec()).unwrap();
    assert!(full_str.contains("<!DOCTYPE html>"));
    assert!(full_str.contains("command-palette"));

    let partial_resp = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &cookie)
                .header("hx-request", "true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(partial_resp.status(), StatusCode::OK);
    let partial_body = to_bytes(partial_resp.into_body(), 256 * 1024)
        .await
        .unwrap();
    let partial_str = String::from_utf8(partial_body.to_vec()).unwrap();
    assert!(!partial_str.contains("<!DOCTYPE html>"));
    assert!(partial_str.contains("ISMS-Übersicht"));
}

#[sqlx::test(migrations = "./migrations")]
async fn organization_profile_update_writes_audit_log(pool: PgPool) {
    let cfg = test_config();
    seed_initial_data(&pool, &cfg).await.unwrap();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let (iso_id, cookie, csrf) =
        create_user_with_session(&pool, &cfg, "iso@example.com", Role::Iso, None).await;

    let resp = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/organization/profile")
                .header(header::COOKIE, &cookie)
                .header("origin", "http://localhost:8080")
                .header("x-csrf-token", &csrf)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(
                    "company_name=Musterbau+GmbH&scope_statement=Standort+Berlin&fw_iso27001=1&fw_nis2=1",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let row =
        sqlx::query("SELECT company_name, scope_statement FROM organization_profile WHERE id = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        row.try_get::<String, _>("company_name").unwrap(),
        "Musterbau GmbH"
    );
    assert_eq!(
        row.try_get::<String, _>("scope_statement").unwrap(),
        "Standort Berlin"
    );

    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE entity_type = 'organization_profile' AND action = 'organization_profile.updated' AND actor_user_id = $1",
    )
    .bind(iso_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit_count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn user_soft_delete_invalidates_sessions_and_audits(pool: PgPool) {
    let cfg = test_config();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let (_, admin_cookie, admin_csrf) =
        create_user_with_session(&pool, &cfg, "admin@example.com", Role::Admin, None).await;
    let (target_id, target_cookie, _) =
        create_user_with_session(&pool, &cfg, "mitarbeiter@example.com", Role::Employee, None)
            .await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/settings/users/{target_id}/deactivate"))
                .header(header::COOKIE, &admin_cookie)
                .header("origin", "http://localhost:8080")
                .header("x-csrf-token", &admin_csrf)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let is_active: bool = sqlx::query_scalar("SELECT is_active FROM users WHERE id = $1")
        .bind(target_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!is_active);

    let blocked = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::COOKIE, &target_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(blocked.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        blocked.headers().get(header::LOCATION).unwrap(),
        &HeaderValue::from_static("/login")
    );

    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE entity_type = 'users' AND entity_id = $1",
    )
    .bind(target_id.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(audit_count >= 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn system_assets_enforce_owner_unit_scope_auditor_readonly_and_audit_logs(pool: PgPool) {
    let cfg = test_config();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let unit_a: Uuid = sqlx::query_scalar(
        "INSERT INTO organization_units (name) VALUES ('IT-Betrieb') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let unit_b: Uuid = sqlx::query_scalar(
        "INSERT INTO organization_units (name) VALUES ('Finanzen') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    let (owner_a_id, owner_a_cookie, owner_a_csrf) = create_user_with_session(
        &pool,
        &cfg,
        "owner-a@example.com",
        Role::Owner,
        Some(unit_a),
    )
    .await;
    let (_, auditor_cookie, auditor_csrf) =
        create_user_with_session(&pool, &cfg, "auditor@example.com", Role::Auditor, None).await;

    let asset_b_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO system_assets (asset_code, name, asset_type, owner_unit_id, criticality)
        VALUES ('FIN-001', 'DATEV-Server', 'server', $1, 'high')
        RETURNING id
        "#,
    )
    .bind(unit_b)
    .fetch_one(&pool)
    .await
    .unwrap();

    let read_b = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/organization/assets/{asset_b_id}"))
                .header(header::COOKIE, &owner_a_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(read_b.status(), StatusCode::OK);

    let forbidden_update = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/organization/assets/{asset_b_id}"))
                .header(header::COOKIE, &owner_a_cookie)
                .header("origin", "http://localhost:8080")
                .header("x-csrf-token", &owner_a_csrf)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "asset_code=FIN-001&name=Manipuliert&asset_type=server&owner_unit_id={unit_b}&criticality=high"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(forbidden_update.status(), StatusCode::FORBIDDEN);

    let create_a = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/organization/assets")
                .header(header::COOKIE, &owner_a_cookie)
                .header("origin", "http://localhost:8080")
                .header("x-csrf-token", &owner_a_csrf)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(format!(
                    "asset_code=IT-001&name=Nextcloud&asset_type=application&owner_unit_id={unit_a}&owner_user_id={owner_a_id}&criticality=high"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_a.status(), StatusCode::SEE_OTHER);

    let auditor_create = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/organization/assets")
                .header(header::COOKIE, &auditor_cookie)
                .header("origin", "http://localhost:8080")
                .header("x-csrf-token", &auditor_csrf)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(
                    "asset_code=AUD-001&name=Verboten&asset_type=server&criticality=normal",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(auditor_create.status(), StatusCode::FORBIDDEN);

    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE entity_type = 'system_assets' AND action = 'system_assets.created' AND actor_user_id = $1",
    )
    .bind(owner_a_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit_count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn system_assets_support_facility_ot_equipment_and_other_types(pool: PgPool) {
    let cfg = test_config();
    seed_initial_data(&pool, &cfg).await.unwrap();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let (_, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "iso-assets@example.com", Role::Iso, None).await;

    for (code, name, asset_type) in [
        ("FAC-001", "Serverraum Hauptgebäude", "facility"),
        ("OT-001", "CNC-Fräsanlage Halle 2", "ot_equipment"),
        ("OTH-001", "Notstromaggregat", "other"),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/organization/assets")
                    .header(header::COOKIE, &iso_cookie)
                    .header("origin", "http://localhost:8080")
                    .header("x-csrf-token", &iso_csrf)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "asset_code={code}&name={name}&asset_type={asset_type}&criticality=high"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    }

    let list_resp = app
        .oneshot(
            Request::builder()
                .uri("/organization/assets")
                .header(header::COOKIE, &iso_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(list_resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        to_bytes(list_resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("Standort / Raum"));
    assert!(body.contains("Maschine / OT-Anlage"));
    assert!(body.contains("Sonstiges Asset"));
    assert!(body.contains("FAC-001"));
    assert!(body.contains("OT-001"));
    assert!(body.contains("OTH-001"));
}
