use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    body::{Body, to_bytes},
    http::{HeaderValue, Method, Request, StatusCode, header},
};
use chrono::{Duration, Utc};
use chrono_tz::Europe::Berlin;
use ins_isms::{
    audit::verify_hash_chain,
    auth::{
        password::hash_password,
        rbac::{Role, forbid_auditor},
        session::create_session,
    },
    build_router,
    config::{AppEnv, Config, StorageBackendConfig},
    db::begin_audited_tx,
    seed::seed_initial_data,
    state::AppState,
    storage::LocalBlobStorage,
};
use sqlx::PgPool;
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
        init_admin_email: Some("init-admin@example.com".to_string()),
        init_admin_password: Some("InitialAdminPass123!".to_string()),
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

fn extract_set_cookie_pair(resp: &axum::response::Response) -> Option<String> {
    for val in resp.headers().get_all(header::SET_COOKIE) {
        if let Ok(s) = val.to_str()
            && let Some(pair) = s.split(';').next()
            && pair.starts_with("ins_session=")
        {
            return Some(pair.to_string());
        }
    }
    None
}

async fn insert_user(
    pool: &PgPool,
    email: &str,
    password: &str,
    role: Role,
    expires_at: Option<chrono::DateTime<Utc>>,
) -> Uuid {
    let hash = hash_password(password).await.unwrap();
    sqlx::query_scalar(
        r#"
        INSERT INTO users (email, full_name, password_hash, role, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
        "#,
    )
    .bind(email)
    .bind("Test User")
    .bind(hash)
    .bind(role.as_str())
    .bind(expires_at)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn zero_touch_admin_seeding_is_repeatablet(pool: PgPool) {
    let cfg = test_config();
    seed_initial_data(&pool, &cfg).await.unwrap();
    seed_initial_data(&pool, &cfg).await.unwrap();

    let admin_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(admin_count, 1);

    let profile_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM organization_profile")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(profile_count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn brute_force_lockout_returns_429_after_five_failures(pool: PgPool) {
    let cfg = test_config();
    insert_user(
        &pool,
        "opfer@example.com",
        "RichtigesPasswort12!",
        Role::Employee,
        None,
    )
    .await;
    let app = build_router(test_state(pool.clone(), cfg));

    for _ in 0..5 {
        let req = Request::builder()
            .method(Method::POST)
            .uri("/login")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(
                "email=opfer%40example.com&password=Falsch123456!",
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    let req6 = Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(
            "email=opfer%40example.com&password=RichtigesPasswort12!",
        ))
        .unwrap();
    let resp6 = app.oneshot(req6).await.unwrap();
    assert_eq!(resp6.status(), StatusCode::TOO_MANY_REQUESTS);

    let locked_events: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE action = 'auth.login_locked'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(locked_events, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn csrf_middleware_blocks_missing_or_invalid_origin_and_token(pool: PgPool) {
    let cfg = test_config();
    let uid = insert_user(
        &pool,
        "user@example.com",
        "MeinPasswort123!",
        Role::Employee,
        None,
    )
    .await;
    let app = build_router(test_state(pool.clone(), cfg));

    let login_req = Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(
            "email=user%40example.com&password=MeinPasswort123!",
        ))
        .unwrap();
    let login_resp = app.clone().oneshot(login_req).await.unwrap();
    assert_eq!(login_resp.status(), StatusCode::SEE_OTHER);
    let cookie_pair = extract_set_cookie_pair(&login_resp).unwrap();

    assert_eq!(
        login_resp.headers().get("x-frame-options").unwrap(),
        &HeaderValue::from_static("DENY")
    );
    assert_eq!(
        login_resp.headers().get("x-content-type-options").unwrap(),
        &HeaderValue::from_static("nosniff")
    );

    let no_origin = Request::builder()
        .method(Method::POST)
        .uri("/logout")
        .header(header::COOKIE, &cookie_pair)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(no_origin).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    let bad_origin = Request::builder()
        .method(Method::POST)
        .uri("/logout")
        .header(header::COOKIE, &cookie_pair)
        .header(header::ORIGIN, "https://evil.example")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(bad_origin).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    let no_csrf = Request::builder()
        .method(Method::POST)
        .uri("/logout")
        .header(header::COOKIE, &cookie_pair)
        .header(header::ORIGIN, "http://localhost:8080")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(no_csrf).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    let csrf_token: String =
        sqlx::query_scalar("SELECT csrf_token FROM sessions WHERE user_id = $1")
            .bind(uid)
            .fetch_one(&pool)
            .await
            .unwrap();
    let valid_logout = Request::builder()
        .method(Method::POST)
        .uri("/logout")
        .header(header::COOKIE, &cookie_pair)
        .header(header::ORIGIN, "http://localhost:8080")
        .header("x-csrf-token", csrf_token)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(valid_logout).await.unwrap().status(),
        StatusCode::SEE_OTHER
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn expired_user_loses_session_access_immediately_and_htmx_gets_hx_redirect(pool: PgPool) {
    let cfg = test_config();
    let uid = insert_user(
        &pool,
        "auditor@example.com",
        "AuditorPass123!",
        Role::Auditor,
        Some(Utc::now() + Duration::hours(2)),
    )
    .await;
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let login_req = Request::builder()
        .method(Method::POST)
        .uri("/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(
            "email=auditor%40example.com&password=AuditorPass123!",
        ))
        .unwrap();
    let login_resp = app.clone().oneshot(login_req).await.unwrap();
    let cookie_pair = extract_set_cookie_pair(&login_resp).unwrap();

    let ok_req = Request::builder()
        .method(Method::GET)
        .uri("/audit-logs/verify")
        .header(header::COOKIE, &cookie_pair)
        .body(Body::empty())
        .unwrap();
    let ok_resp = app.clone().oneshot(ok_req).await.unwrap();
    assert_eq!(ok_resp.status(), StatusCode::OK);

    sqlx::query("UPDATE users SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1")
        .bind(uid)
        .execute(&pool)
        .await
        .unwrap();

    let expired_req = Request::builder()
        .method(Method::GET)
        .uri("/audit-logs")
        .header(header::COOKIE, &cookie_pair)
        .body(Body::empty())
        .unwrap();
    let expired_resp = app.clone().oneshot(expired_req).await.unwrap();
    assert_eq!(expired_resp.status(), StatusCode::SEE_OTHER);

    let htmx_req = Request::builder()
        .method(Method::GET)
        .uri("/audit-logs")
        .header(header::COOKIE, &cookie_pair)
        .header("hx-request", "true")
        .body(Body::empty())
        .unwrap();
    let htmx_resp = app.oneshot(htmx_req).await.unwrap();
    assert_eq!(htmx_resp.status(), StatusCode::OK);
    assert_eq!(
        htmx_resp.headers().get("hx-redirect").unwrap(),
        &HeaderValue::from_static("/login")
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn auditor_is_strictly_read_only_on_admin_endpoints(pool: PgPool) {
    let cfg = test_config();
    let auditor_id = insert_user(
        &pool,
        "pruefer@example.com",
        "PrueferPass123!",
        Role::Auditor,
        None,
    )
    .await;
    let target_id = insert_user(
        &pool,
        "mitarbeiter@example.com",
        "Mitarbeiter123!",
        Role::Employee,
        None,
    )
    .await;

    let (sid, csrf) = create_session(&pool, auditor_id, None, None, 12)
        .await
        .unwrap();
    let signed = ins_isms::auth::session::sign_session_id(&sid, &cfg.session_secret).unwrap();
    let cookie_pair = format!("ins_session={signed}");

    let app = build_router(test_state(pool, cfg));
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("/settings/users/{target_id}/reset-password"))
        .header(header::COOKIE, cookie_pair)
        .header(header::ORIGIN, "http://localhost:8080")
        .header("x-csrf-token", csrf)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(""))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let dummy_auditor = ins_isms::auth::rbac::CurrentUser {
        id: auditor_id,
        email: "pruefer@example.com".to_string(),
        full_name: "Prüfer".to_string(),
        role: Role::Auditor,
        organization_unit_id: None,
        session_id: "s".to_string(),
        csrf_token: "c".to_string(),
    };
    assert!(forbid_auditor(&dummy_auditor).is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn audit_hash_chain_is_immutable_and_detects_tampering(pool: PgPool) {
    let cfg = test_config();
    let admin_id = insert_user(
        &pool,
        "admin@example.com",
        "AdminPasswort123!",
        Role::Admin,
        None,
    )
    .await;

    let mut tx = begin_audited_tx(&pool, Some(admin_id), Some("10.0.0.5".parse().unwrap()))
        .await
        .unwrap();
    sqlx::query(
        r#"
        INSERT INTO system_assets (asset_code, name, asset_type, owner_user_id)
        VALUES ('SYS-001', 'ERP-System', 'application', $1)
        "#,
    )
    .bind(admin_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let valid_res = verify_hash_chain(&pool).await.unwrap();
    assert!(valid_res.is_valid());
    assert!(valid_res.total_entries >= 2);

    let update_err = sqlx::query("UPDATE audit_logs SET summary = 'manipuliert' WHERE id = 1")
        .execute(&pool)
        .await
        .unwrap_err();
    assert!(update_err.to_string().contains("immutable"));

    let delete_err = sqlx::query("DELETE FROM audit_logs WHERE id = 1")
        .execute(&pool)
        .await
        .unwrap_err();
    assert!(delete_err.to_string().contains("immutable"));

    sqlx::query("ALTER TABLE audit_logs DISABLE TRIGGER trg_audit_logs_immutable")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE audit_logs SET summary = 'heimlich geaendert' WHERE id = 1")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE audit_logs ENABLE TRIGGER trg_audit_logs_immutable")
        .execute(&pool)
        .await
        .unwrap();

    let compromised = verify_hash_chain(&pool).await.unwrap();
    assert!(!compromised.is_valid());
    assert_eq!(compromised.first_broken_id, Some(1));

    let (sid, _) = create_session(&pool, admin_id, None, None, 12)
        .await
        .unwrap();
    let signed = ins_isms::auth::session::sign_session_id(&sid, &cfg.session_secret).unwrap();
    let app = build_router(test_state(pool, cfg));

    let verify_req = Request::builder()
        .method(Method::GET)
        .uri("/audit-logs/verify")
        .header(header::COOKIE, format!("ins_session={signed}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(verify_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        to_bytes(resp.into_body(), 1024 * 64)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("COMPROMISED"));
}

#[sqlx::test(migrations = "./migrations")]
async fn audit_log_list_shows_actor_and_detail_drawer_renders_diff(pool: PgPool) {
    let cfg = test_config();
    let actor_id = insert_user(
        &pool,
        "audit-actor@example.com",
        "ActorPasswort123!",
        Role::Iso,
        None,
    )
    .await;
    let auditor_id = insert_user(
        &pool,
        "audit-viewer@example.com",
        "AuditorPasswort123!",
        Role::Auditor,
        None,
    )
    .await;
    let employee_id = insert_user(
        &pool,
        "audit-employee@example.com",
        "EmployeePass123!",
        Role::Employee,
        None,
    )
    .await;
    let owner_id = insert_user(
        &pool,
        "audit-owner@example.com",
        "OwnerPasswort123!",
        Role::Owner,
        None,
    )
    .await;

    let mut tx = begin_audited_tx(&pool, Some(actor_id), Some("10.10.0.1".parse().unwrap()))
        .await
        .unwrap();
    let asset_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO system_assets (asset_code, name, asset_type, owner_user_id)
        VALUES ('SYS-DIFF-1', 'Alt-System', 'application', $1)
        RETURNING id
        "#,
    )
    .bind(actor_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let mut tx2 = begin_audited_tx(&pool, Some(actor_id), Some("10.10.0.1".parse().unwrap()))
        .await
        .unwrap();
    sqlx::query("UPDATE system_assets SET name = 'Neu-System' WHERE id = $1")
        .bind(asset_id)
        .execute(&mut *tx2)
        .await
        .unwrap();
    tx2.commit().await.unwrap();

    let update_log_id: i64 = sqlx::query_scalar(
        "SELECT id FROM audit_logs WHERE entity_type = 'system_assets' AND action = 'system_assets.updated' AND entity_id = $1",
    )
    .bind(asset_id.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();

    let (auditor_sid, _) = create_session(&pool, auditor_id, None, None, 12)
        .await
        .unwrap();
    let auditor_cookie = format!(
        "ins_session={}",
        ins_isms::auth::session::sign_session_id(&auditor_sid, &cfg.session_secret).unwrap()
    );
    let (emp_sid, _) = create_session(&pool, employee_id, None, None, 12)
        .await
        .unwrap();
    let emp_cookie = format!(
        "ins_session={}",
        ins_isms::auth::session::sign_session_id(&emp_sid, &cfg.session_secret).unwrap()
    );
    let (owner_sid, _) = create_session(&pool, owner_id, None, None, 12)
        .await
        .unwrap();
    let owner_cookie = format!(
        "ins_session={}",
        ins_isms::auth::session::sign_session_id(&owner_sid, &cfg.session_secret).unwrap()
    );

    let app = build_router(test_state(pool, cfg));

    let list_req = Request::builder()
        .method(Method::GET)
        .uri("/audit-logs")
        .header(header::COOKIE, &auditor_cookie)
        .body(Body::empty())
        .unwrap();
    let list_resp = app.clone().oneshot(list_req).await.unwrap();
    assert_eq!(list_resp.status(), StatusCode::OK);
    let list_body = String::from_utf8(
        to_bytes(list_resp.into_body(), 1024 * 128)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(list_body.contains("Test User (audit-actor@example.com)"));
    assert!(list_body.contains(&format!("/audit-logs/{update_log_id}")));

    let drawer_req = Request::builder()
        .method(Method::GET)
        .uri(format!("/audit-logs/{update_log_id}"))
        .header(header::COOKIE, &auditor_cookie)
        .body(Body::empty())
        .unwrap();
    let drawer_resp = app.clone().oneshot(drawer_req).await.unwrap();
    assert_eq!(drawer_resp.status(), StatusCode::OK);
    let drawer_body = String::from_utf8(
        to_bytes(drawer_resp.into_body(), 1024 * 64)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(drawer_body.contains("Test User (audit-actor@example.com)"));
    assert!(drawer_body.contains("Alt-System"));
    assert!(drawer_body.contains("Neu-System"));

    for forbidden_cookie in [&emp_cookie, &owner_cookie] {
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/audit-logs/{update_log_id}"))
            .header(header::COOKIE, forbidden_cookie.as_str())
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
