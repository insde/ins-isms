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
            path: PathBuf::from("./target/test-blobs-risks"),
        },
        max_upload_bytes: 2 * 1024 * 1024,
        typst_bin_path: PathBuf::from("typst"),
        typst_font_paths: None,
        pdf_template_dir: None,
        seed_starter_content: true,
        seed_dir: PathBuf::from("seeds/example_pack"),
        smtp: None,
        rust_log: "warn".to_string(),
    })
}

fn test_state(pool: PgPool, config: Arc<Config>) -> AppState {
    AppState {
        pool,
        config,
        storage: Arc::new(LocalBlobStorage::new(PathBuf::from(
            "./target/test-blobs-risks",
        ))),
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

fn get_req(uri: &str, cookie: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn score_c3_c4_impact_hint_and_control_linking_audit(pool: PgPool) {
    let cfg = test_config();
    seed_initial_data(&pool, &cfg).await.unwrap();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let (_iso_id, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "iso-r1@example.com", Role::Iso, None).await;

    let c3_level_id: Uuid =
        sqlx::query_scalar("SELECT id FROM classification_levels WHERE code = 'C3'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let c4_level_id: Uuid =
        sqlx::query_scalar("SELECT id FROM classification_levels WHERE code = 'C4'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let ia_c3_id: Uuid = sqlx::query_scalar(
        "INSERT INTO information_assets (name, classification_level_id) VALUES ('Kundendatenbank', $1) RETURNING id",
    )
    .bind(c3_level_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let ia_c4_id: Uuid = sqlx::query_scalar(
        "INSERT INTO information_assets (name, classification_level_id) VALUES ('Signaturschlüssel', $1) RETURNING id",
    )
    .bind(c4_level_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    let sys_id: Uuid = sqlx::query_scalar(
        "INSERT INTO system_assets (asset_code, name, asset_type, criticality) VALUES ('SYS-HSM', 'HSM-Cluster', 'server', 'critical') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO information_asset_systems (information_asset_id, system_asset_id) VALUES ($1, $2)")
        .bind(ia_c4_id)
        .bind(sys_id)
        .execute(&pool)
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(get_req(
            &format!("/risks/impact-hint?affected_information_asset_id={ia_c3_id}"),
            &iso_cookie,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("mindestens 4"));

    let resp = app
        .clone()
        .oneshot(get_req(
            &format!("/risks/impact-hint?affected_system_asset_id={sys_id}"),
            &iso_cookie,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("C4"));
    assert!(body.contains("mindestens"));
    assert!(body.contains('5'));

    let create_body = format!(
        "reference_code=RSK-101&title=Ransomware+Dateiserver&threat_description=Verschl%C3%BCsselung&affected_information_asset_id={ia_c3_id}&inherent_likelihood=4&inherent_impact=4&residual_likelihood=2&residual_impact=4&treatment_strategy=mitigate&status=treating"
    );
    let resp = app
        .clone()
        .oneshot(post_form("/risks", &iso_cookie, &iso_csrf, create_body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let risk_id: Uuid =
        sqlx::query_scalar("SELECT id FROM risk_scenarios WHERE reference_code = 'RSK-101'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let soa_id: Uuid = sqlx::query_scalar("SELECT id FROM soa_entries LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(post_form(
            &format!("/risks/{risk_id}/controls"),
            &iso_cookie,
            &iso_csrf,
            format!("soa_entry_id={soa_id}"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let linked_audit: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE action = 'risk_control_links.linked' AND entity_id = $1",
    )
    .bind(risk_id.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(linked_audit, 1);

    let resp = app
        .clone()
        .oneshot(post_form(
            &format!("/risks/{risk_id}/controls/{soa_id}/unlink"),
            &iso_cookie,
            &iso_csrf,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let unlinked_audit: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE action = 'risk_control_links.unlinked' AND entity_id = $1",
    )
    .bind(risk_id.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(unlinked_audit, 1);

    let resp = app
        .clone()
        .oneshot(get_req(
            "/risks?mode=residual&likelihood=2&impact=4",
            &iso_cookie,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let html = String::from_utf8(
        to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("RSK-101"));

    let resp = app
        .oneshot(get_req("/risks/export.csv", &iso_cookie))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let csv = String::from_utf8(
        to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(csv.contains("RSK-101;Ransomware Dateiserver"));
}

#[sqlx::test(migrations = "./migrations")]
async fn acceptance_guard_and_automatic_reset_on_residual_increase(pool: PgPool) {
    let cfg = test_config();
    seed_initial_data(&pool, &cfg).await.unwrap();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let (iso_id, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "iso-r2@example.com", Role::Iso, None).await;

    let resp = app
        .clone()
        .oneshot(post_form(
            "/risks",
            &iso_cookie,
            &iso_csrf,
            "reference_code=RSK-201&title=Legacy+Server&threat_description=Ausfall&inherent_likelihood=4&inherent_impact=4&residual_likelihood=3&residual_impact=4&treatment_strategy=accept&status=accepted&acceptance_justification=   ".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let resp = app
        .clone()
        .oneshot(post_form(
            "/risks",
            &iso_cookie,
            &iso_csrf,
            "reference_code=RSK-201&title=Legacy+Server&threat_description=Ausfall&inherent_likelihood=4&inherent_impact=4&residual_likelihood=3&residual_impact=4&treatment_strategy=accept&status=assessed&acceptance_justification=Abl%C3%B6sung+f%C3%BCr+Q3+geplant".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let risk_id: Uuid =
        sqlx::query_scalar("SELECT id FROM risk_scenarios WHERE reference_code = 'RSK-201'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let resp = app
        .clone()
        .oneshot(post_form(
            &format!("/risks/{risk_id}"),
            &iso_cookie,
            &iso_csrf,
            "reference_code=RSK-201&title=Legacy+Server&threat_description=Ausfall&inherent_likelihood=4&inherent_impact=4&residual_likelihood=3&residual_impact=4&treatment_strategy=accept&status=accepted&acceptance_justification=Abl%C3%B6sung+f%C3%BCr+Q3+geplant".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let row = sqlx::query(
        "SELECT status, accepted_by_user_id, accepted_at FROM risk_scenarios WHERE id = $1",
    )
    .bind(risk_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("status"), "accepted");
    assert_eq!(
        row.get::<Option<Uuid>, _>("accepted_by_user_id"),
        Some(iso_id)
    );
    assert!(
        row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("accepted_at")
            .is_some()
    );

    let accepted_audit: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE action = 'risk_scenarios.accepted' AND entity_id = $1",
    )
    .bind(risk_id.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(accepted_audit, 1);

    let resp = app
        .oneshot(post_form(
            &format!("/risks/{risk_id}"),
            &iso_cookie,
            &iso_csrf,
            "reference_code=RSK-201&title=Legacy+Server&threat_description=Ausfall&inherent_likelihood=4&inherent_impact=4&residual_likelihood=4&residual_impact=4&treatment_strategy=accept&status=accepted&acceptance_justification=Abl%C3%B6sung+f%C3%BCr+Q3+geplant".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let after = sqlx::query(
        "SELECT status, accepted_by_user_id, accepted_at FROM risk_scenarios WHERE id = $1",
    )
    .bind(risk_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after.get::<String, _>("status"), "assessed");
    assert_eq!(after.get::<Option<Uuid>, _>("accepted_by_user_id"), None);
    assert!(
        after
            .get::<Option<chrono::DateTime<chrono::Utc>>, _>("accepted_at")
            .is_none()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn rbac_owner_scope_elevated_acceptance_and_auditor_readonly(pool: PgPool) {
    let cfg = test_config();
    seed_initial_data(&pool, &cfg).await.unwrap();
    let app = build_router(test_state(pool.clone(), cfg.clone()));

    let unit_a: Uuid = sqlx::query_scalar(
        "INSERT INTO organization_units (name) VALUES ('IT-Betrieb') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let unit_b: Uuid = sqlx::query_scalar(
        "INSERT INTO organization_units (name) VALUES ('Vertrieb') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    let (_owner_id, owner_cookie, owner_csrf) = create_user_with_session(
        &pool,
        &cfg,
        "owner-r3@example.com",
        Role::Owner,
        Some(unit_a),
    )
    .await;
    let (_auditor_id, auditor_cookie, auditor_csrf) =
        create_user_with_session(&pool, &cfg, "auditor-r3@example.com", Role::Auditor, None).await;

    let resp = app
        .clone()
        .oneshot(post_form(
            "/risks",
            &owner_cookie,
            &owner_csrf,
            format!(
                "reference_code=RSK-301&title=Hohes+Risiko&threat_description=Test&owner_unit_id={unit_a}&inherent_likelihood=4&inherent_impact=4&residual_likelihood=3&residual_impact=4&treatment_strategy=accept&status=accepted&acceptance_justification=Test"
            ),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = app
        .clone()
        .oneshot(post_form(
            "/risks",
            &owner_cookie,
            &owner_csrf,
            format!(
                "reference_code=RSK-302&title=Unit+A+Risiko&threat_description=Test&owner_unit_id={unit_a}&inherent_likelihood=3&inherent_impact=3&residual_likelihood=2&residual_impact=2&treatment_strategy=mitigate&status=treating"
            ),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let unit_b_risk_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO risk_scenarios (
            reference_code, title, threat_description, owner_unit_id,
            inherent_likelihood, inherent_impact, residual_likelihood, residual_impact
        )
        VALUES ('RSK-303', 'Unit B Risiko', 'Test', $1, 2, 2, 2, 2)
        RETURNING id
        "#,
    )
    .bind(unit_b)
    .fetch_one(&pool)
    .await
    .unwrap();

    let resp = app
        .clone()
        .oneshot(post_form(
            &format!("/risks/{unit_b_risk_id}"),
            &owner_cookie,
            &owner_csrf,
            format!(
                "reference_code=RSK-303&title=Unit+B+Ge%C3%A4ndert&threat_description=Test&owner_unit_id={unit_b}&inherent_likelihood=2&inherent_impact=2&residual_likelihood=2&residual_impact=2&treatment_strategy=mitigate&status=assessed"
            ),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let resp = app
        .clone()
        .oneshot(get_req("/risks", &auditor_cookie))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app
        .oneshot(post_form(
            "/risks",
            &auditor_cookie,
            &auditor_csrf,
            "reference_code=RSK-304&title=Auditor+Test&threat_description=Test&inherent_likelihood=2&inherent_impact=2&residual_likelihood=2&residual_impact=2&treatment_strategy=mitigate&status=identified".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
