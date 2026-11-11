use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    body::{Body, to_bytes},
    http::{HeaderValue, Method, Request, StatusCode, header},
};
use chrono::{DateTime, Duration, Utc};
use chrono_tz::Europe::Berlin;
use ins_isms::{
    auth::{
        password::hash_password,
        rbac::Role,
        session::{create_session, sign_session_id},
    },
    build_router,
    config::{AppEnv, Config, StorageBackendConfig},
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
            path: PathBuf::from("./target/test-blobs-incidents"),
        },
        max_upload_bytes: 2 * 1024 * 1024,
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
        storage: Arc::new(LocalBlobStorage::new(PathBuf::from(
            "./target/test-blobs-incidents",
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
async fn nis2_deadlines_calculated_for_24h_72h_and_30d(pool: PgPool) {
    let cfg = test_config();
    let (_, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "iso-inc@example.com", Role::Iso, None).await;
    let app = build_router(test_state(pool.clone(), cfg));

    let resp = app
        .clone()
        .oneshot(post_form(
            "/incidents",
            &iso_cookie,
            &iso_csrf,
            "reference_code=INC-NIS2-01&title=Ransomware-Verdacht&description=Ungewoehnliche+Dateiverschluesselung&severity=critical&detected_at=2026-11-21T10%3A00%3A00Z&is_nis2_significant=1".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let row = sqlx::query(
        r#"
        SELECT id, detected_at, early_warning_due_at, incident_report_due_at, final_report_due_at
        FROM security_incidents
        WHERE reference_code = 'INC-NIS2-01'
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    let inc_id: Uuid = row.try_get("id").unwrap();
    let detected_at: DateTime<Utc> = row.try_get("detected_at").unwrap();
    let early_due: DateTime<Utc> = row.try_get("early_warning_due_at").unwrap();
    let report_due: DateTime<Utc> = row.try_get("incident_report_due_at").unwrap();
    let final_due: Option<DateTime<Utc>> = row.try_get("final_report_due_at").unwrap();

    assert_eq!(early_due, detected_at + Duration::hours(24));
    assert_eq!(report_due, detected_at + Duration::hours(72));
    assert!(final_due.is_none());

    let submit_resp = app
        .clone()
        .oneshot(post_form(
            &format!("/incidents/{inc_id}/nis2/submit"),
            &iso_cookie,
            &iso_csrf,
            "stage=incident_report&bsi_ticket_reference=BSI-2026-999".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(submit_resp.status(), StatusCode::OK);

    let updated = sqlx::query(
        r#"
        SELECT incident_report_submitted_at, final_report_due_at, bsi_ticket_reference
        FROM security_incidents
        WHERE id = $1
        "#,
    )
    .bind(inc_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    let report_sub: DateTime<Utc> = updated.try_get("incident_report_submitted_at").unwrap();
    let final_due_after: DateTime<Utc> = updated.try_get("final_report_due_at").unwrap();
    let ticket: String = updated.try_get("bsi_ticket_reference").unwrap();

    assert_eq!(final_due_after, report_sub + Duration::days(30));
    assert_eq!(ticket, "BSI-2026-999");

    let reset_resp = app
        .oneshot(post_form(
            &format!("/incidents/{inc_id}"),
            &iso_cookie,
            &iso_csrf,
            "title=Ransomware-Verdacht&description=Entwarnung&severity=low&status=analyzing"
                .to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(reset_resp.status(), StatusCode::OK);

    let after_reset = sqlx::query(
        "SELECT early_warning_due_at, final_report_due_at FROM security_incidents WHERE id = $1",
    )
    .bind(inc_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        after_reset
            .try_get::<Option<DateTime<Utc>>, _>("early_warning_due_at")
            .unwrap()
            .is_none()
    );
    assert!(
        after_reset
            .try_get::<Option<DateTime<Utc>>, _>("final_report_due_at")
            .unwrap()
            .is_none()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn closure_guard_requires_rca_and_lessons_and_logs_audit(pool: PgPool) {
    let cfg = test_config();
    let (_, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "iso-close@example.com", Role::Iso, None).await;
    let app = build_router(test_state(pool.clone(), cfg));

    let resp = app
        .clone()
        .oneshot(post_form(
            "/incidents",
            &iso_cookie,
            &iso_csrf,
            "reference_code=INC-CLS-01&title=Phishing-Klick&description=Mitarbeiter+hat+Link+geoeffnet&severity=medium".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let inc_id: Uuid =
        sqlx::query_scalar("SELECT id FROM security_incidents WHERE reference_code = 'INC-CLS-01'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let fail_resp = app
        .clone()
        .oneshot(post_form(
            &format!("/incidents/{inc_id}"),
            &iso_cookie,
            &iso_csrf,
            "title=Phishing-Klick&description=Mitarbeiter+hat+Link+geoeffnet&severity=medium&status=closed&root_cause_analysis=Fehlender+Filter&lessons_learned=".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(fail_resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let ok_resp = app
        .clone()
        .oneshot(post_form(
            &format!("/incidents/{inc_id}"),
            &iso_cookie,
            &iso_csrf,
            "title=Phishing-Klick&description=Mitarbeiter+hat+Link+geoeffnet&severity=medium&status=closed&root_cause_analysis=Fehlender+Filter&lessons_learned=SPF+und+MFA+nachgeschaerft".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(ok_resp.status(), StatusCode::OK);

    let row = sqlx::query("SELECT status, resolved_at FROM security_incidents WHERE id = $1")
        .bind(inc_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(row.try_get::<String, _>("status").unwrap(), "closed");
    assert!(
        row.try_get::<Option<DateTime<Utc>>, _>("resolved_at")
            .unwrap()
            .is_some()
    );

    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE entity_type = 'security_incidents' AND entity_id = $1",
    )
    .bind(inc_id.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(audit_count >= 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn timeline_events_are_recorded_and_audited(pool: PgPool) {
    let cfg = test_config();
    let (_, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "iso-tl@example.com", Role::Iso, None).await;
    let app = build_router(test_state(pool.clone(), cfg));

    let resp = app
        .clone()
        .oneshot(post_form(
            "/incidents",
            &iso_cookie,
            &iso_csrf,
            "reference_code=INC-TL-01&title=VPN-Stoerung&description=Verbindungsabbrueche&severity=low".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let inc_id: Uuid =
        sqlx::query_scalar("SELECT id FROM security_incidents WHERE reference_code = 'INC-TL-01'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let tl_resp = app
        .oneshot(post_form(
            &format!("/incidents/{inc_id}/timeline"),
            &iso_cookie,
            &iso_csrf,
            "note=Firewall-Logs+gesichert+und+ausgewertet".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(tl_resp.status(), StatusCode::OK);
    let body = String::from_utf8(
        to_bytes(tl_resp.into_body(), 1024 * 64)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("Firewall-Logs gesichert und ausgewertet"));

    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE entity_type = 'incident_timeline_events' AND action = 'incident_timeline_events.created'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(audit_count >= 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn incidents_rbac_enforces_employee_owner_and_auditor_boundaries(pool: PgPool) {
    let cfg = test_config();

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

    let (emp_id, emp_cookie, emp_csrf) = create_user_with_session(
        &pool,
        &cfg,
        "emp-inc@example.com",
        Role::Employee,
        Some(unit_a),
    )
    .await;
    let (_, owner_a_cookie, owner_a_csrf) = create_user_with_session(
        &pool,
        &cfg,
        "owner-a@example.com",
        Role::Owner,
        Some(unit_a),
    )
    .await;
    let (_, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "iso-rbac@example.com", Role::Iso, None).await;
    let (_, aud_cookie, aud_csrf) =
        create_user_with_session(&pool, &cfg, "aud-rbac@example.com", Role::Auditor, None).await;

    let app = build_router(test_state(pool.clone(), cfg));

    let emp_report_resp = app
        .clone()
        .oneshot(post_form(
            "/incidents/report",
            &emp_cookie,
            &emp_csrf,
            "title=Laptop+verloren&description=Im+ICE+vergessen&severity=high".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(emp_report_resp.status(), StatusCode::OK);

    let emp_inc_id: Uuid =
        sqlx::query_scalar("SELECT id FROM security_incidents WHERE reported_by_user_id = $1")
            .bind(emp_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    let emp_own_get = app
        .clone()
        .oneshot(get_req(&format!("/incidents/{emp_inc_id}"), &emp_cookie))
        .await
        .unwrap();
    assert_eq!(emp_own_get.status(), StatusCode::OK);

    let iso_create = app
        .clone()
        .oneshot(post_form(
            "/incidents",
            &iso_cookie,
            &iso_csrf,
            format!(
                "reference_code=INC-UNITB-01&title=Vertrieb-Vorfall&description=CRM+Stoerung&severity=medium&owner_unit_id={unit_b}"
            ),
        ))
        .await
        .unwrap();
    assert_eq!(iso_create.status(), StatusCode::OK);

    let unit_b_inc_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM security_incidents WHERE reference_code = 'INC-UNITB-01'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    let emp_other_get = app
        .clone()
        .oneshot(get_req(&format!("/incidents/{unit_b_inc_id}"), &emp_cookie))
        .await
        .unwrap();
    assert_eq!(emp_other_get.status(), StatusCode::FORBIDDEN);

    let owner_other_get = app
        .clone()
        .oneshot(get_req(
            &format!("/incidents/{unit_b_inc_id}"),
            &owner_a_cookie,
        ))
        .await
        .unwrap();
    assert_eq!(owner_other_get.status(), StatusCode::FORBIDDEN);

    let owner_tl = app
        .clone()
        .oneshot(post_form(
            &format!("/incidents/{emp_inc_id}/timeline"),
            &owner_a_cookie,
            &owner_a_csrf,
            "note=Geraet+ueber+MDM+gesperrt".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(owner_tl.status(), StatusCode::OK);

    let owner_close = app
        .clone()
        .oneshot(post_form(
            &format!("/incidents/{emp_inc_id}"),
            &owner_a_cookie,
            &owner_a_csrf,
            "title=Laptop+verloren&description=Im+ICE+vergessen&severity=high&status=closed&root_cause_analysis=A&lessons_learned=B".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(owner_close.status(), StatusCode::FORBIDDEN);

    let owner_bsi = app
        .clone()
        .oneshot(post_form(
            &format!("/incidents/{emp_inc_id}/nis2/submit"),
            &owner_a_cookie,
            &owner_a_csrf,
            "stage=early_warning".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(owner_bsi.status(), StatusCode::FORBIDDEN);

    let aud_list = app
        .clone()
        .oneshot(get_req("/incidents", &aud_cookie))
        .await
        .unwrap();
    assert_eq!(aud_list.status(), StatusCode::OK);

    let aud_detail = app
        .clone()
        .oneshot(get_req(&format!("/incidents/{unit_b_inc_id}"), &aud_cookie))
        .await
        .unwrap();
    assert_eq!(aud_detail.status(), StatusCode::OK);

    let aud_post_tl = app
        .clone()
        .oneshot(post_form(
            &format!("/incidents/{unit_b_inc_id}/timeline"),
            &aud_cookie,
            &aud_csrf,
            "note=Auditor+Versuch".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(aud_post_tl.status(), StatusCode::FORBIDDEN);

    let aud_report = app
        .oneshot(post_form(
            "/incidents/report",
            &aud_cookie,
            &aud_csrf,
            "title=Test&description=Test".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(aud_report.status(), StatusCode::FORBIDDEN);
}
