use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    body::{Body, to_bytes},
    http::{HeaderValue, Method, Request, StatusCode, header},
};
use chrono::{Duration, NaiveDate, Utc};
use chrono_tz::Europe::Berlin;
use ins_isms::{
    auth::{
        password::hash_password,
        rbac::Role,
        session::{create_session, sign_session_id},
    },
    build_router,
    config::{AppEnv, Config, StorageBackendConfig},
    db::begin_audited_tx,
    domain::actions::generate_next_recurrence_tx,
    mailer::Mailer,
    scheduler::{
        check_nis2_alerts, cleanup_expired_sessions_and_attempts, run_daily_action_maintenance,
    },
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
            path: PathBuf::from("./target/test-blobs-actions"),
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
            "./target/test-blobs-actions",
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
async fn iso102_effectiveness_guard_and_unlocks_audit_finding(pool: PgPool) {
    let cfg = test_config();
    let unit_id: Uuid =
        sqlx::query_scalar("INSERT INTO organization_units (name) VALUES ('IT') RETURNING id")
            .fetch_one(&pool)
            .await
            .unwrap();

    let (iso_id, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "iso@example.com", Role::Iso, Some(unit_id)).await;
    let (_, owner_cookie, owner_csrf) =
        create_user_with_session(&pool, &cfg, "owner@example.com", Role::Owner, Some(unit_id))
            .await;

    let app = build_router(test_state(pool.clone(), cfg));

    let audit_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO internal_audits (audit_code, title, scope, auditor_name, audit_date, status)
        VALUES ('AUD-ACT-1', 'Audit 2026', 'ISMS', 'Auditor', '2026-11-15', 'in_progress')
        RETURNING id
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    let finding_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO audit_findings (audit_id, finding_code, finding_type, owner_unit_id, description, status)
        VALUES ($1, 'FND-01', 'major_nc', $2, 'Fehlender Restore-Test', 'open')
        RETURNING id
        "#,
    )
    .bind(audit_id)
    .bind(unit_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    let capa_res = app
        .clone()
        .oneshot(post_form(
            &format!("/audits/{audit_id}/findings/{finding_id}/capa"),
            &iso_cookie,
            &iso_csrf,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(capa_res.status(), StatusCode::OK);

    let finding_status: String =
        sqlx::query_scalar("SELECT status FROM audit_findings WHERE id = $1")
            .bind(finding_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(finding_status, "action_planned");

    let action_id: Uuid =
        sqlx::query_scalar("SELECT id FROM action_items WHERE linked_audit_finding_id = $1")
            .bind(finding_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    let owner_done = app
        .clone()
        .oneshot(post_form(
            &format!("/actions/{action_id}/status"),
            &owner_cookie,
            &owner_csrf,
            "status=done&verification_note=Selbst+geprueft".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(owner_done.status(), StatusCode::FORBIDDEN);

    let owner_review = app
        .clone()
        .oneshot(post_form(
            &format!("/actions/{action_id}/status"),
            &owner_cookie,
            &owner_csrf,
            "status=review".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(owner_review.status(), StatusCode::OK);

    let close_blocked = app
        .clone()
        .oneshot(post_form(
            &format!("/audits/findings/{finding_id}/status"),
            &iso_cookie,
            &iso_csrf,
            "status=verified_closed".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(close_blocked.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let iso_no_note = app
        .clone()
        .oneshot(post_form(
            &format!("/actions/{action_id}/status"),
            &iso_cookie,
            &iso_csrf,
            "status=done&verification_note=   ".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(iso_no_note.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let iso_done = app
        .clone()
        .oneshot(post_form(
            &format!("/actions/{action_id}/status"),
            &iso_cookie,
            &iso_csrf,
            "status=done&verification_note=Restore-Protokoll+geprueft".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(iso_done.status(), StatusCode::OK);

    let verified_by: Option<Uuid> =
        sqlx::query_scalar("SELECT verified_by_user_id FROM action_items WHERE id = $1")
            .bind(action_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(verified_by, Some(iso_id));

    let close_ok = app
        .oneshot(post_form(
            &format!("/audits/findings/{finding_id}/status"),
            &iso_cookie,
            &iso_csrf,
            "status=verified_closed".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(close_ok.status(), StatusCode::OK);
}

#[sqlx::test(migrations = "./migrations")]
async fn recurrence_generation_on_done_and_scheduler(pool: PgPool) {
    let cfg = test_config();
    let (_, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "iso-rec@example.com", Role::Iso, None).await;
    let app = build_router(test_state(pool.clone(), cfg));

    let create_res = app
        .clone()
        .oneshot(post_form(
            "/actions",
            &iso_cookie,
            &iso_csrf,
            "reference_code=ACT-REC-1&title=Quartalsweiser+Backup-Test&source_type=recurring_compliance&priority=high&due_date=2026-01-15&recurrence_interval=quarterly".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(create_res.status(), StatusCode::OK);

    let parent_id: Uuid =
        sqlx::query_scalar("SELECT id FROM action_items WHERE reference_code = 'ACT-REC-1'")
            .fetch_one(&pool)
            .await
            .unwrap();

    let done_res = app
        .oneshot(post_form(
            &format!("/actions/{parent_id}/status"),
            &iso_cookie,
            &iso_csrf,
            "status=done".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(done_res.status(), StatusCode::OK);

    let parent_flag: bool =
        sqlx::query_scalar("SELECT recurrence_next_generated FROM action_items WHERE id = $1")
            .bind(parent_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(parent_flag);

    let child_row = sqlx::query(
        "SELECT status, due_date, recurrence_parent_id, recurrence_next_generated FROM action_items WHERE recurrence_parent_id = $1",
    )
    .bind(parent_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(child_row.get::<String, _>("status"), "open");
    assert_eq!(
        child_row.get::<NaiveDate, _>("due_date"),
        NaiveDate::from_ymd_opt(2026, 4, 15).unwrap()
    );
    assert!(!child_row.get::<bool, _>("recurrence_next_generated"));

    let mut tx = begin_audited_tx(&pool, None, None).await.unwrap();
    let dup = generate_next_recurrence_tx(&mut tx, parent_id)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(dup.is_none());

    let overdue_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO action_items (
            reference_code, title, source_type, priority, status, due_date, recurrence_interval
        )
        VALUES ('ACT-REC-SCHED', 'Monatlicher Patch-Check', 'recurring_compliance', 'medium', 'open', CURRENT_DATE - 3, 'monthly')
        RETURNING id
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    let mailer = Mailer::new(None);
    let sum1 = run_daily_action_maintenance(&pool, &mailer).await.unwrap();
    assert_eq!(sum1.recurrences_generated, 2); // child_row (2026-04-15 < CURRENT_DATE 2026-11-21) + overdue_id
    assert_eq!(sum1.digest_emails_sent, 0);

    let sum2 = run_daily_action_maintenance(&pool, &mailer).await.unwrap();

    let overdue_children: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM action_items WHERE recurrence_parent_id = $1")
            .bind(overdue_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(overdue_children, 1);
    let _ = sum2;
}

#[sqlx::test(migrations = "./migrations")]
async fn one_click_capa_from_incident_creates_action_and_audit_log(pool: PgPool) {
    let cfg = test_config();
    let (_, iso_cookie, iso_csrf) =
        create_user_with_session(&pool, &cfg, "iso-inc@example.com", Role::Iso, None).await;
    let app = build_router(test_state(pool.clone(), cfg));

    let inc_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO security_incidents (reference_code, title, description, severity, status)
        VALUES ('INC-CAPA-1', 'Ransomware-Verdacht', 'Isoliert', 'critical', 'contained')
        RETURNING id
        "#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    let res = app
        .oneshot(post_form(
            &format!("/incidents/{inc_id}/capa"),
            &iso_cookie,
            &iso_csrf,
            String::new(),
        ))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let row = sqlx::query(
        "SELECT id, source_type, priority FROM action_items WHERE linked_incident_id = $1",
    )
    .bind(inc_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("source_type"), "incident_capa");
    assert_eq!(row.get::<String, _>("priority"), "critical");
    let action_id: Uuid = row.get("id");

    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE entity_type = 'action_items' AND entity_id = $1 AND action = 'action_items.created'",
    )
    .bind(action_id.to_string())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit_count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn scheduler_nis2_deduplication_and_noop_mailer(pool: PgPool) {
    let cfg = test_config();
    let _ = create_user_with_session(&pool, &cfg, "iso-nis2@example.com", Role::Iso, None).await;

    let due_24h = Utc::now() + Duration::hours(2);
    let inc_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO security_incidents (
            reference_code, title, description, severity, status,
            is_nis2_significant, early_warning_due_at
        )
        VALUES ('INC-NIS2-AL', 'DDoS', 'Kurz vor 24h', 'high', 'analyzing', TRUE, $1)
        RETURNING id
        "#,
    )
    .bind(due_24h)
    .fetch_one(&pool)
    .await
    .unwrap();

    let mailer = Mailer::new(None);
    assert!(!mailer.is_enabled());

    let first = check_nis2_alerts(&pool, &mailer).await.unwrap();
    assert_eq!(first.alerts_24h_triggered, 1);
    assert_eq!(first.emails_sent, 0);

    let sent_at: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT nis2_alert_24h_sent_at FROM security_incidents WHERE id = $1")
            .bind(inc_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(sent_at.is_some());

    let second = check_nis2_alerts(&pool, &mailer).await.unwrap();
    assert_eq!(second.alerts_24h_triggered, 0);

    let (s_del, a_del) = cleanup_expired_sessions_and_attempts(&pool).await.unwrap();
    assert_eq!(s_del, 0);
    assert_eq!(a_del, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn actions_rbac_for_employee_owner_and_auditor(pool: PgPool) {
    let cfg = test_config();
    let unit_a: Uuid =
        sqlx::query_scalar("INSERT INTO organization_units (name) VALUES ('Unit A') RETURNING id")
            .fetch_one(&pool)
            .await
            .unwrap();
    let unit_b: Uuid =
        sqlx::query_scalar("INSERT INTO organization_units (name) VALUES ('Unit B') RETURNING id")
            .fetch_one(&pool)
            .await
            .unwrap();

    let (emp_id, emp_cookie, emp_csrf) =
        create_user_with_session(&pool, &cfg, "emp@example.com", Role::Employee, Some(unit_a))
            .await;
    let (_, owner_cookie, owner_csrf) =
        create_user_with_session(&pool, &cfg, "own@example.com", Role::Owner, Some(unit_a)).await;
    let (_, aud_cookie, aud_csrf) =
        create_user_with_session(&pool, &cfg, "aud@example.com", Role::Auditor, None).await;

    let app = build_router(test_state(pool.clone(), cfg));

    let emp_task_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO action_items (reference_code, title, assignee_user_id, owner_unit_id, priority, status)
        VALUES ('ACT-EMP-1', 'Eigene Mitarbeiter-Aufgabe', $1, $2, 'medium', 'open')
        RETURNING id
        "#,
    )
    .bind(emp_id)
    .bind(unit_a)
    .fetch_one(&pool)
    .await
    .unwrap();

    let other_unit_task_id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO action_items (reference_code, title, owner_unit_id, priority, status)
        VALUES ('ACT-UNIT-B', 'Fremde Unit-B-Aufgabe', $1, 'high', 'open')
        RETURNING id
        "#,
    )
    .bind(unit_b)
    .fetch_one(&pool)
    .await
    .unwrap();

    let emp_list = app
        .clone()
        .oneshot(get_req("/actions", &emp_cookie))
        .await
        .unwrap();
    assert_eq!(emp_list.status(), StatusCode::OK);
    let emp_body = String::from_utf8(
        to_bytes(emp_list.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(emp_body.contains("ACT-EMP-1"));
    assert!(!emp_body.contains("ACT-UNIT-B"));

    let emp_post = app
        .clone()
        .oneshot(post_form(
            &format!("/actions/{emp_task_id}/status"),
            &emp_cookie,
            &emp_csrf,
            "status=in_progress".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(emp_post.status(), StatusCode::FORBIDDEN);

    let own_drawer = app
        .clone()
        .oneshot(get_req(
            &format!("/actions/{other_unit_task_id}/drawer"),
            &owner_cookie,
        ))
        .await
        .unwrap();
    assert_eq!(own_drawer.status(), StatusCode::FORBIDDEN);

    let own_edit = app
        .clone()
        .oneshot(post_form(
            &format!("/actions/{emp_task_id}/status"),
            &owner_cookie,
            &owner_csrf,
            "status=in_progress".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(own_edit.status(), StatusCode::OK);

    let aud_list = app
        .clone()
        .oneshot(get_req("/actions", &aud_cookie))
        .await
        .unwrap();
    assert_eq!(aud_list.status(), StatusCode::OK);
    let aud_body = String::from_utf8(
        to_bytes(aud_list.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(aud_body.contains("ACT-EMP-1"));
    assert!(aud_body.contains("ACT-UNIT-B"));

    let aud_post = app
        .oneshot(post_form(
            "/actions",
            &aud_cookie,
            &aud_csrf,
            "title=Verboten&priority=medium".to_string(),
        ))
        .await
        .unwrap();
    assert_eq!(aud_post.status(), StatusCode::FORBIDDEN);
}
