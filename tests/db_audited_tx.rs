use std::net::{IpAddr, Ipv4Addr};

use sqlx::PgPool;
use uuid::Uuid;

use ins_isms::db::begin_audited_tx;

#[sqlx::test(migrations = "./migrations")]
async fn begin_audited_tx_sets_local_actor_context_without_leaking(pool: PgPool) {
    let actor_id = Uuid::new_v4();
    let actor_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42));

    let mut tx = begin_audited_tx(&pool, Some(actor_id), Some(actor_ip))
        .await
        .expect("begin audited tx");

    let (got_id, got_ip): (String, String) = sqlx::query_as(
        "SELECT current_setting('app.current_actor_id', true), current_setting('app.current_actor_ip', true)",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("read local settings");

    assert_eq!(got_id, actor_id.to_string());
    assert_eq!(got_ip, "192.0.2.42");

    let pgcrypto_len: i32 =
        sqlx::query_scalar("SELECT length(encode(digest('ins-isms', 'sha256'), 'hex'))::int")
            .fetch_one(&mut *tx)
            .await
            .expect("pgcrypto digest works");
    assert_eq!(pgcrypto_len, 64);

    tx.commit().await.expect("commit tx");

    let (after_id, after_ip): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT NULLIF(current_setting('app.current_actor_id', true), ''), NULLIF(current_setting('app.current_actor_ip', true), '')",
    )
    .fetch_one(&pool)
    .await
    .expect("read settings after commit");

    assert!(after_id.is_none());
    assert!(after_ip.is_none());
}
