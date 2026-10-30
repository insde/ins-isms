use std::{net::SocketAddr, sync::Arc};

use tokio::net::TcpListener;
use tracing_subscriber::{EnvFilter, fmt};

use ins_isms::{
    build_router,
    config::Config,
    db::{create_pool, run_migrations},
    scheduler::spawn_scheduler,
    seed::seed_initial_data,
    state::AppState,
    storage::{BlobStorage, build_storage},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    let config = Arc::new(Config::from_env()?);

    let filter = EnvFilter::try_new(&config.rust_log).unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();

    run_migrations(&config.migration_database_url).await?;
    let pool = create_pool(&config.database_url).await?;
    seed_initial_data(&pool, &config).await?;

    let storage: Arc<dyn BlobStorage> = Arc::from(build_storage(&config.storage));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let scheduler_handle = spawn_scheduler(pool.clone(), Arc::clone(&config), shutdown_rx);

    let state = AppState {
        pool,
        config: Arc::clone(&config),
        storage,
    };

    let app = build_router(state);

    let listener = TcpListener::bind(config.bind_addr).await?;
    tracing::info!(addr = %config.bind_addr, "ins-isms Server gestartet");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    })
    .await?;

    let _ = scheduler_handle.await;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
