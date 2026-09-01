use std::{net::SocketAddr, sync::Arc};

use dotenvy::dotenv;
use metrics_exporter_prometheus::PrometheusBuilder;
use sqlx::postgres::PgPoolOptions;
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use axum_template::{
    config::AppConfig, create_app, services::realtime::RealtimeService, state::AppState,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    init_tracing();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "Starting Axum application"
    );

    let prometheus_handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("Failed to install Prometheus metrics recorder");

    let config = AppConfig::load_from_env().inspect_err(|e| {
        tracing::error!("Configuration validation failed: {e}");
    })?;
    config.log_summary();

    let pool = PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(config.database_url.expose())
        .await
        .inspect_err(|e| tracing::error!("Failed to connect to PostgreSQL: {e}"))?;

    tracing::info!("Database connection pool established");

    // Migrations run here, before the listener binds. Nothing previously ran
    // them at all: the `migrate` feature was enabled and the Dockerfile shipped
    // the directory, but a fresh deployment came up against an empty schema and
    // failed on the first query. Failing to migrate must prevent serving.
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .inspect_err(|e| tracing::error!("Database migration failed: {e}"))?;
    tracing::info!("Database migrations applied");

    let app_state = Arc::new(AppState::new(pool, config.clone(), prometheus_handle));

    // Bridge Postgres NOTIFY onto this replica's local broadcast channel, so SSE
    // clients receive events published by any replica.
    tokio::spawn(RealtimeService::run_listener(
        config.database_url.expose().to_string(),
        app_state.realtime_tx.clone(),
    ));

    // Reap expired idempotency keys, recovery tokens, and dead sessions.
    tokio::spawn(cleanup_loop(app_state.clone()));

    let app = create_app(app_state);

    let addr: SocketAddr = format!("{}:{}", config.server_host, config.server_port)
        .parse()
        .expect("Invalid address format");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Server listening on http://{addr}");
    tracing::info!("API documentation at http://{addr}/docs");
    tracing::info!(
        "Metrics at http://{addr}/metrics{}",
        if config.metrics_token.is_some() {
            " (token required)"
        } else {
            ""
        }
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    tracing::info!("Server shutdown completed gracefully");
    Ok(())
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "axum_template=info,tower_http=info".into());

    let registry = tracing_subscriber::registry().with(filter);

    // Structured JSON in production so logs are queryable; human-readable
    // locally.
    if std::env::var("APP_ENV").as_deref() == Ok("production") {
        registry
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        registry.with(tracing_subscriber::fmt::layer()).init();
    }
}

/// Bounded growth for the tables that would otherwise accumulate forever.
async fn cleanup_loop(state: Arc<AppState>) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
    ticker.tick().await; // fire immediately, then hourly

    loop {
        ticker.tick().await;

        let statements = [
            (
                "idempotency_keys",
                "DELETE FROM idempotency_keys WHERE expires_at <= now()",
            ),
            (
                "verifications",
                "DELETE FROM verifications WHERE expires_at <= now() - interval '7 days'",
            ),
            (
                "oauth_auth_requests",
                "DELETE FROM oauth_auth_requests WHERE expires_at <= now()",
            ),
            (
                "sessions",
                "DELETE FROM sessions WHERE expires_at <= now() - interval '30 days'",
            ),
        ];

        for (table, sql) in statements {
            match sqlx::query(sql).execute(&state.db).await {
                Ok(result) if result.rows_affected() > 0 => {
                    tracing::debug!(table, rows = result.rows_affected(), "Reaped expired rows");
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(table, error = %e, "Cleanup query failed"),
            }
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("Received Ctrl+C; shutting down"),
        _ = terminate => tracing::info!("Received SIGTERM; shutting down"),
    }
}
