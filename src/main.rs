use std::{net::SocketAddr, sync::Arc};
use dotenvy::dotenv;
use metrics_exporter_prometheus::PrometheusBuilder;
use sqlx::postgres::PgPoolOptions;
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use axum_template::{config::AppConfig, create_app, state::AppState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load environment variables
    dotenv().ok();

    // 2. Initialize structured JSON/Env tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "axum_template=debug,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Axum Application...");

    // 3. Initialize Prometheus Metrics Recorder
    let prometheus_handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("Failed to install Prometheus metrics recorder");

    // 4. Load & strictly validate configuration
    let config = AppConfig::load_from_env().map_err(|e| {
        tracing::error!("Configuration validation failed: {e}");
        e
    })?;

    // 5. Initialize Database Connection Pool
    let pool = PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(&config.database_url)
        .await
        .map_err(|e| {
            tracing::error!("Failed to connect to PostgreSQL: {e}");
            e
        })?;

    tracing::info!("Database connection pool established");

    // 6. Build Shared Application State & Router
    let app_state = Arc::new(AppState::new(pool, config.clone(), prometheus_handle));
    let app = create_app(app_state);

    // 7. Bind Listener
    let addr: SocketAddr = format!("{}:{}", config.server_host, config.server_port)
        .parse()
        .expect("Invalid address format");

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Server listening on http://{}", addr);
    tracing::info!("Scalar API documentation available at http://{}/docs", addr);
    tracing::info!("Prometheus metrics available at http://{}/metrics", addr);

    // 8. Serve with Graceful Shutdown
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    tracing::info!("Server shutdown completed gracefully.");
    Ok(())
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
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C signal. Initiating graceful shutdown...");
        },
        _ = terminate => {
            tracing::info!("Received SIGTERM signal. Initiating graceful shutdown...");
        },
    }
}
