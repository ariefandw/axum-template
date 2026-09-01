use std::sync::Arc;

use metrics_exporter_prometheus::PrometheusHandle;
use sqlx::PgPool;
use tokio::sync::broadcast;

use crate::{config::AppConfig, models::events::RealtimeEvent};

/// Postgres channel used to fan realtime events out across replicas.
///
/// The previous design published into a process-local `broadcast` channel, so a
/// client connected to replica B never saw an event raised on replica A. Events
/// now go out through `pg_notify`, and every replica's listener task re-publishes
/// onto its own local channel.
pub const REALTIME_CHANNEL: &str = "realtime_events";

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<AppConfig>,
    pub http_client: reqwest::Client,
    pub prometheus_handle: Arc<PrometheusHandle>,
    /// Local fan-out. Fed by the Postgres listener, never published to directly:
    /// use `RealtimeService::publish` so the event reaches every replica.
    pub realtime_tx: broadcast::Sender<RealtimeEvent>,
}

impl AppState {
    pub fn new(db: PgPool, config: AppConfig, prometheus_handle: PrometheusHandle) -> Self {
        let (realtime_tx, _) = broadcast::channel(1024);
        Self {
            db,
            config: Arc::new(config),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .user_agent(concat!("axum-template/", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("Failed to build reqwest client"),
            prometheus_handle: Arc::new(prometheus_handle),
            realtime_tx,
        }
    }
}
