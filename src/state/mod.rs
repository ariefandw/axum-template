use std::sync::Arc;

use metrics_exporter_prometheus::PrometheusHandle;
use sqlx::PgPool;
use tokio::sync::broadcast;

use crate::{
    config::{AppConfig, StorageBackendKind},
    models::events::RealtimeEvent,
    services::storage_backend::{LocalBackend, S3Backend, StorageBackend},
};

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
    /// Where object bytes live. Selected once at startup from configuration, so
    /// no request path branches on the backend.
    pub storage: Arc<dyn StorageBackend>,
}

impl AppState {
    pub fn new(db: PgPool, config: AppConfig, prometheus_handle: PrometheusHandle) -> Self {
        let (realtime_tx, _) = broadcast::channel(1024);

        let storage: Arc<dyn StorageBackend> = match (config.storage_backend, config.s3.as_ref()) {
            (StorageBackendKind::S3, Some(s3)) => Arc::new(S3Backend::new(s3)),
            // Configuration guarantees S3 credentials exist when the backend is
            // s3, so this arm is unreachable in practice; falling back loudly
            // beats panicking in a constructor.
            (StorageBackendKind::S3, None) => {
                tracing::error!("STORAGE_BACKEND=s3 but no S3 configuration; using local disk");
                Arc::new(LocalBackend::new(config.upload_dir.clone()))
            }
            (StorageBackendKind::Local, _) => {
                Arc::new(LocalBackend::new(config.upload_dir.clone()))
            }
        };

        Self {
            storage,
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
