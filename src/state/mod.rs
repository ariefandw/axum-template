use std::{collections::HashMap, sync::Arc};
use bytes::Bytes;
use metrics_exporter_prometheus::PrometheusHandle;
use sqlx::PgPool;
use tokio::sync::RwLock;
use crate::config::AppConfig;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<AppConfig>,
    pub http_client: reqwest::Client,
    pub idempotency_store: Arc<RwLock<HashMap<String, (u16, Bytes)>>>,
    pub prometheus_handle: Arc<PrometheusHandle>,
}

impl AppState {
    pub fn new(db: PgPool, config: AppConfig, prometheus_handle: PrometheusHandle) -> Self {
        Self {
            db,
            config: Arc::new(config),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("Failed to build reqwest client"),
            idempotency_store: Arc::new(RwLock::new(HashMap::new())),
            prometheus_handle: Arc::new(prometheus_handle),
        }
    }
}
