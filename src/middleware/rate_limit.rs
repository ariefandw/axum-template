use std::sync::Arc;
use tower_governor::{
    governor::GovernorConfigBuilder,
    key_extractor::SmartIpKeyExtractor,
    GovernorLayer,
};

pub fn create_rate_limiter() -> GovernorLayer<SmartIpKeyExtractor, governor::middleware::NoOpMiddleware> {
    let governor_conf = GovernorConfigBuilder::default()
        .per_second(20)
        .burst_size(40)
        .key_extractor(SmartIpKeyExtractor)
        .finish()
        .expect("Invalid rate limit configuration");

    GovernorLayer {
        config: Arc::new(governor_conf),
    }
}
