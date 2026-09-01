use axum_template::config::AppConfig;
use axum_template::{ApiDoc, routes};
use std::fs;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;

fn main() {
    let (_, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .merge(routes::app_router(&AppConfig::for_testing(
            "postgres://localhost/openapi-export",
        )))
        .split_for_parts();

    let spec = api
        .to_pretty_json()
        .expect("Failed to serialize OpenAPI spec");
    fs::write("openapi.json", spec).expect("Failed to write openapi.json file");
    println!("Successfully exported complete openapi.json with hierarchical nested routes!");
}
