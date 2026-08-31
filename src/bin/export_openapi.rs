use std::fs;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use axum_template::{routes, ApiDoc};

fn main() {
    let (_, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .merge(routes::app_router())
        .split_for_parts();

    let spec = api.to_pretty_json().expect("Failed to serialize OpenAPI spec");
    fs::write("openapi.json", spec).expect("Failed to write openapi.json file");
    println!("Successfully exported complete openapi.json with hierarchical nested routes!");
}
