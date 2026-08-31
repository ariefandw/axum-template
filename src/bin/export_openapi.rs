use std::fs;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use axum_template::{
    routes::{health, v1::auth},
    ApiDoc,
};

fn main() {
    let (_, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(health::health_check))
        .routes(routes!(health::prometheus_metrics))
        .routes(routes!(auth::sign_up_email))
        .routes(routes!(auth::sign_in_email))
        .routes(routes!(auth::verify_email))
        .routes(routes!(auth::forget_password))
        .routes(routes!(auth::reset_password))
        .routes(routes!(auth::get_session))
        .routes(routes!(auth::google_auth))
        .routes(routes!(auth::google_callback))
        .routes(routes!(auth::github_auth))
        .routes(routes!(auth::github_callback))
        .routes(routes!(axum_template::routes::v1::files::upload_file))
        .routes(routes!(axum_template::routes::v1::files::get_file))
        .split_for_parts();

    let spec = api.to_pretty_json().expect("Failed to serialize OpenAPI spec");
    fs::write("openapi.json", spec).expect("Failed to write openapi.json file");
    println!("Successfully exported complete openapi.json with Better Auth aligned routes!");
}
