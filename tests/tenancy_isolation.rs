//! Regression tests for tenant data isolation.
//!
//! Organizations previously existed only as a registry: `files` and
//! `notifications` carried `org_id` columns that no code read or wrote, and org
//! membership granted access to nothing. These tests assert that the tenancy
//! boundary now reaches the data plane in both directions — members can see
//! their tenant's data, and outsiders cannot.

mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use common::*;

/// A member of an organization can read files that belong to it, without being
/// the uploader. Without org-aware authorization this fails with 404.
#[tokio::test]
async fn org_members_can_read_their_organizations_files() {
    let app = TestApp::spawn().await;
    let (owner_token, _, _) = app.register(&unique_email("org-owner")).await;
    let (member_token, _, member_id) = app.register(&unique_email("org-member")).await;
    let (outsider_token, _, _) = app.register(&unique_email("org-outsider")).await;

    let (_app_id, org_id) = app.create_app_and_org(&owner_token).await;
    let (status, _) = app
        .post_as(
            &format!("/api/v1/apps/orgs/{org_id}/members"),
            serde_json::json!({ "user_id": member_id, "role": "member" }),
            &owner_token,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "adding the member should succeed"
    );

    // The owner uploads a private file attributed to the organization.
    let (status, body) = app
        .upload_png_to_org(&owner_token, "private", Some(&org_id))
        .await;
    assert_eq!(status, StatusCode::CREATED, "org upload failed: {body}");
    let file_id = body["data"]["id"].as_str().unwrap().to_string();
    assert_eq!(
        body["data"]["org_id"].as_str(),
        Some(org_id.as_str()),
        "the file must record which organization it belongs to"
    );

    // A fellow member can read it.
    let (status, _) = app
        .get_as(&format!("/api/v1/files/{file_id}"), &member_token)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an org member should be able to read the org's file"
    );

    // An outsider cannot, and is told it does not exist.
    let (status, _) = app
        .get_as(&format!("/api/v1/files/{file_id}"), &outsider_token)
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a non-member must not read tenant data"
    );

    // Nor can an anonymous caller.
    let (status, _) = app
        .request(
            Request::builder()
                .uri(format!("/api/v1/files/{file_id}"))
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Reading a tenant's data is not the same as destroying it.
#[tokio::test]
async fn plain_members_cannot_delete_organization_files() {
    let app = TestApp::spawn().await;
    let (owner_token, _, _) = app.register(&unique_email("del-owner")).await;
    let (member_token, _, member_id) = app.register(&unique_email("del-member")).await;
    let (admin_token, _, admin_id) = app.register(&unique_email("del-orgadmin")).await;

    let (_app_id, org_id) = app.create_app_and_org(&owner_token).await;
    for (uid, role) in [(&member_id, "member"), (&admin_id, "admin")] {
        let (status, body) = app
            .post_as(
                &format!("/api/v1/apps/orgs/{org_id}/members"),
                serde_json::json!({ "user_id": uid, "role": role }),
                &owner_token,
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "adding {role} failed: {body}");
    }

    let (_, body) = app
        .upload_png_to_org(&owner_token, "private", Some(&org_id))
        .await;
    let file_id = body["data"]["id"].as_str().unwrap().to_string();

    let delete = |token: String, id: String| async move {
        Request::builder()
            .uri(format!("/api/v1/files/{id}"))
            .method("DELETE")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };

    // A plain member may read but not delete.
    let (status, _) = app
        .request(delete(member_token, file_id.clone()).await)
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a plain member must not delete tenant files"
    );

    // An org admin may.
    let (status, _) = app.request(delete(admin_token, file_id).await).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "an org admin should be able to delete tenant files"
    );
}

/// Uploading into an organization requires membership, checked before any bytes
/// are written, and a non-member cannot use it to probe for org IDs.
#[tokio::test]
async fn outsiders_cannot_upload_into_an_organization() {
    let app = TestApp::spawn().await;
    let (owner_token, _, _) = app.register(&unique_email("up-owner")).await;
    let (outsider_token, _, _) = app.register(&unique_email("up-outsider")).await;
    let (_app_id, org_id) = app.create_app_and_org(&owner_token).await;

    let (status, body) = app
        .upload_png_to_org(&outsider_token, "private", Some(&org_id))
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a non-member must not upload into someone else's organization: {body}"
    );
}

/// The org file listing is membership-gated in both directions.
#[tokio::test]
async fn org_file_listing_is_membership_gated() {
    let app = TestApp::spawn().await;
    let (owner_token, _, _) = app.register(&unique_email("list-owner")).await;
    let (member_token, _, member_id) = app.register(&unique_email("list-member")).await;
    let (outsider_token, _, _) = app.register(&unique_email("list-outsider")).await;

    let (_app_id, org_id) = app.create_app_and_org(&owner_token).await;
    app.post_as(
        &format!("/api/v1/apps/orgs/{org_id}/members"),
        serde_json::json!({ "user_id": member_id, "role": "member" }),
        &owner_token,
    )
    .await;

    app.upload_png_to_org(&owner_token, "private", Some(&org_id))
        .await;
    app.upload_png_to_org(&owner_token, "private", Some(&org_id))
        .await;
    // A personal file by the same owner must NOT appear in the org listing.
    app.upload_png(&owner_token, "private").await;

    let (status, body) = app
        .get_as(&format!("/api/v1/files/org/{org_id}"), &member_token)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a member should be able to list org files: {body}"
    );
    assert_eq!(
        body["data"].as_array().unwrap().len(),
        2,
        "the listing must contain only the organization's files"
    );

    let (status, _) = app
        .get_as(&format!("/api/v1/files/org/{org_id}"), &outsider_token)
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a non-member must not list tenant files"
    );
}

/// The notification feed can be filtered by organization, and the filter is
/// membership-checked rather than trusted.
#[tokio::test]
async fn notification_org_filter_requires_membership() {
    let app = TestApp::spawn().await;
    let (owner_token, _, owner_id) = app.register(&unique_email("notif-owner")).await;
    let (outsider_token, _, _) = app.register(&unique_email("notif-outsider")).await;
    let (_app_id, org_id) = app.create_app_and_org(&owner_token).await;

    let uid = uuid::Uuid::parse_str(&owner_id).unwrap();
    let oid = uuid::Uuid::parse_str(&org_id).unwrap();

    axum_template::services::notification::NotificationService::create_scoped(
        &app.state,
        uid,
        Some(oid),
        "Tenant event",
        "body",
        None,
    )
    .await
    .expect("org notification");
    axum_template::services::notification::NotificationService::create(
        &app.state,
        uid,
        "Personal event",
        "body",
        None,
    )
    .await
    .expect("personal notification");

    // Unfiltered: both.
    let (status, all) = app.get_as("/api/v1/notifications", &owner_token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(all["data"].as_array().unwrap().len(), 2);

    // Filtered: only the tenant's.
    let (status, scoped) = app
        .get_as(
            &format!("/api/v1/notifications?org_id={org_id}"),
            &owner_token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{scoped}");
    let items = scoped["data"].as_array().unwrap();
    assert_eq!(items.len(), 1, "the org filter should narrow the feed");
    assert_eq!(items[0]["title"], "Tenant event");

    // An outsider cannot filter by an org they do not belong to.
    let (status, _) = app
        .get_as(
            &format!("/api/v1/notifications?org_id={org_id}"),
            &outsider_token,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the filter must be membership-checked"
    );
}
