#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(missing_docs)]

use zbierak::token_hash;

mod common;

use axum::{body::Body, http::StatusCode};
use common::{ingest_request, response_json, seed_key, seed_project, test_app, test_pool};
use tower::ServiceExt;

const VALID_EVENT: &str =
    r#"{"event_id":"evt-1","timestamp":"2026-09-24T12:00:00Z","message":"boom"}"#;

#[tokio::test]
async fn missing_authorization_is_unauthorized() {
    let app = test_app(test_pool().await);
    let response = app
        .oneshot(ingest_request(
            "demo",
            None,
            Some("application/json"),
            Body::from(VALID_EVENT),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response_json(response).await;
    assert_eq!(body["code"], "unauthorized");
}

#[tokio::test]
async fn unknown_ingest_key_is_unauthorized() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    let app = test_app(db);
    let response = app
        .oneshot(ingest_request(
            "demo",
            Some("zbk_wrong"),
            Some("application/json"),
            Body::from(VALID_EVENT),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn key_for_another_project_is_unauthorized() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_project(&db, 2, "other").await;
    seed_key(&db, 2, "zbk_other_project_key").await;
    let app = test_app(db);
    let response = app
        .oneshot(ingest_request(
            "demo",
            Some("zbk_other_project_key"),
            Some("application/json"),
            Body::from(VALID_EVENT),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoked_ingest_key_is_unauthorized() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_key(&db, 1, "zbk_revoked_key").await;
    sqlx::query("UPDATE ingest_keys SET revoked_at=unixepoch() WHERE key_hash=?")
        .bind(token_hash("zbk_revoked_key"))
        .execute(&db)
        .await
        .unwrap();
    let app = test_app(db);
    let response = app
        .oneshot(ingest_request(
            "demo",
            Some("zbk_revoked_key"),
            Some("application/json"),
            Body::from(VALID_EVENT),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response_json(response).await;
    assert_eq!(body["code"], "unauthorized");
}

#[tokio::test]
async fn unknown_project_slug_is_indistinguishable_from_bad_key() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_key(&db, 1, "zbk_test_key").await;
    let app = test_app(db);
    let response = app
        .oneshot(ingest_request(
            "missing",
            Some("zbk_test_key"),
            Some("application/json"),
            Body::from(VALID_EVENT),
        ))
        .await
        .unwrap();
    // The key lookup is scoped by slug, so an unknown project and an invalid
    // key produce the same 401 rather than revealing whether the slug exists.
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn oversized_body_is_too_large() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_key(&db, 1, "zbk_test_key").await;
    let app = test_app(db);
    let body = vec![b'x'; 1_048_577];
    let response = app
        .oneshot(ingest_request(
            "demo",
            Some("zbk_test_key"),
            Some("application/json"),
            Body::from(body),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body = response_json(response).await;
    assert_eq!(body["code"], "payload_too_large");
}

#[tokio::test]
async fn malformed_json_is_bad_request() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_key(&db, 1, "zbk_test_key").await;
    let app = test_app(db);
    let response = app
        .oneshot(ingest_request(
            "demo",
            Some("zbk_test_key"),
            Some("application/json"),
            Body::from("{not json"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_json(response).await;
    assert_eq!(body["code"], "bad_request");
}

#[tokio::test]
async fn invalid_timestamp_is_unprocessable() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_key(&db, 1, "zbk_test_key").await;
    let app = test_app(db);
    let event = r#"{"event_id":"evt-1","timestamp":"yesterday","message":"boom"}"#;
    let response = app
        .oneshot(ingest_request(
            "demo",
            Some("zbk_test_key"),
            Some("application/json"),
            Body::from(event),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = response_json(response).await;
    assert_eq!(body["code"], "validation_failed");
    assert_eq!(body["field"], "timestamp");
}

#[tokio::test]
async fn conflicting_reuse_of_event_id_is_conflict() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_key(&db, 1, "zbk_test_key").await;
    let app = test_app(db);
    let first = app
        .clone()
        .oneshot(ingest_request(
            "demo",
            Some("zbk_test_key"),
            Some("application/json"),
            Body::from(VALID_EVENT),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);

    let conflicting =
        r#"{"event_id":"evt-1","timestamp":"2026-09-24T12:00:00Z","message":"different"}"#;
    let response = app
        .oneshot(ingest_request(
            "demo",
            Some("zbk_test_key"),
            Some("application/json"),
            Body::from(conflicting),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = response_json(response).await;
    assert_eq!(body["code"], "event_id_conflict");
    assert!(body["message"].as_str().unwrap().contains("evt-1"));
}

#[tokio::test]
async fn identical_duplicate_returns_the_first_result() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_key(&db, 1, "zbk_test_key").await;
    let app = test_app(db);
    let first = app
        .clone()
        .oneshot(ingest_request(
            "demo",
            Some("zbk_test_key"),
            Some("application/json"),
            Body::from(VALID_EVENT),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);

    let response = app
        .oneshot(ingest_request(
            "demo",
            Some("zbk_test_key"),
            Some("application/json"),
            Body::from(VALID_EVENT),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = response_json(response).await;
    assert_eq!(body["id"], "evt-1");
    assert_eq!(body["duplicate"], true);
}
