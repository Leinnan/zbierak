#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(missing_docs)]

//! HTTP contract tests for the Axum boundaries: router scoping, extractor
//! rejections, body limits, and authentication ordering.

mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::{
    ingest_request, put_json_request, response_json, seed_key, seed_membership, seed_project,
    seed_token, seed_user, test_app, test_pool,
};
use tower::ServiceExt;

const VALID_EVENT: &str =
    r#"{"event_id":"evt-1","timestamp":"2026-09-24T12:00:00Z","message":"boom"}"#;

async fn seeded_app() -> axum::Router {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_key(&db, 1, "zbk_test_key").await;
    seed_user(&db, 1, "owner@example.com", "Owner").await;
    seed_membership(&db, 1, 1, "owner").await;
    seed_token(&db, 1, "zpat_test_token").await;
    test_app(db)
}

#[tokio::test]
async fn unknown_api_routes_return_json_404() {
    let app = seeded_app().await;
    let response = app
        .oneshot(
            Request::get("/api/v1/does-not-exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = response_json(response).await;
    assert_eq!(body["code"], "not_found");
    assert_eq!(body["message"], "not found");
}

#[tokio::test]
async fn wrong_method_on_api_routes_returns_json_405() {
    let app = seeded_app().await;
    let response = app
        .oneshot(
            Request::get("/api/v1/projects/demo/events")
                .header("authorization", "Bearer zbk_test_key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    let body = response_json(response).await;
    assert_eq!(body["code"], "method_not_allowed");
}

#[tokio::test]
async fn invalid_path_parameters_return_json_400() {
    let app = seeded_app().await;
    let response = app
        .oneshot(common::get_request(
            "/api/v1/projects/demo/issues/not-a-number",
            "zpat_test_token",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_json(response).await;
    assert_eq!(body["code"], "bad_request");
}

#[tokio::test]
async fn malformed_query_values_return_json_400() {
    let app = seeded_app().await;
    let response = app
        .oneshot(common::get_request(
            "/api/v1/projects/demo/issues?limit=no",
            "zpat_test_token",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_json(response).await;
    assert_eq!(body["code"], "bad_request");
}

#[tokio::test]
async fn out_of_range_limits_are_rejected_not_clamped() {
    for limit in ["0", "201", "-1"] {
        let app = seeded_app().await;
        let response = app
            .oneshot(common::get_request(
                &format!("/api/v1/projects/demo/issues?limit={limit}"),
                "zpat_test_token",
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "limit={limit} must be rejected"
        );
    }
}

#[tokio::test]
async fn boundary_limits_are_accepted() {
    for limit in ["1", "200"] {
        let app = seeded_app().await;
        let response = app
            .oneshot(common::get_request(
                &format!("/api/v1/projects/demo/issues?limit={limit}"),
                "zpat_test_token",
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "limit={limit} must be accepted"
        );
    }
}

#[tokio::test]
async fn ingestion_requires_json_media_type() {
    for content_type in [None, Some("text/plain"), Some("application/xml")] {
        let app = seeded_app().await;
        let response = app
            .oneshot(ingest_request(
                "demo",
                Some("zbk_test_key"),
                content_type,
                Body::from(VALID_EVENT),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "content type {content_type:?} must be rejected"
        );
        let body = response_json(response).await;
        assert_eq!(body["code"], "unsupported_media_type");
    }
}

#[tokio::test]
async fn ingestion_accepts_json_media_type_with_parameters() {
    let app = seeded_app().await;
    let response = app
        .oneshot(ingest_request(
            "demo",
            Some("zbk_test_key"),
            Some("application/json; charset=utf-8"),
            Body::from(VALID_EVENT),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn bodies_beyond_axums_old_default_still_return_json_413() {
    let app = seeded_app().await;
    // 3 MiB — larger than Axum's former default limit, so this exercises the
    // extractor-level 1 MiB boundary rather than the framework default.
    let body = vec![b'x'; 3 * 1024 * 1024];
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
async fn authentication_precedes_body_parsing() {
    // Invalid credentials plus an unparseable body must fail with 401 —
    // never with a body error — because the auth extractor runs first.
    let app = seeded_app().await;
    let response = app
        .oneshot(ingest_request(
            "demo",
            Some("zbk_wrong_key"),
            Some("application/json"),
            Body::from("{not json"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response_json(response).await;
    assert_eq!(body["code"], "unauthorized");
}

#[tokio::test]
async fn api_token_authentication_precedes_body_parsing() {
    let app = seeded_app().await;
    let response = app
        .oneshot(put_json_request(
            "/api/v1/projects/demo/issues/1/tags",
            "zpat_wrong_token",
            Some("application/json"),
            "{not json",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn malformed_management_json_maps_to_json_400() {
    let app = seeded_app().await;
    let response = app
        .oneshot(put_json_request(
            "/api/v1/projects/demo/issues/1/tags",
            "zpat_test_token",
            Some("application/json"),
            "{not json",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_json(response).await;
    assert_eq!(body["code"], "bad_request");
}

#[tokio::test]
async fn wrong_payload_shape_maps_to_json_422() {
    let app = seeded_app().await;
    let response = app
        .oneshot(put_json_request(
            "/api/v1/projects/demo/issues/1/tags",
            "zpat_test_token",
            Some("application/json"),
            r#"{"tags": "not-a-list"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = response_json(response).await;
    assert_eq!(body["code"], "validation_failed");
}

#[tokio::test]
async fn management_endpoints_require_json_media_type() {
    let app = seeded_app().await;
    let response = app
        .oneshot(put_json_request(
            "/api/v1/projects/demo/issues/1/tags",
            "zpat_test_token",
            Some("text/plain"),
            r#"{"tags": []}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let body = response_json(response).await;
    assert_eq!(body["code"], "unsupported_media_type");
}

#[tokio::test]
async fn unauthorized_api_responses_challenge_with_bearer() {
    let app = seeded_app().await;
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
    assert_eq!(
        response
            .headers()
            .get("www-authenticate")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer")
    );
}

#[tokio::test]
async fn bearer_scheme_is_case_insensitive_end_to_end() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_key(&db, 1, "zbk_test_key").await;
    let app = test_app(db);
    for scheme in ["bearer", "BEARER", "bEaReR"] {
        let request = Request::post("/api/v1/projects/demo/events")
            .header("authorization", format!("{scheme} zbk_test_key"))
            .header("content-type", "application/json")
            .body(Body::from(VALID_EVENT))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::ACCEPTED,
            "scheme {scheme} must be accepted"
        );
    }
}

#[tokio::test]
async fn unknown_ui_routes_do_not_return_json() {
    let app = seeded_app().await;
    let response = app
        .oneshot(
            Request::get("/definitely-not-a-page")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(
        !content_type.starts_with("application/json"),
        "UI fallback must not answer with JSON"
    );
}

#[tokio::test]
async fn api_responses_never_set_cookies() {
    let app = seeded_app().await;
    let response = app
        .oneshot(ingest_request(
            "demo",
            None,
            Some("application/json"),
            Body::from(VALID_EVENT),
        ))
        .await
        .unwrap();
    assert!(response.headers().get("set-cookie").is_none());
}
