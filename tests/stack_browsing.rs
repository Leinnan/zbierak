#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(missing_docs)]

mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;
use zbierak::hash_password;

use common::{
    app_with_templates, get_request, ingest_request, login, response_json, seed_key,
    seed_membership, seed_project, seed_token, test_app, test_pool,
};
const PASSWORD: &str = "correct horse battery staple";
const TOKEN: &str = "zpat_stack_browsing_token";
const KEY: &str = "zbk_stack_browsing_key";

fn framed_event(event_id: &str) -> String {
    json!({
        "event_id": event_id,
        "timestamp": "2026-09-24T12:00:00Z",
        "message": "connection lost",
        "error": {
            "type": "io::Error",
            "value": "connection refused",
            "stack_frames": [
                {"function": "store::connect", "filename": "src/store.rs", "line": 42, "column": 9, "in_app": true},
                {"function": "std::io::read", "filename": "/rustc/hash/library/std/src/io/mod.rs", "line": 7, "in_app": false}
            ]
        }
    })
    .to_string()
}

async fn ingest(app: &axum::Router, body: String) -> axum::response::Response {
    app.clone()
        .oneshot(ingest_request(
            "demo",
            Some(KEY),
            Some("application/json"),
            Body::from(body),
        ))
        .await
        .unwrap()
}

async fn seeded_app() -> (axum::Router, sqlx::SqlitePool, i64) {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_membership(&db, 1, 1, "owner").await;
    seed_key(&db, 1, KEY).await;
    seed_token(&db, 1, TOKEN).await;
    let app = test_app(db.clone());
    let accepted = response_json(ingest(&app, framed_event("evt-1")).await).await;
    let issue_id = accepted["issue_id"].as_i64().unwrap();
    (app, db, issue_id)
}

#[tokio::test]
async fn api_lists_issue_events_with_resolved_frames() {
    let (app, _db, issue_id) = seeded_app().await;
    let response = app
        .oneshot(get_request(
            &format!("/api/v1/projects/demo/issues/{issue_id}/events"),
            TOKEN,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    let events = body.as_array().expect("events array");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["id"], "evt-1");
    assert_eq!(events[0]["message"], "connection lost");
    assert_eq!(events[0]["severity"], "error");
    assert_eq!(events[0]["environment"], "default");
    assert_eq!(events[0]["error_type"], "io::Error");
    assert_eq!(events[0]["error_value"], "connection refused");
    let frames = events[0]["stack_frames"].as_array().expect("frames array");
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0]["number"], 1);
    assert_eq!(frames[0]["function"], "store::connect");
    assert_eq!(frames[0]["filename"], "src/store.rs");
    assert_eq!(frames[0]["line"], 42);
    assert_eq!(frames[0]["column"], 9);
    assert_eq!(frames[0]["in_app"], true);
    assert_eq!(frames[1]["in_app"], false);
}

#[tokio::test]
async fn api_event_frames_fall_back_to_event_level_frames() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_membership(&db, 1, 1, "owner").await;
    seed_key(&db, 1, KEY).await;
    seed_token(&db, 1, TOKEN).await;
    let app = test_app(db.clone());
    let body = json!({
        "event_id": "evt-top",
        "timestamp": "2026-09-24T12:00:00Z",
        "message": "flat capture",
        "stack_frames": [{"function": "solo", "filename": "src/solo.rs", "line": 3}]
    })
    .to_string();
    assert_eq!(ingest(&app, body).await.status(), StatusCode::ACCEPTED);

    let response = app
        .oneshot(get_request("/api/v1/projects/demo/issues/1/events", TOKEN))
        .await
        .unwrap();
    let events = response_json(response).await;
    let frames = events[0]["stack_frames"].as_array().unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0]["function"], "solo");
    assert!(events[0]["error_type"].is_null());
}

#[tokio::test]
async fn api_events_endpoint_validates_pagination_and_access() {
    let (app, _db, issue_id) = seeded_app().await;

    for limit in ["0", "101"] {
        let response = app
            .clone()
            .oneshot(get_request(
                &format!("/api/v1/projects/demo/issues/{issue_id}/events?limit={limit}"),
                TOKEN,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "limit {limit}");
    }

    let response = app
        .clone()
        .oneshot(get_request(
            &format!("/api/v1/projects/demo/issues/{issue_id}/events?limit=1&offset=1"),
            TOKEN,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await.as_array().unwrap().len(),
        0,
        "offset past the single event yields an empty page"
    );

    let response = app
        .clone()
        .oneshot(get_request(
            &format!("/api/v1/projects/demo/issues/{issue_id}/events"),
            "zpat_wrong_token",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .oneshot(get_request(
            "/api/v1/projects/demo/issues/99999/events",
            TOKEN,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn oversized_stack_frames_fail_ingest_with_field() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_key(&db, 1, KEY).await;
    let app = test_app(db);

    let frames: Vec<serde_json::Value> = (0..257)
        .map(|index| json!({"function": format!("f{index}"), "filename": "src/x.rs"}))
        .collect();
    let body = json!({
        "event_id": "evt-too-many",
        "timestamp": "2026-09-24T12:00:00Z",
        "message": "boom",
        "stack_frames": frames,
    })
    .to_string();

    let response = ingest(&app, body).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let error = response_json(response).await;
    assert_eq!(error["code"], "validation_failed");
    assert_eq!(error["field"], "stack_frames");
}

#[tokio::test]
async fn issue_page_renders_structured_frames_with_error_headline() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_membership(&db, 1, 1, "owner").await;
    sqlx::query("UPDATE users SET password_hash=? WHERE id=1")
        .bind(hash_password(PASSWORD).unwrap())
        .execute(&db)
        .await
        .unwrap();
    seed_key(&db, 1, KEY).await;
    let app = app_with_templates(db.clone());

    let accepted = response_json(ingest(&app, framed_event("evt-ui")).await).await;
    let issue_id = accepted["issue_id"].as_i64().unwrap();

    let session = login(&app, &db, "owner@example.com", PASSWORD).await;
    let page = session
        .app
        .clone()
        .oneshot(
            Request::get(format!("/projects/demo/issues/{issue_id}"))
                .header("cookie", session.cookie_header.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let html = String::from_utf8(
        page.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    // Structured frame list with server-side in_app classification.
    assert!(html.contains(r#"class="stack-frame is-app""#));
    assert!(html.contains(r#"class="stack-frame is-system""#));
    assert!(html.contains("frame-number"));
    assert!(html.contains("store::connect"));
    assert!(html.contains(r"src/store.rs:42:9"));
    // Error headline with type and value.
    assert!(html.contains(r#"<code class="error-type">io::Error</code>"#));
    assert!(html.contains(r#"<span class="error-value">connection refused</span>"#));
    // Hidden flattened text stays available for the copy button.
    assert!(html.contains(r#"id="stack-trace""#));
    assert!(html.contains("std::io::read"));
}

#[tokio::test]
async fn issue_page_renders_per_event_stack_frames() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_membership(&db, 1, 1, "owner").await;
    sqlx::query("UPDATE users SET password_hash=? WHERE id=1")
        .bind(hash_password(PASSWORD).unwrap())
        .execute(&db)
        .await
        .unwrap();
    seed_key(&db, 1, KEY).await;
    let app = app_with_templates(db.clone());

    let accepted = response_json(ingest(&app, framed_event("evt-page")).await).await;
    let issue_id = accepted["issue_id"].as_i64().unwrap();

    let session = login(&app, &db, "owner@example.com", PASSWORD).await;
    let page = session
        .app
        .clone()
        .oneshot(
            Request::get(format!("/projects/demo/issues/{issue_id}"))
                .header("cookie", session.cookie_header.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let html = String::from_utf8(
        page.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    // Each event card carries its own structured stack plus hidden text.
    assert!(html.contains("data-copy-target=\"#event-stack-1\""));
    assert!(html.contains(r#"id="event-stack-1""#));
    assert!(html.contains("<h3>Stack trace</h3>"));
}
