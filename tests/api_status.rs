use std::{path::PathBuf, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use tower::ServiceExt;
use zbierak::{AppState, Config, router, token_hash};

async fn test_pool() -> SqlitePool {
    let db = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!().run(&db).await.unwrap();
    db
}

async fn seed_project(db: &SqlitePool, project_id: i64, slug: &str) {
    sqlx::query(
        "INSERT OR IGNORE INTO users (id, email, display_name, password_hash)
         VALUES (1, 'owner@example.com', 'Owner', 'unused')",
    )
    .execute(db)
    .await
    .unwrap();
    sqlx::query("INSERT INTO projects (id, slug, name, created_by) VALUES (?, ?, 'Demo', 1)")
        .bind(project_id)
        .bind(slug)
        .execute(db)
        .await
        .unwrap();
}

async fn seed_key(db: &SqlitePool, project_id: i64, key: &str) {
    sqlx::query(
        "INSERT INTO ingest_keys (project_id, name, key_prefix, key_hash, created_by)
         VALUES (?, 'test', 'zbk_test', ?, 1)",
    )
    .bind(project_id)
    .bind(token_hash(key))
    .execute(db)
    .await
    .unwrap();
}

fn test_app(db: SqlitePool) -> Router {
    let state = AppState {
        config: Arc::new(Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            database_url: "sqlite::memory:".into(),
            cookie_secure: false,
            session_days: 30,
            static_dir: PathBuf::from("src/static"),
            template_dir: PathBuf::from("src/templates"),
            webhook_key: None,
        }),
        db,
        templates: Arc::new(tera::Tera::default()),
        http: reqwest::Client::new(),
        resolver: std::sync::Arc::new(zbierak::SystemResolver),
    };
    router(state)
}

fn ingest_request(slug: &str, key: Option<&str>, body: impl Into<Body>) -> Request<Body> {
    let mut builder = Request::post(format!("/api/v1/projects/{slug}/events"))
        .header("content-type", "application/json");
    if let Some(key) = key {
        builder = builder.header("authorization", format!("Bearer {key}"));
    }
    builder.body(body.into()).unwrap()
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

const VALID_EVENT: &str =
    r#"{"event_id":"evt-1","timestamp":"2026-09-24T12:00:00Z","message":"boom"}"#;

#[tokio::test]
async fn missing_authorization_is_unauthorized() {
    let app = test_app(test_pool().await);
    let response = app
        .oneshot(ingest_request("demo", None, Body::from(VALID_EVENT)))
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
            Body::from(VALID_EVENT),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);

    let response = app
        .oneshot(ingest_request(
            "demo",
            Some("zbk_test_key"),
            Body::from(VALID_EVENT),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = response_json(response).await;
    assert_eq!(body["id"], "evt-1");
    assert_eq!(body["duplicate"], true);
}
