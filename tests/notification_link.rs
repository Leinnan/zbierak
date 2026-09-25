#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(missing_docs)]

mod common;

use axum::{Router, body::Body, http::StatusCode};
use common::{
    app_with_templates_and_config, ingest_request, seed_key, seed_project, test_config, test_pool,
};
use serde_json::Value;
use sqlx::SqlitePool;
use tower::ServiceExt;
use url::Url;

const VALID_EVENT: &str =
    r#"{"event_id":"evt-1","timestamp":"2026-09-24T12:00:00Z","message":"boom"}"#;
const ISSUE_URL: &str = "https://errors.example.com/projects/demo/issues/1";

async fn seeded_app(public_url: Option<&str>) -> (Router, SqlitePool) {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_key(&db, 1, "zbk_test_key").await;
    sqlx::query(
        "INSERT INTO notification_endpoints (project_id, name, kind, url, created_by)
         VALUES (1, 'discord', 'discord', 'https://discord.com/api/webhooks/1/abc', 1)",
    )
    .execute(&db)
    .await
    .unwrap();
    let mut config = test_config();
    config.public_url = public_url.map(|raw| Url::parse(raw).unwrap());
    let app = app_with_templates_and_config(db.clone(), config);
    (app, db)
}

async fn ingest_issue(app: Router) {
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
}

async fn outbox_payloads(db: &SqlitePool) -> Vec<Value> {
    let rows: Vec<String> = sqlx::query_scalar("SELECT payload_json FROM outbox ORDER BY id")
        .fetch_all(db)
        .await
        .unwrap();
    rows.into_iter()
        .map(|row| serde_json::from_str(&row).unwrap())
        .collect()
}

#[tokio::test]
async fn discord_notification_includes_the_issue_link() {
    let (app, db) = seeded_app(Some("https://errors.example.com/")).await;
    ingest_issue(app).await;

    let payloads = outbox_payloads(&db).await;
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0]["issue_url"], ISSUE_URL);
    let content = payloads[0]["content"].as_str().unwrap();
    assert!(content.contains("New issue in demo: boom"));
    assert!(content.ends_with(ISSUE_URL));
}

#[tokio::test]
async fn notification_has_no_link_without_public_url() {
    let (app, db) = seeded_app(None).await;
    ingest_issue(app).await;

    let payloads = outbox_payloads(&db).await;
    assert_eq!(payloads.len(), 1);
    assert!(payloads[0].get("issue_url").is_none());
    assert_eq!(payloads[0]["content"], "New issue in demo: boom");
}
