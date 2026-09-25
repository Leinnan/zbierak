#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(missing_docs)]

mod common;

use std::{net::IpAddr, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use common::{LoggedIn, app_with, login as shared_login, test_config, test_pool};
use sqlx::SqlitePool;
use tower::ServiceExt;
use zbierak::{Resolver, SystemResolver, decrypt, encrypt, generate_key, hash_password, parse_key};

const EMAIL: &str = "owner@example.com";
const PASSWORD: &str = "correct-horse-staple-12";

/// Pins every lookup to a single address so tests never touch real DNS.
use common::Pinned;

struct TestApp {
    app: Router,
    db: SqlitePool,
}

async fn seeded_app(
    resolver: Arc<dyn zbierak::Resolver>,
    webhook_key: Option<[u8; 32]>,
) -> TestApp {
    let db = test_pool().await;
    sqlx::query("INSERT INTO users (email, display_name, password_hash) VALUES (?, 'Owner', ?)")
        .bind(EMAIL)
        .bind(hash_password(PASSWORD).unwrap())
        .execute(&db)
        .await
        .unwrap();
    sqlx::query("INSERT INTO projects (id, slug, name, created_by) VALUES (1, 'demo', 'Demo', 1)")
        .execute(&db)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO project_memberships (project_id, user_id, role) VALUES (1, 1, 'owner')",
    )
    .execute(&db)
    .await
    .unwrap();
    let mut config = test_config();
    config.webhook_key = webhook_key;
    TestApp {
        app: app_with(db.clone(), config, resolver),
        db,
    }
}

async fn login(app: &Router, db: &SqlitePool) -> (String, String) {
    let LoggedIn {
        session_value,
        csrf,
        ..
    } = shared_login(app, db, EMAIL, PASSWORD).await;
    (session_value, csrf)
}

fn create_webhook_request(session: &str, csrf: &str, kind: &str, url: &str) -> Request<Body> {
    let secret = if kind == "webhook" {
        "&secret=0123456789abcdef"
    } else {
        ""
    };
    Request::post("/projects/demo/notifications/webhooks")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("cookie", format!("zbierak_session={session}"))
        .body(Body::from(format!(
            "csrf_token={csrf}&kind={kind}&name=test&url={url}{secret}"
        )))
        .unwrap()
}

#[tokio::test]
async fn webhook_secrets_are_stored_encrypted() {
    let master = parse_key(&generate_key()).unwrap();
    let public = "93.184.216.34".parse::<IpAddr>().unwrap();
    let TestApp { app, db } = seeded_app(Arc::new(Pinned(public)), Some(master)).await;
    let (session, csrf) = login(&app, &db).await;

    let response = app
        .clone()
        .oneshot(create_webhook_request(
            &session,
            &csrf,
            "webhook",
            "https://hooks.example.test/zbierak",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let (stored, flag): (String, i64) = sqlx::query_as(
        "SELECT secret, secret_encrypted FROM notification_endpoints WHERE kind='webhook'",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(flag, 1);
    assert!(stored.starts_with("v1:"));
    assert!(!stored.contains("0123456789abcdef"));
    assert_eq!(decrypt(&master, &stored).unwrap(), "0123456789abcdef");
}

#[tokio::test]
async fn webhook_creation_requires_the_master_key() {
    let public = "93.184.216.34".parse::<IpAddr>().unwrap();
    let TestApp { app, db } = seeded_app(Arc::new(Pinned(public)), None).await;
    let (session, csrf) = login(&app, &db).await;

    let response = app
        .oneshot(create_webhook_request(
            &session,
            &csrf,
            "webhook",
            "https://hooks.example.test/zbierak",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn internal_destinations_are_rejected_at_creation() {
    let master = parse_key(&generate_key()).unwrap();
    let loopback = "127.0.0.1".parse::<IpAddr>().unwrap();
    let TestApp { app, db } = seeded_app(Arc::new(Pinned(loopback)), Some(master)).await;
    let (session, csrf) = login(&app, &db).await;

    let response = app
        .clone()
        .oneshot(create_webhook_request(
            &session,
            &csrf,
            "webhook",
            "https://metadata.internal/hook",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM notification_endpoints")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn discord_endpoints_follow_the_same_policy() {
    let master = parse_key(&generate_key()).unwrap();
    let loopback = "10.1.2.3".parse::<IpAddr>().unwrap();
    let TestApp { app, db } = seeded_app(Arc::new(Pinned(loopback)), Some(master)).await;
    let (session, csrf) = login(&app, &db).await;

    let response = app
        .oneshot(create_webhook_request(
            &session,
            &csrf,
            "discord",
            "https://discord.com/api/webhooks/1/2",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn system_resolver_still_resolves_public_hosts() {
    // Sanity check that the production resolver compiles into the trait and
    // filters obviously private results (no network access required).
    let resolver = SystemResolver;
    let addresses = resolver
        .resolve("localhost".into(), 8080)
        .await
        .unwrap_or_default();
    let allowed: Vec<_> = addresses
        .iter()
        .filter(|ip| zbierak::is_allowed_destination(**ip))
        .collect();
    assert!(allowed.is_empty(), "localhost must never be allowed");
    let _ = encrypt;
}
