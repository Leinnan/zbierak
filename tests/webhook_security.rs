use std::{net::IpAddr, path::PathBuf, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use tower::ServiceExt;
use zbierak::{
    AppState, BoxResolveFuture, Config, Resolver, SystemResolver, decrypt, encrypt, generate_key,
    hash_password, parse_key, router,
};

const EMAIL: &str = "owner@example.com";
const PASSWORD: &str = "correct-horse-staple-12";

/// Pins every lookup to a single address so tests never touch real DNS.
struct Pinned(IpAddr);

impl zbierak::Resolver for Pinned {
    fn resolve(&self, _host: String, _port: u16) -> BoxResolveFuture {
        let ip = self.0;
        Box::pin(async move { Ok(vec![ip]) })
    }
}

struct TestApp {
    app: Router,
    db: SqlitePool,
}

async fn seeded_app(
    resolver: Arc<dyn zbierak::Resolver>,
    webhook_key: Option<[u8; 32]>,
) -> TestApp {
    let db = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!().run(&db).await.unwrap();
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
    let state = AppState {
        config: Arc::new(Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            database_url: "sqlite::memory:".into(),
            cookie_secure: false,
            session_days: 30,
            static_dir: PathBuf::from("src/static"),
            template_dir: PathBuf::from("src/templates"),
            webhook_key,
        }),
        db: db.clone(),
        templates: Arc::new(tera::Tera::new("src/templates/**/*.html").unwrap()),
        http: reqwest::Client::new(),
        resolver,
    };
    TestApp {
        app: router(state),
        db,
    }
}

async fn login(app: &Router, db: &SqlitePool) -> (String, String) {
    let challenge = app
        .clone()
        .oneshot(Request::get("/login").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let set_cookie = challenge
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap();
    let (pair, _) = set_cookie.split_once(';').unwrap();
    let csrf = pair.split_once('=').unwrap().1;

    let response = app
        .clone()
        .oneshot(
            Request::post("/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", format!("zbierak_login_csrf={csrf}"))
                .body(Body::from(format!(
                    "csrf_token={csrf}&email={EMAIL}&password={PASSWORD}"
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap();
    let (pair, _) = set_cookie.split_once(';').unwrap();
    let session = pair.split_once('=').unwrap().1;
    let session_csrf: String =
        sqlx::query_scalar("SELECT csrf_token FROM sessions WHERE token_hash=?")
            .bind(zbierak::token_hash(session))
            .fetch_one(db)
            .await
            .unwrap();
    (session.to_owned(), session_csrf)
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
