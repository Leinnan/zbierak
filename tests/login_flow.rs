use std::{path::PathBuf, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use tower::ServiceExt;
use zbierak::{AppState, Config, hash_password, router};

const EMAIL: &str = "owner@example.com";
const PASSWORD: &str = "correct-horse-staple-12";

async fn seeded_app() -> (Router, SqlitePool) {
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
        db: db.clone(),
        templates: Arc::new(tera::Tera::new("src/templates/**/*.html").unwrap()),
        http: reqwest::Client::new(),
        resolver: std::sync::Arc::new(zbierak::SystemResolver),
    };
    (router(state), db)
}

/// Performs GET /login and returns (router, csrf cookie pair) so the browser
/// contract — anonymous cookie plus matching form field — can be replayed.
async fn fresh_login_challenge(app: &Router) -> (String, String) {
    let response = app
        .clone()
        .oneshot(Request::get("/login").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = response
        .headers()
        .get("set-cookie")
        .expect("login page sets a CSRF cookie")
        .to_str()
        .unwrap()
        .to_owned();
    let (name_value, _attrs) = set_cookie.split_once(';').unwrap();
    let (name, value) = name_value.split_once('=').unwrap();
    assert_eq!(name, "zbierak_login_csrf");
    (name.to_owned(), value.to_owned())
}

fn login_body(csrf: &str, email: &str, password: &str) -> Body {
    Body::from(format!(
        "csrf_token={csrf}&email={email}&password={password}"
    ))
}

async fn post_login(
    app: &Router,
    cookie: Option<(&str, &str)>,
    csrf_field: &str,
    email: &str,
    password: &str,
) -> axum::response::Response {
    let mut builder =
        Request::post("/login").header("content-type", "application/x-www-form-urlencoded");
    if let Some((name, value)) = cookie {
        builder = builder.header("cookie", format!("{name}={value}"));
    }
    app.clone()
        .oneshot(
            builder
                .body(login_body(csrf_field, email, password))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn login_without_csrf_pair_is_rejected() {
    let (app, _db) = seeded_app().await;
    let response = post_login(&app, None, "", EMAIL, PASSWORD).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let (_name, value) = fresh_login_challenge(&app).await;
    // Field without cookie, and cookie without field, both fail.
    let response = post_login(&app, None, &value, EMAIL, PASSWORD).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = post_login(
        &app,
        Some(("zbierak_login_csrf", &value)),
        "mismatch",
        EMAIL,
        PASSWORD,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn login_with_valid_pair_and_credentials_succeeds() {
    let (app, _db) = seeded_app().await;
    let (name, value) = fresh_login_challenge(&app).await;
    let response = post_login(&app, Some((&name, &value)), &value, EMAIL, PASSWORD).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get("location").unwrap(), "/projects");
}

#[tokio::test]
async fn repeated_failures_lock_the_identity_even_with_correct_password() {
    let (app, db) = seeded_app().await;
    for _ in 0..5 {
        let (name, value) = fresh_login_challenge(&app).await;
        let response =
            post_login(&app, Some((&name, &value)), &value, EMAIL, "wrong-password").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // The correct password is rejected while the lockout is active...
    let (name, value) = fresh_login_challenge(&app).await;
    let response = post_login(&app, Some((&name, &value)), &value, EMAIL, PASSWORD).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // ...but a different identity is unaffected.
    sqlx::query("INSERT INTO users (email, display_name, password_hash) VALUES (?, 'Other', ?)")
        .bind("other@example.com")
        .bind(hash_password(PASSWORD).unwrap())
        .execute(&db)
        .await
        .unwrap();
    let (name, value) = fresh_login_challenge(&app).await;
    let response = post_login(
        &app,
        Some((&name, &value)),
        &value,
        "other@example.com",
        PASSWORD,
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}
