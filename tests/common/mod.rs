//! Shared fixtures for the integration test suites.
//!
//! Kept as ordinary helper functions (not macros) so setup stays readable
//! and each suite only uses what it needs.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(missing_docs)]

use std::sync::Arc;

use axum::{Router, body::Body, http::Request};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use tower::ServiceExt;
use zbierak::{AppState, AssetSource, Config, SystemResolver, router, token_hash};

pub async fn test_pool() -> SqlitePool {
    let db = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!().run(&db).await.unwrap();
    db
}

pub fn test_config() -> Config {
    Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        database_url: "sqlite::memory:".into(),
        cookie_secure: false,
        session_days: 30,
        static_dir: AssetSource::Embedded,
        template_dir: AssetSource::Embedded,
        webhook_key: None,
        public_url: None,
    }
}

pub fn test_app(db: SqlitePool) -> Router {
    let state = AppState {
        config: Arc::new(test_config()),
        db,
        templates: Arc::new(tera::Tera::default()),
        resolver: Arc::new(SystemResolver),
    };
    router(state)
}

/// App wired with the real template directory, required by tests that
/// exercise the full login/form UI flow.
pub fn app_with_templates(db: SqlitePool) -> Router {
    app_with_templates_and_config(db, test_config())
}

/// Resolver stub that pins every lookup to one address so tests never touch
/// real DNS.
pub struct Pinned(pub std::net::IpAddr);

impl zbierak::Resolver for Pinned {
    fn resolve(&self, _host: String, _port: u16) -> zbierak::BoxResolveFuture {
        let ip = self.0;
        Box::pin(async move { Ok(vec![ip]) })
    }
}

pub fn app_with_templates_and_config(db: SqlitePool, config: Config) -> Router {
    app_with(db, config, Arc::new(SystemResolver))
}

pub fn app_with(db: SqlitePool, config: Config, resolver: Arc<dyn zbierak::Resolver>) -> Router {
    let templates = zbierak::load_templates(&AssetSource::Embedded).unwrap();
    let state = AppState {
        config: Arc::new(config),
        db,
        templates: Arc::new(templates),
        resolver,
    };
    router(state)
}

pub async fn seed_user(db: &SqlitePool, id: i64, email: &str, display_name: &str) {
    sqlx::query(
        "INSERT OR IGNORE INTO users (id, email, display_name, password_hash)
         VALUES (?, ?, ?, 'unused')",
    )
    .bind(id)
    .bind(email)
    .bind(display_name)
    .execute(db)
    .await
    .unwrap();
}

pub async fn seed_project(db: &SqlitePool, project_id: i64, slug: &str) {
    seed_user(db, 1, "owner@example.com", "Owner").await;
    sqlx::query("INSERT INTO projects (id, slug, name, created_by) VALUES (?, ?, 'Demo', 1)")
        .bind(project_id)
        .bind(slug)
        .execute(db)
        .await
        .unwrap();
}

pub async fn seed_membership(db: &SqlitePool, project_id: i64, user_id: i64, role: &str) {
    sqlx::query("INSERT INTO project_memberships (project_id, user_id, role) VALUES (?, ?, ?)")
        .bind(project_id)
        .bind(user_id)
        .bind(role)
        .execute(db)
        .await
        .unwrap();
}

pub async fn seed_key(db: &SqlitePool, project_id: i64, key: &str) {
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

pub async fn seed_token(db: &SqlitePool, user_id: i64, token: &str) {
    sqlx::query(
        "INSERT INTO api_tokens (user_id, name, token_prefix, token_hash)
         VALUES (?, 'test', 'zpat_test', ?)",
    )
    .bind(user_id)
    .bind(token_hash(token))
    .execute(db)
    .await
    .unwrap();
}

pub async fn response_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

pub fn get_request(path: &str, token: &str) -> Request<Body> {
    Request::get(path.to_owned())
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

pub fn put_json_request(
    path: &str,
    token: &str,
    content_type: Option<&str>,
    body: &str,
) -> Request<Body> {
    let mut builder =
        Request::put(path.to_owned()).header("authorization", format!("Bearer {token}"));
    if let Some(content_type) = content_type {
        builder = builder.header("content-type", content_type);
    }
    builder.body(Body::from(body.to_owned())).unwrap()
}

pub fn ingest_request(
    slug: &str,
    key: Option<&str>,
    content_type: Option<&str>,
    body: impl Into<Body>,
) -> Request<Body> {
    let mut builder = Request::post(format!("/api/v1/projects/{slug}/events"));
    if let Some(key) = key {
        builder = builder.header("authorization", format!("Bearer {key}"));
    }
    if let Some(content_type) = content_type {
        builder = builder.header("content-type", content_type);
    }
    builder.body(body.into()).unwrap()
}

/// Result of a completed UI login: the router plus the credentials needed to
/// POST authenticated forms (session cookie and the session CSRF token).
pub struct LoggedIn {
    pub app: Router,
    /// Raw session token, for tests that need the value itself.
    pub session_value: String,
    /// Preformatted `Cookie` header value carrying the session.
    pub cookie_header: String,
    pub csrf: String,
}

/// Performs the real double-submit login flow against `app` and returns the
/// authenticated session.
pub async fn login(app: &Router, db: &SqlitePool, email: &str, password: &str) -> LoggedIn {
    let page = app
        .clone()
        .oneshot(Request::get("/login").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(page.status(), 200, "login page must render");
    let login_csrf = set_cookie_value(&page, "zbierak_login_csrf")
        .unwrap_or_else(|| panic!("login page must set the CSRF cookie"));

    let body = format!("csrf_token={login_csrf}&email={email}&password={password}");
    let response = app
        .clone()
        .oneshot(
            Request::post("/login")
                .header("cookie", format!("zbierak_login_csrf={login_csrf}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 303, "login must redirect on success");
    let session = set_cookie_value(&response, "zbierak_session")
        .unwrap_or_else(|| panic!("login must set the session cookie"));

    let csrf: String = sqlx::query_scalar("SELECT csrf_token FROM sessions WHERE token_hash = ?")
        .bind(token_hash(&session))
        .fetch_one(db)
        .await
        .unwrap();

    LoggedIn {
        app: app.clone(),
        session_value: session.clone(),
        cookie_header: format!("zbierak_session={session}"),
        csrf,
    }
}

fn set_cookie_value(response: &axum::response::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|value| {
            let value = value.to_str().ok()?;
            let pair = value.split(';').next()?; // "name=value"
            let (cookie_name, cookie_value) = pair.split_once('=')?;
            (cookie_name.trim() == name).then(|| cookie_value.to_owned())
        })
}

impl LoggedIn {
    /// Builds an authenticated form POST against the logged-in router.
    pub fn post_form(&self, path: &str, fields: &[(&str, &str)]) -> Request<Body> {
        use std::fmt::Write as _;
        let mut body = String::new();
        for (key, value) in fields {
            if !body.is_empty() {
                body.push('&');
            }
            let _ = write!(body, "{key}={value}");
        }
        Request::post(path.to_owned())
            .header("cookie", self.cookie_header.clone())
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap()
    }
}
