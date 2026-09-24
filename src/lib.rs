mod api_error;
mod audit;
mod auth;
mod config;
mod db;
mod error;
mod fingerprint;
mod handlers;
mod net_policy;
pub use net_policy::{BoxResolveFuture, Resolver, SystemResolver, is_allowed_destination};
#[cfg(feature = "docs")]
mod openapi;
mod outbox;
mod secrets;
pub use secrets::{decrypt, encrypt, generate_key, parse_key};
mod tags;

use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    http::{HeaderName, HeaderValue, Request},
    middleware::{self, Next},
    response::Response,
    routing::{get, post, put},
};
use sqlx::SqlitePool;
use tera::Tera;
use tokio::{net::TcpListener, sync::watch};
use tower_cookies::CookieManagerLayer;

pub use auth::{hash_password, token_hash, verify_password};
pub use config::Config;
pub use error::{AppError, AppResult};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: SqlitePool,
    pub templates: Arc<Tera>,
    pub http: reqwest::Client,
    pub resolver: Arc<dyn net_policy::Resolver>,
}

pub fn router(state: AppState) -> Router {
    let app = Router::new()
        .route("/", get(handlers::home))
        .route(
            "/bootstrap",
            get(handlers::bootstrap_page).post(handlers::bootstrap),
        )
        .route("/login", get(handlers::login_page).post(handlers::login))
        .route("/logout", post(handlers::logout))
        .route(
            "/projects",
            get(handlers::projects).post(handlers::create_project),
        )
        .route("/projects/{slug}", get(handlers::project))
        .route("/projects/{slug}/members", post(handlers::create_member))
        .route("/projects/{slug}/keys", post(handlers::create_ingest_key))
        .route(
            "/projects/{slug}/keys/{key_id}/revoke",
            post(handlers::revoke_ingest_key),
        )
        .route("/projects/{slug}/issues/{issue_id}", get(handlers::issue))
        .route(
            "/projects/{slug}/issues/{issue_id}/export.md",
            get(handlers::export_issue_markdown),
        )
        .route(
            "/projects/{slug}/issues/{issue_id}/status",
            post(handlers::change_issue_status),
        )
        .route(
            "/projects/{slug}/issues/{issue_id}/comments",
            post(handlers::add_comment),
        )
        .route(
            "/projects/{slug}/issues/{issue_id}/resolve",
            post(handlers::resolve_issue),
        )
        .route(
            "/projects/{slug}/issues/{issue_id}/reopen",
            post(handlers::reopen_issue),
        )
        .route(
            "/projects/{slug}/issues/{issue_id}/tags",
            post(handlers::update_issue_tags_form),
        )
        .route("/settings", get(handlers::settings))
        .route("/settings/password", post(handlers::change_password))
        .route(
            "/settings/sessions/revoke-others",
            post(handlers::revoke_other_sessions),
        )
        .route(
            "/settings/sessions/{session_id}/revoke",
            post(handlers::revoke_session),
        )
        .route(
            "/projects/{slug}/notifications/webhooks",
            post(handlers::create_webhook),
        )
        .route(
            "/projects/{slug}/notifications/webhooks/{webhook_id}/delete",
            post(handlers::delete_webhook),
        )
        .route("/api/v1/projects/{slug}/events", post(handlers::ingest))
        .route("/api/v1/projects/{slug}/issues", get(handlers::list_issues))
        .route(
            "/api/v1/projects/{slug}/issues/{issue_id}",
            get(handlers::get_issue),
        )
        .route(
            "/api/v1/projects/{slug}/issues/{issue_id}/tags",
            put(handlers::update_issue_tags),
        )
        .route("/settings/tokens", post(handlers::create_api_token))
        .route(
            "/settings/tokens/{token_id}/revoke",
            post(handlers::revoke_api_token),
        )
        .route("/health", get(handlers::health))
        .route("/ready", get(handlers::ready))
        .route("/static/{*path}", get(handlers::static_asset))
        .layer(middleware::from_fn(security_headers))
        .layer(CookieManagerLayer::new())
        .with_state(state);

    // Merged after the security layer so the documentation routes receive their
    // own, relaxed CSP instead of the application-wide policy.
    #[cfg(feature = "docs")]
    let app = app.merge(openapi::docs_router());

    app
}

pub async fn run() -> AppResult<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zbierak=info".into()),
        )
        .init();

    let config = Arc::new(Config::from_env()?);
    let db = db::connect(&config.database_url).await?;
    let templates = Arc::new(load_templates(&config.template_dir)?);
    let state = AppState {
        config: config.clone(),
        db,
        templates,
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?,
        resolver: Arc::new(net_policy::SystemResolver),
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let worker = tokio::spawn(outbox::run(state.clone(), shutdown_rx));
    let listener = TcpListener::bind(config.bind).await?;
    tracing::info!(address = %config.bind, "server listening");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    let _ = shutdown_tx.send(true);
    let _ = worker.await;
    Ok(())
}

fn load_templates(directory: &std::path::Path) -> AppResult<Tera> {
    let pattern = format!("{}/**/*.html", directory.display());
    let tera = Tera::new(&pattern)?;
    for name in [
        "base.html",
        "login.html",
        "bootstrap.html",
        "projects.html",
        "project.html",
        "issue.html",
        "settings.html",
        "error.html",
    ] {
        tera.get_template(name).map_err(|_| {
            AppError::Config(format!(
                "required template {}/{name} is missing",
                directory.display()
            ))
        })?;
    }
    Ok(tera)
}

async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
        ),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    response
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = terminate => {} }
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use sqlx::sqlite::SqlitePoolOptions;
    use tower::ServiceExt;

    use super::{AppState, Config, router};

    #[tokio::test]
    async fn ingest_route_persists_and_groups_an_event() {
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, email, display_name, password_hash)
             VALUES (1, 'owner@example.com', 'Owner', 'unused')",
        )
        .execute(&db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO projects (id, slug, name, created_by) VALUES (1, 'demo', 'Demo', 1)",
        )
        .execute(&db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO ingest_keys (project_id, name, key_prefix, key_hash, created_by)
             VALUES (1, 'test', 'zbk_test', ?, 1)",
        )
        .bind(crate::auth::token_hash("zbk_test_key"))
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
            templates: Arc::new(tera::Tera::default()),
            http: reqwest::Client::new(),
            resolver: std::sync::Arc::new(super::SystemResolver),
        };
        sqlx::query(
            "INSERT INTO notification_endpoints
             (project_id, name, kind, url, secret, created_by)
             VALUES (1, 'test', 'webhook', 'https://example.com/hook', '0123456789abcdef', 1)",
        )
        .execute(&db)
        .await
        .unwrap();
        let app = router(state);
        let event = r#"{"event_id":"evt-1","timestamp":"2026-09-24T12:00:00Z","message":"boom"}"#;
        let request = || {
            Request::post("/api/v1/projects/demo/events")
                .header("authorization", "Bearer zbk_test_key")
                .header("content-type", "application/json")
                .body(Body::from(event))
                .unwrap()
        };

        let first = app.clone().oneshot(request()).await.unwrap();
        let duplicate = app.oneshot(request()).await.unwrap();

        assert_eq!(first.status(), StatusCode::ACCEPTED);
        assert_eq!(duplicate.status(), StatusCode::ACCEPTED);
        let duplicate_body: serde_json::Value =
            serde_json::from_slice(&duplicate.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(duplicate_body["id"], "evt-1");
        assert_eq!(duplicate_body["duplicate"], true);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM raw_events")
                .fetch_one(&db)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT event_count FROM issues")
                .fetch_one(&db)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM events")
                .fetch_one(&db)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM outbox")
                .fetch_one(&db)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM issues")
                .fetch_one(&db)
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn ingest_validation_failures_return_json_422() {
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, email, display_name, password_hash)
             VALUES (1, 'owner@example.com', 'Owner', 'unused')",
        )
        .execute(&db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO projects (id, slug, name, created_by) VALUES (1, 'demo', 'Demo', 1)",
        )
        .execute(&db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO ingest_keys (project_id, name, key_prefix, key_hash, created_by)
             VALUES (1, 'test', 'zbk_test', ?, 1)",
        )
        .bind(crate::auth::token_hash("zbk_test_key"))
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
            db,
            templates: Arc::new(tera::Tera::default()),
            http: reqwest::Client::new(),
            resolver: std::sync::Arc::new(super::SystemResolver),
        };
        let app = router(state);
        let invalid = r#"{"event_id":"evt-1","timestamp":"2026-09-24T12:00:00Z","message":""}"#;
        let response = app
            .oneshot(
                Request::post("/api/v1/projects/demo/events")
                    .header("authorization", "Bearer zbk_test_key")
                    .header("content-type", "application/json")
                    .body(Body::from(invalid))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["code"], "validation_failed");
        assert_eq!(body["field"], "message");
    }

    #[tokio::test]
    async fn project_roles_enforce_capability_levels() {
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        for (id, name) in [(1, "Owner"), (2, "Admin"), (3, "Developer"), (4, "Viewer")] {
            sqlx::query(
                "INSERT INTO users (id, email, display_name, password_hash) VALUES (?, ?, ?, 'unused')",
            )
            .bind(id)
            .bind(format!("{}@example.com", name.to_ascii_lowercase()))
            .bind(name)
            .execute(&db)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO projects (id, slug, name, created_by) VALUES (1, 'demo', 'Demo', 1)",
        )
        .execute(&db)
        .await
        .unwrap();
        for (user_id, role) in [(1, "owner"), (2, "admin"), (3, "developer"), (4, "viewer")] {
            sqlx::query(
                "INSERT INTO project_memberships (project_id, user_id, role) VALUES (1, ?, ?)",
            )
            .bind(user_id)
            .bind(role)
            .execute(&db)
            .await
            .unwrap();
        }
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
            resolver: std::sync::Arc::new(super::SystemResolver),
        };

        assert!(
            crate::auth::require_project_role(&state, 4, "demo", "viewer")
                .await
                .is_ok()
        );
        assert!(
            crate::auth::require_project_role(&state, 4, "demo", "developer")
                .await
                .is_err()
        );
        assert!(
            crate::auth::require_project_role(&state, 3, "demo", "developer")
                .await
                .is_ok()
        );
        assert!(
            crate::auth::require_project_role(&state, 3, "demo", "admin")
                .await
                .is_err()
        );
        assert!(
            crate::auth::require_project_role(&state, 2, "demo", "admin")
                .await
                .is_ok()
        );
        assert!(
            crate::auth::require_project_role(&state, 1, "demo", "owner")
                .await
                .is_ok()
        );
    }
}
