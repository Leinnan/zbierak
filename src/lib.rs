//! Zbierak: a self-hosted error and crash collection service.
//!
//! The binary serves an operator UI for issue triage and a versioned JSON
//! API (`/api/v1`) for event ingestion and issue management, backed by
//! SQLite. Events are grouped into issues by fingerprint, notifications are
//! delivered asynchronously through an outbox worker, and outbound webhook
//! destinations are validated against the destination policy.
//!
//! The externally re-exported items ([`Config`], [`AppState`], [`AppError`],
//! the authentication helpers, and the resolver types) support embedding the
//! server, testing, and operational tooling.

mod api_error;
mod assets;
mod audit;
mod auth;
mod avatars;
mod config;
mod db;
mod domain;
mod error;
pub mod extractors;
mod fingerprint;
mod handlers;
mod markdown;
mod net_policy;
pub use net_policy::{BoxResolveFuture, Resolver, SystemResolver, is_allowed_destination};
#[cfg(feature = "docs")]
mod openapi;
mod outbox;
mod secrets;
pub use secrets::{decrypt, encrypt, generate_key, parse_key};
mod tags;

use std::{env, future::Future, sync::Arc};

use axum::{
    Router,
    body::Body,
    extract::{DefaultBodyLimit, Request},
    http::{HeaderName, HeaderValue},
    middleware::{self, Next},
    response::Response,
    routing::{get, post, put},
};
use sqlx::SqlitePool;
use tera::Tera;
use tokio::{net::TcpListener, sync::watch};
use tower_cookies::CookieManagerLayer;

use extractors::FORM_BODY_LIMIT;

use crate::api_error::ApiError;

pub use auth::{hash_password, token_hash, verify_password};
pub use config::{AssetSource, Config};
pub use error::{AppError, AppResult};

/// Shared request state handed to every handler and background worker.
///
/// Every field is a cheap handle: configuration and templates are immutable
/// and shared through [`Arc`], the pool is internally shared, and the
/// resolver is a stateless trait object, so cloning `AppState` per request
/// copies only pointers.
#[derive(Clone)]
pub struct AppState {
    /// Runtime configuration loaded from the environment.
    pub config: Arc<Config>,
    /// SQLite connection pool with migrations already applied.
    pub db: SqlitePool,
    /// Rendered operator-UI templates.
    pub templates: Arc<Tera>,
    /// DNS strategy for outbound webhook destinations; injectable for tests.
    pub resolver: Arc<dyn net_policy::Resolver>,
}

fn ui_router() -> Router<AppState> {
    Router::new()
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
            "/projects/{slug}/issues/{issue_id}/comments/{comment_id}/edit",
            post(handlers::edit_comment_form),
        )
        .route(
            "/projects/{slug}/issues/{issue_id}/comments/{comment_id}/delete",
            post(handlers::delete_comment_form),
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
        .route("/users", get(handlers::users))
        .route("/users/{user_id}", get(handlers::user_profile))
        .route("/users/{user_id}/settings", get(handlers::user_settings))
        .route("/users/{user_id}/profile", post(handlers::update_profile))
        .route(
            "/users/{user_id}/avatar",
            get(handlers::serve_avatar).post(handlers::upload_avatar),
        )
        .route(
            "/users/{user_id}/avatar/delete",
            post(handlers::delete_avatar),
        )
        .route("/users/{user_id}/password", post(handlers::change_password))
        .route(
            "/users/{user_id}/sessions/revoke-others",
            post(handlers::revoke_other_sessions),
        )
        .route(
            "/users/{user_id}/sessions/{session_id}/revoke",
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
        .route("/settings/tokens", post(handlers::create_api_token))
        .route(
            "/settings/tokens/{token_id}/revoke",
            post(handlers::revoke_api_token),
        )
}

fn api_router() -> Router<AppState> {
    Router::new()
        .route("/projects/{slug}/events", post(handlers::ingest))
        .route("/projects/{slug}/issues", get(handlers::list_issues))
        .route(
            "/projects/{slug}/issues/{issue_id}",
            get(handlers::get_issue),
        )
        .route(
            "/projects/{slug}/issues/{issue_id}/tags",
            put(handlers::update_issue_tags).layer(DefaultBodyLimit::max(FORM_BODY_LIMIT)),
        )
        .route(
            "/projects/{slug}/issues/{issue_id}/comments",
            get(handlers::list_comments)
                .post(handlers::create_comment)
                .layer(DefaultBodyLimit::max(FORM_BODY_LIMIT)),
        )
        .route(
            "/projects/{slug}/issues/{issue_id}/comments/{comment_id}",
            put(handlers::update_comment)
                .delete(handlers::delete_comment)
                .layer(DefaultBodyLimit::max(FORM_BODY_LIMIT)),
        )
        .fallback(api_not_found)
        .method_not_allowed_fallback(api_method_not_allowed)
}

fn system_router() -> Router<AppState> {
    Router::new()
        .route("/health", get(handlers::health))
        .route("/ready", get(handlers::ready))
}

fn static_router() -> Router<AppState> {
    Router::new().route("/static/{*path}", get(handlers::static_asset))
}

async fn api_not_found() -> ApiError {
    ApiError(AppError::NotFound)
}

async fn api_method_not_allowed() -> ApiError {
    ApiError(AppError::MethodNotAllowed)
}

/// Builds the complete application router.
///
/// The operator UI, the versioned API (nested under `/api/v1` with JSON
/// fallbacks), the system endpoints, and the static assets each live in
/// their own subrouter so cookie handling, body limits, and fallback
/// behavior are scoped per surface. With the `docs` feature, the `OpenAPI`
/// document and Scalar UI are merged with their own relaxed CSP.
pub fn router(state: AppState) -> Router {
    let app = Router::new()
        .merge(
            ui_router()
                .layer(middleware::from_fn(security_headers))
                .layer(CookieManagerLayer::new())
                .layer(DefaultBodyLimit::max(FORM_BODY_LIMIT)),
        )
        .merge(
            Router::new()
                .nest("/api/v1", api_router())
                .layer(middleware::from_fn(security_headers)),
        )
        .merge(system_router().layer(middleware::from_fn(security_headers)))
        .merge(static_router().layer(middleware::from_fn(security_headers)))
        .with_state(state);

    // Merged after the security layer so the documentation routes receive their
    // own, relaxed CSP instead of the application-wide policy.
    #[cfg(feature = "docs")]
    let app = app.merge(openapi::docs_router());

    app
}

/// Installs the process-wide tracing subscriber.
///
/// Reads `RUST_LOG` (`EnvFilter` syntax). A missing variable selects the
/// default `zbierak=info`; a set-but-invalid value is reported on stderr and
/// also falls back to the default, so operators notice when their verbosity
/// setting is not taking effect instead of debugging a silent filter.
pub fn init_logging() {
    let default_filter = tracing_subscriber::EnvFilter::new("zbierak=info");
    let filter = match env::var("RUST_LOG") {
        Err(_) => default_filter,
        Ok(raw) => match tracing_subscriber::EnvFilter::try_new(raw) {
            Ok(filter) => filter,
            Err(error) => {
                eprintln!(
                    "zbierak: ignoring invalid RUST_LOG ({error}); using default zbierak=info"
                );
                default_filter
            }
        },
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

/// Runs the server binary: loads configuration, connects to the database,
/// renders the template check, and serves until shutdown.
///
/// Call [`init_logging`] first; this function logs the outcome of every
/// startup phase so a fatal error can be located from the journal alone.
///
/// # Errors
///
/// Returns an error when the environment configuration is invalid, the
/// database cannot be reached or migrated, required templates are missing,
/// or the listener cannot be bound.
pub async fn run() -> AppResult<()> {
    dotenvy::dotenv().ok();
    tracing::info!("starting zbierak {}", env!("CARGO_PKG_VERSION"));

    tracing::info!("loading configuration");
    let config = Arc::new(Config::from_env()?);
    tracing::info!(summary = %config.summary(), "configuration loaded");

    tracing::info!(database = %config.database_url, "connecting to database");
    let db = db::connect(&config.database_url).await?;
    tracing::info!("database ready (migrations applied)");

    tracing::info!(
        templates = %config.template_dir.describe(),
        "loading templates"
    );
    let templates = Arc::new(load_templates(&config.template_dir)?);
    let state = AppState {
        config: config.clone(),
        db,
        templates,
        resolver: Arc::new(net_policy::SystemResolver),
    };

    tracing::info!(address = %config.bind, "binding listener");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let worker = tokio::spawn(outbox::run(state.clone(), shutdown_rx));
    let listener = TcpListener::bind(config.bind).await?;
    tracing::info!(address = %config.bind, "server listening");
    let terminate = install_terminate_signal()?;
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal(terminate))
        .await?;
    tracing::info!("shutdown requested; stopping outbox worker");
    let _ = shutdown_tx.send(true);
    let _ = worker.await;
    tracing::info!("shutdown complete");
    Ok(())
}

/// Template names that must be present for the operator UI to render.
const REQUIRED_TEMPLATES: [&str; 11] = [
    "base.html",
    "login.html",
    "bootstrap.html",
    "projects.html",
    "project.html",
    "issue.html",
    "settings.html",
    "users.html",
    "user.html",
    "user_settings.html",
    "error.html",
];

/// Loads the operator-UI templates from the configured [`AssetSource`] and
/// registers the application's custom Tera filters.
///
/// Embedded assets ship inside the binary, so a bare deployment needs no
/// template directory on disk. Tera 2 removed the built-in `urlencode`
/// filter (formerly gated behind the `builtins` feature), so it is provided
/// here; templates rely on it to percent-encode tag values into
/// query-string links.
///
/// # Errors
///
/// Returns [`AppError::Config`] when a filesystem override fails to parse or
/// a required template is missing from the resolved source.
pub fn load_templates(source: &AssetSource) -> AppResult<Tera> {
    fn urlencode(value: &str, _: tera::Kwargs, _: &tera::State) -> String {
        let mut encoded = String::with_capacity(value.len());
        for byte in value.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    encoded.push(byte as char);
                }
                other => {
                    let _ = std::fmt::Write::write_fmt(&mut encoded, format_args!("%{other:02X}"));
                }
            }
        }
        encoded
    }

    let mut tera = Tera::new();
    tera.register_filter("urlencode", urlencode);
    match source {
        AssetSource::Directory(directory) => {
            let pattern = format!("{}/**/*.html", directory.display());
            tera.load_from_glob(&pattern)?;
        }
        AssetSource::Embedded => {
            // Bulk-insert everything before validation runs: base.html
            // includes fragments/* and imports components from
            // fragments/ui.html, and per-template registration would reject
            // those forward references.
            tera.add_raw_templates(assets::html_templates())?;
        }
    }
    for name in REQUIRED_TEMPLATES {
        if !tera.contains_template(name) {
            let location = match source {
                AssetSource::Directory(directory) => {
                    format!("{}/{name}", directory.display())
                }
                AssetSource::Embedded => format!("embedded templates ({name})"),
            };
            return Err(AppError::Config(format!(
                "required template {location} is missing"
            )));
        }
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

/// Future completing when the terminate signal fires.
type BoxShutdownSignal = std::pin::Pin<Box<dyn Future<Output = ()> + Send>>;

/// Registers the SIGTERM handler before serving so registration failures
/// abort startup instead of panicking mid-request. Returns the future that
/// completes when SIGTERM arrives.
#[cfg(unix)]
fn install_terminate_signal() -> AppResult<BoxShutdownSignal> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut terminate = signal(SignalKind::terminate()).map_err(AppError::Io)?;
    Ok(Box::pin(async move {
        terminate.recv().await;
    }))
}

#[cfg(not(unix))]
fn install_terminate_signal() -> AppResult<BoxShutdownSignal> {
    Ok(Box::pin(std::future::pending()))
}

/// Completes on Ctrl-C or SIGTERM, which triggers graceful shutdown.
async fn shutdown_signal(terminate: BoxShutdownSignal) {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };
    tokio::select! { () = ctrl_c => {}, () = terminate => {} }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use sqlx::sqlite::SqlitePoolOptions;
    use tower::ServiceExt;

    use super::{AppError, AppState, AssetSource, Config, router};

    fn test_state(db: sqlx::SqlitePool) -> AppState {
        AppState {
            config: Arc::new(Config {
                bind: "127.0.0.1:0".parse().unwrap(),
                database_url: "sqlite::memory:".into(),
                cookie_secure: false,
                session_days: 30,
                static_dir: AssetSource::Embedded,
                template_dir: AssetSource::Embedded,
                webhook_key: None,
            }),
            db,
            templates: Arc::new(tera::Tera::default()),
            resolver: Arc::new(super::SystemResolver),
        }
    }

    #[test]
    fn embedded_templates_load_into_tera() {
        let tera = super::load_templates(&AssetSource::Embedded).unwrap();
        for name in super::REQUIRED_TEMPLATES {
            assert!(tera.contains_template(name), "missing {name}");
        }
    }

    #[test]
    fn directory_templates_override_embedded() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("base.html"), "<html></html>").unwrap();
        let source = AssetSource::Directory(directory.path().to_path_buf());
        let result = super::load_templates(&source);
        assert!(
            matches!(&result, Err(AppError::Config(message))
                if message.contains("login.html") && message.contains("is missing")),
            "expected a missing-template error, got {result:?}"
        );
    }

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
        let state = test_state(db.clone());
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
        let state = test_state(db);
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
        let state = test_state(db);

        assert!(
            crate::auth::require_project_role(
                &state,
                4,
                "demo",
                crate::domain::ProjectRole::Viewer
            )
            .await
            .is_ok()
        );
        assert!(
            crate::auth::require_project_role(
                &state,
                4,
                "demo",
                crate::domain::ProjectRole::Developer
            )
            .await
            .is_err()
        );
        assert!(
            crate::auth::require_project_role(
                &state,
                3,
                "demo",
                crate::domain::ProjectRole::Developer
            )
            .await
            .is_ok()
        );
        assert!(
            crate::auth::require_project_role(&state, 3, "demo", crate::domain::ProjectRole::Admin)
                .await
                .is_err()
        );
        assert!(
            crate::auth::require_project_role(&state, 2, "demo", crate::domain::ProjectRole::Admin)
                .await
                .is_ok()
        );
        assert!(
            crate::auth::require_project_role(&state, 1, "demo", crate::domain::ProjectRole::Owner)
                .await
                .is_ok()
        );
    }
}
