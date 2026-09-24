use std::fmt::Write as _;
use std::path::{Component, Path};

use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Form, Path as AxumPath, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Row};
use tera::Context;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tower_cookies::{Cookie, Cookies};
use url::Url;
use uuid::Uuid;

use crate::{
    AppError, AppResult, AppState,
    api_error::ApiError,
    audit,
    auth::{self, User},
    fingerprint::event_fingerprint,
};

#[cfg(feature = "docs")]
use zbierak_protocol::ApiErrorResponse;

#[derive(Deserialize)]
pub struct BootstrapForm {
    email: String,
    display_name: String,
    password: String,
}

#[derive(Deserialize)]
pub struct LoginForm {
    #[serde(default)]
    csrf_token: String,
    email: String,
    password: String,
}

#[derive(Deserialize)]
pub struct CsrfForm {
    csrf_token: String,
}

#[derive(Deserialize)]
pub struct PasswordForm {
    csrf_token: String,
    current_password: String,
    new_password: String,
}

#[derive(Deserialize)]
pub struct ProjectForm {
    csrf_token: String,
    name: String,
    slug: Option<String>,
    description: Option<String>,
}

#[derive(Deserialize)]
pub struct KeyForm {
    csrf_token: String,
    name: String,
}

#[derive(Deserialize)]
pub struct MemberForm {
    csrf_token: String,
    email: String,
    display_name: String,
    password: String,
    role: String,
}

#[derive(Deserialize)]
pub struct StatusForm {
    csrf_token: String,
    status: String,
}

#[derive(Deserialize)]
pub struct CommentForm {
    csrf_token: String,
    body: String,
}

#[derive(Deserialize)]
pub struct WebhookForm {
    csrf_token: String,
    name: String,
    url: String,
    kind: String,
    secret: Option<String>,
}

#[derive(Deserialize)]
pub struct TokenForm {
    csrf_token: String,
    name: String,
}

#[derive(Deserialize)]
pub struct TagsForm {
    csrf_token: String,
    tags: String,
}

#[derive(Deserialize)]
pub struct ProjectQuery {
    /// Comma-separated tag filters; issues must carry every listed tag.
    tag: Option<String>,
}

#[derive(Deserialize)]
pub struct IssueListQuery {
    /// Comma-separated tag filters; issues must carry every listed tag.
    tag: Option<String>,
    status: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

#[cfg_attr(feature = "docs", derive(utoipa::ToSchema))]
#[derive(Deserialize)]
pub struct UpdateTagsPayload {
    /// Replacement tag set; an empty list removes all tags.
    pub tags: Vec<String>,
}

#[derive(Debug, Serialize, FromRow)]
struct ProjectRow {
    id: String,
    slug: String,
    name: String,
    role: String,
    created_at: i64,
    description: String,
    status: String,
    ingest_url: String,
}

#[derive(Debug, Serialize, FromRow)]
struct IssueRow {
    id: i64,
    title: String,
    status: String,
    event_count: i64,
    first_seen_at: i64,
    last_seen_at: i64,
    fingerprint: String,
}

#[derive(Debug, Serialize, FromRow)]
struct EventRow {
    id: String,
    payload_json: String,
    received_at: i64,
}

#[derive(Debug, Serialize)]
struct EventView {
    id: String,
    payload_json: String,
    occurred_at: String,
    occurred_at_iso: String,
    environment: String,
    release: Option<String>,
    user: Option<String>,
    context: String,
}

#[derive(Debug, Serialize, FromRow)]
struct CommentRow {
    id: i64,
    body: String,
    display_name: String,
    created_at: i64,
}

#[derive(Debug, Serialize, FromRow)]
struct EndpointRow {
    id: i64,
    name: String,
    kind: String,
    url: String,
    enabled: bool,
    project_slug: String,
}

#[derive(Debug, Serialize, FromRow)]
struct MemberRow {
    id: i64,
    email: String,
    display_name: String,
    role: String,
}

#[derive(Debug, Serialize, FromRow)]
struct KeyRow {
    id: i64,
    name: String,
    key_prefix: String,
    created_at: i64,
    last_used_at: Option<i64>,
}

#[derive(Debug, Serialize, FromRow)]
struct ApiTokenRow {
    id: i64,
    name: String,
    token_prefix: String,
    created_at: i64,
    last_used_at: Option<i64>,
}

/// Issue row used by listings; `tags` is filled in after the main query.
#[cfg_attr(feature = "docs", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize, FromRow)]
pub struct IssueJson {
    id: i64,
    title: String,
    status: String,
    event_count: i64,
    first_seen_at: i64,
    last_seen_at: i64,
    fingerprint: String,
    #[sqlx(skip)]
    tags: Vec<String>,
}

#[cfg_attr(feature = "docs", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub struct TagsResponse {
    tags: Vec<String>,
}

#[derive(Debug, Serialize, FromRow)]
struct ActivityRow {
    id: i64,
    kind: String,
    details_json: String,
    display_name: Option<String>,
    created_at: i64,
}

#[derive(Debug, Serialize, FromRow)]
struct SessionRow {
    id: i64,
    created_at: i64,
    expires_at: i64,
    is_current: bool,
}

pub async fn home(State(state): State<AppState>, cookies: Cookies) -> AppResult<Redirect> {
    if auth::session(&state, &cookies).await?.is_some() {
        return Ok(Redirect::to("/projects"));
    }
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&state.db)
        .await?;
    Ok(Redirect::to(if users == 0 {
        "/bootstrap"
    } else {
        "/login"
    }))
}

pub async fn bootstrap_page(State(state): State<AppState>) -> AppResult<Html<String>> {
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&state.db)
        .await?;
    if users != 0 {
        return Err(AppError::NotFound);
    }
    render(&state, "bootstrap.html", Context::new())
}

pub async fn bootstrap(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<BootstrapForm>,
) -> AppResult<Redirect> {
    validate_identity(&form.email, &form.display_name)?;
    let password_hash = auth::hash_password(&form.password)?;
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO bootstrap_lock (id, touched_at) VALUES (1, unixepoch())
         ON CONFLICT(id) DO UPDATE SET touched_at = unixepoch()",
    )
    .execute(&mut *tx)
    .await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&mut *tx)
        .await?;
    if count != 0 {
        return Err(AppError::NotFound);
    }
    let user_id = sqlx::query(
        "INSERT INTO users (email, display_name, password_hash) VALUES (?, ?, ?) RETURNING id",
    )
    .bind(form.email.trim().to_ascii_lowercase())
    .bind(form.display_name.trim())
    .bind(password_hash)
    .fetch_one(&mut *tx)
    .await?
    .get::<i64, _>(0);
    tx.commit().await?;
    auth::create_session(&state, &cookies, user_id).await?;
    Ok(Redirect::to("/projects"))
}

pub async fn login_page(
    State(state): State<AppState>,
    cookies: Cookies,
) -> AppResult<Html<String>> {
    // Double-submit CSRF: the anonymous cookie value must round-trip through
    // the rendered form, so a cross-site post cannot guess it.
    let token = auth::random_token(24);
    let cookie = Cookie::build((auth::LOGIN_CSRF_COOKIE, token.clone()))
        .path("/login")
        .http_only(true)
        .same_site(tower_cookies::cookie::SameSite::Lax)
        .build();
    cookies.add(cookie);
    let mut context = Context::new();
    context.insert("csrf_token", &token);
    render(&state, "login.html", context)
}

pub async fn login(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<LoginForm>,
) -> AppResult<Redirect> {
    let cookie_token = cookies
        .get(auth::LOGIN_CSRF_COOKIE)
        .map(|cookie| cookie.value().to_owned())
        .unwrap_or_default();
    if !auth::secure_eq(&cookie_token, &form.csrf_token) || cookie_token.is_empty() {
        return Err(AppError::Forbidden);
    }
    if auth::login_locked(&state, &form.email).await? {
        return Err(AppError::Unauthorized);
    }
    let row = sqlx::query_as::<_, (i64, String)>(
        "SELECT id, password_hash FROM users WHERE email = ? COLLATE NOCASE",
    )
    .bind(form.email.trim())
    .fetch_optional(&state.db)
    .await?;
    let Some((user_id, hash)) = row else {
        auth::login_failure(&state, &form.email).await?;
        audit::record(
            &state.db,
            None,
            "user.login_failed",
            Some("identity"),
            Some(auth::token_hash(&form.email.trim().to_ascii_lowercase())),
            json!({ "reason": "unknown_email" }),
        )
        .await?;
        return Err(AppError::Unauthorized);
    };
    if !auth::verify_password(&form.password, &hash) {
        auth::login_failure(&state, &form.email).await?;
        audit::record(
            &state.db,
            Some(user_id),
            "user.login_failed",
            Some("user"),
            Some(user_id.to_string()),
            json!({ "reason": "wrong_password" }),
        )
        .await?;
        return Err(AppError::Unauthorized);
    }
    auth::login_success(&state, &form.email).await?;
    auth::create_session(&state, &cookies, user_id).await?;
    audit::record(
        &state.db,
        Some(user_id),
        "user.login",
        Some("user"),
        Some(user_id.to_string()),
        json!({}),
    )
    .await?;
    Ok(Redirect::to("/projects"))
}

pub async fn logout(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<CsrfForm>,
) -> AppResult<Redirect> {
    let session = auth::require_session(&state, &cookies).await?;
    auth::check_csrf(&session, &form.csrf_token)?;
    auth::destroy_session(&state, &cookies).await?;
    Ok(Redirect::to("/login"))
}

pub async fn projects(State(state): State<AppState>, cookies: Cookies) -> AppResult<Html<String>> {
    let session = auth::require_session(&state, &cookies).await?;
    let projects = sqlx::query_as::<_, ProjectRow>(
        "SELECT p.slug AS id, p.slug, p.name, m.role, p.created_at, p.description, p.status,
                '/api/v1/projects/' || p.slug || '/events' AS ingest_url FROM projects p
         JOIN project_memberships m ON m.project_id = p.id WHERE m.user_id = ? ORDER BY p.name",
    )
    .bind(session.user.id)
    .fetch_all(&state.db)
    .await?;
    let mut context = page_context(&session.user, &session.csrf_token);
    context.insert("projects", &projects);
    render(&state, "projects.html", context)
}

pub async fn create_project(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<ProjectForm>,
) -> AppResult<Redirect> {
    let session = auth::require_session(&state, &cookies).await?;
    auth::check_csrf(&session, &form.csrf_token)?;
    let name = required_text("name", &form.name, 100)?;
    let slug = form
        .slug
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| slugify(name));
    validate_slug(&slug)?;
    let description = form.description.as_deref().unwrap_or("").trim();
    if description.chars().count() > 240 {
        return Err(AppError::BadRequest(
            "description must contain at most 240 characters".into(),
        ));
    }
    let mut tx = state.db.begin().await?;
    let project_id =
        sqlx::query("INSERT INTO projects (slug, name, description, created_by) VALUES (?, ?, ?, ?) RETURNING id")
            .bind(&slug)
            .bind(name)
            .bind(description)
            .bind(session.user.id)
            .fetch_one(&mut *tx)
            .await?
            .get::<i64, _>(0);
    sqlx::query(
        "INSERT INTO project_memberships (project_id, user_id, role) VALUES (?, ?, 'owner')",
    )
    .bind(project_id)
    .bind(session.user.id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Redirect::to(&format!("/projects/{slug}")))
}

pub async fn project(
    State(state): State<AppState>,
    cookies: Cookies,
    AxumPath(slug): AxumPath<String>,
    Query(query): Query<ProjectQuery>,
) -> AppResult<Html<String>> {
    let session = auth::require_session(&state, &cookies).await?;
    let project_id = auth::require_project_role(&state, session.user.id, &slug, "viewer").await?;
    let project = sqlx::query_as::<_, ProjectRow>(
        "SELECT p.slug AS id, p.slug, p.name, m.role, p.created_at, p.description, p.status,
                '/api/v1/projects/' || p.slug || '/events' AS ingest_url FROM projects p
         JOIN project_memberships m ON m.project_id=p.id WHERE p.id=? AND m.user_id=?",
    )
    .bind(project_id)
    .bind(session.user.id)
    .fetch_one(&state.db)
    .await?;
    let filter_tags = filter_tags(query.tag.as_deref())?;
    let issues = fetch_issues(&state.db, project_id, &filter_tags, None, 100, 0).await?;
    let project_tags = project_tag_list(&state.db, project_id).await?;
    let can_manage = auth::role_rank(&project.role) >= auth::role_rank("admin");
    let keys = if can_manage {
        sqlx::query_as::<_, KeyRow>(
            "SELECT id, name, key_prefix, created_at, last_used_at FROM ingest_keys
             WHERE project_id=? AND revoked_at IS NULL ORDER BY created_at DESC",
        )
        .bind(project_id)
        .fetch_all(&state.db)
        .await?
    } else {
        Vec::new()
    };
    let endpoints = if can_manage {
        sqlx::query_as::<_, EndpointRow>(
            "SELECT n.id, n.name, n.kind, n.url, n.enabled, p.slug AS project_slug
             FROM notification_endpoints n JOIN projects p ON p.id=n.project_id
             WHERE n.project_id=? ORDER BY n.created_at DESC",
        )
        .bind(project_id)
        .fetch_all(&state.db)
        .await?
    } else {
        Vec::new()
    };
    let members = if can_manage {
        sqlx::query_as::<_, MemberRow>(
            "SELECT u.id, u.email, u.display_name, m.role FROM project_memberships m
             JOIN users u ON u.id=m.user_id WHERE m.project_id=? ORDER BY u.display_name",
        )
        .bind(project_id)
        .fetch_all(&state.db)
        .await?
    } else {
        Vec::new()
    };
    let mut context = page_context(&session.user, &session.csrf_token);
    context.insert("project", &project);
    context.insert("issues", &issues);
    context.insert("project_tags", &project_tags);
    context.insert("filter_tags", &filter_tags);
    context.insert("ingest_keys", &keys);
    context.insert("members", &members);
    context.insert("notification_endpoints", &endpoints);
    render(&state, "project.html", context)
}

pub async fn create_member(
    State(state): State<AppState>,
    cookies: Cookies,
    AxumPath(slug): AxumPath<String>,
    Form(form): Form<MemberForm>,
) -> AppResult<Redirect> {
    let session = auth::require_session(&state, &cookies).await?;
    auth::check_csrf(&session, &form.csrf_token)?;
    let project_id = auth::require_project_role(&state, session.user.id, &slug, "admin").await?;
    if !matches!(
        form.role.as_str(),
        "owner" | "admin" | "developer" | "viewer"
    ) {
        return Err(AppError::BadRequest(
            "role must be owner, admin, developer, or viewer".into(),
        ));
    }
    let actor_role: String =
        sqlx::query_scalar("SELECT role FROM project_memberships WHERE project_id=? AND user_id=?")
            .bind(project_id)
            .bind(session.user.id)
            .fetch_one(&state.db)
            .await?;
    if actor_role != "owner" && auth::role_rank(&form.role) >= auth::role_rank("admin") {
        return Err(AppError::Forbidden);
    }
    validate_identity(&form.email, &form.display_name)?;
    let email = form.email.trim().to_ascii_lowercase();
    let mut tx = state.db.begin().await?;
    let existing =
        sqlx::query_scalar::<_, i64>("SELECT id FROM users WHERE email=? COLLATE NOCASE")
            .bind(&email)
            .fetch_optional(&mut *tx)
            .await?;
    let user_id = match existing {
        Some(id) => id,
        None => {
            let password_hash = auth::hash_password(&form.password)?;
            sqlx::query(
                "INSERT INTO users (email, display_name, password_hash) VALUES (?, ?, ?) RETURNING id",
            )
            .bind(email)
            .bind(form.display_name.trim())
            .bind(password_hash)
            .fetch_one(&mut *tx)
            .await?
            .get::<i64, _>(0)
        }
    };
    let target_role = sqlx::query_scalar::<_, String>(
        "SELECT role FROM project_memberships WHERE project_id=? AND user_id=?",
    )
    .bind(project_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    if actor_role != "owner"
        && target_role
            .as_deref()
            .is_some_and(|role| auth::role_rank(role) >= auth::role_rank("admin"))
    {
        return Err(AppError::Forbidden);
    }
    if user_id == session.user.id && form.role != "owner" {
        return Err(AppError::BadRequest(
            "an owner cannot demote their own membership".into(),
        ));
    }
    sqlx::query(
        "INSERT INTO project_memberships (project_id, user_id, role) VALUES (?, ?, ?)
         ON CONFLICT(project_id, user_id) DO UPDATE SET role=excluded.role",
    )
    .bind(project_id)
    .bind(user_id)
    .bind(form.role)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Redirect::to(&format!("/projects/{slug}")))
}

pub async fn create_ingest_key(
    State(state): State<AppState>,
    cookies: Cookies,
    AxumPath(slug): AxumPath<String>,
    Form(form): Form<KeyForm>,
) -> AppResult<Html<String>> {
    let session = auth::require_session(&state, &cookies).await?;
    auth::check_csrf(&session, &form.csrf_token)?;
    let project_id = auth::require_project_role(&state, session.user.id, &slug, "admin").await?;
    let name = required_text("name", &form.name, 100)?;
    let key = format!("zbk_{}", auth::random_token(32));
    sqlx::query(
        "INSERT INTO ingest_keys (project_id, name, key_prefix, key_hash, created_by)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(project_id)
    .bind(name)
    .bind(&key[..12])
    .bind(auth::token_hash(&key))
    .bind(session.user.id)
    .execute(&state.db)
    .await?;
    let project = sqlx::query_as::<_, ProjectRow>(
        "SELECT p.slug AS id, p.slug, p.name, m.role, p.created_at, p.description, p.status,
                '/api/v1/projects/' || p.slug || '/events' AS ingest_url FROM projects p
         JOIN project_memberships m ON m.project_id=p.id WHERE p.id=? AND m.user_id=?",
    )
    .bind(project_id)
    .bind(session.user.id)
    .fetch_one(&state.db)
    .await?;
    let issues = fetch_issues(&state.db, project_id, &[], None, 100, 0).await?;
    let keys = sqlx::query_as::<_, KeyRow>(
        "SELECT id, name, key_prefix, created_at, last_used_at FROM ingest_keys
         WHERE project_id=? AND revoked_at IS NULL ORDER BY created_at DESC",
    )
    .bind(project_id)
    .fetch_all(&state.db)
    .await?;
    let members = sqlx::query_as::<_, MemberRow>(
        "SELECT u.id, u.email, u.display_name, m.role FROM project_memberships m
         JOIN users u ON u.id=m.user_id WHERE m.project_id=? ORDER BY u.display_name",
    )
    .bind(project_id)
    .fetch_all(&state.db)
    .await?;
    let endpoints = sqlx::query_as::<_, EndpointRow>(
        "SELECT n.id, n.name, n.kind, n.url, n.enabled, p.slug AS project_slug
         FROM notification_endpoints n JOIN projects p ON p.id=n.project_id
         WHERE n.project_id=? ORDER BY n.created_at DESC",
    )
    .bind(project_id)
    .fetch_all(&state.db)
    .await?;
    let mut context = page_context(&session.user, &session.csrf_token);
    context.insert("project", &project);
    context.insert("ingest_key", &key);
    context.insert("issues", &issues);
    context.insert("project_tags", &Vec::<String>::new());
    context.insert("filter_tags", &Vec::<String>::new());
    context.insert("ingest_keys", &keys);
    context.insert("members", &members);
    context.insert("notification_endpoints", &endpoints);
    render(&state, "project.html", context)
}

pub async fn revoke_ingest_key(
    State(state): State<AppState>,
    cookies: Cookies,
    AxumPath((slug, key_id)): AxumPath<(String, i64)>,
    Form(form): Form<CsrfForm>,
) -> AppResult<Redirect> {
    let session = auth::require_session(&state, &cookies).await?;
    auth::check_csrf(&session, &form.csrf_token)?;
    let project_id = auth::require_project_role(&state, session.user.id, &slug, "admin").await?;
    let result =
        sqlx::query("UPDATE ingest_keys SET revoked_at=unixepoch() WHERE id=? AND project_id=? AND revoked_at IS NULL")
            .bind(key_id)
            .bind(project_id)
            .execute(&state.db)
            .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    audit::record(
        &state.db,
        Some(session.user.id),
        "ingest_key.revoked",
        Some("ingest_key"),
        Some(key_id.to_string()),
        json!({ "project": slug }),
    )
    .await?;
    Ok(Redirect::to(&format!("/projects/{slug}")))
}

struct IssueDetails {
    project: ProjectRow,
    issue: Value,
    events: Vec<EventView>,
    comments: Vec<CommentRow>,
    activity: Vec<ActivityRow>,
}

async fn load_issue_details(
    state: &AppState,
    user_id: i64,
    slug: &str,
    issue_id: i64,
) -> AppResult<IssueDetails> {
    let project_id = auth::require_project_role(state, user_id, slug, "viewer").await?;
    let project = sqlx::query_as::<_, ProjectRow>(
        "SELECT p.slug AS id, p.slug, p.name, m.role, p.created_at, p.description, p.status,
                '/api/v1/projects/' || p.slug || '/events' AS ingest_url FROM projects p
         JOIN project_memberships m ON m.project_id=p.id WHERE p.id=? AND m.user_id=?",
    )
    .bind(project_id)
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;
    let issue = sqlx::query_as::<_, IssueRow>(
        "SELECT id, title, status, event_count, first_seen_at, last_seen_at, fingerprint FROM issues
         WHERE id=? AND project_id=?",
    )
    .bind(issue_id)
    .bind(project_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;
    let events = sqlx::query_as::<_, EventRow>(
        "SELECT r.producer_event_id AS id, e.payload_json, e.received_at FROM events e
         JOIN raw_events r ON r.id=e.id WHERE e.issue_id=? ORDER BY e.received_at DESC LIMIT 20",
    )
    .bind(issue_id)
    .fetch_all(&state.db)
    .await?;
    let event_views: Vec<EventView> = events.into_iter().map(event_view).collect();
    let comments = sqlx::query_as::<_, CommentRow>(
        "SELECT c.id, c.body, u.display_name, c.created_at FROM issue_comments c
         JOIN users u ON u.id=c.user_id WHERE c.issue_id=? ORDER BY c.created_at",
    )
    .bind(issue_id)
    .fetch_all(&state.db)
    .await?;
    let activity = sqlx::query_as::<_, ActivityRow>(
        "SELECT a.id, a.kind, a.details_json, u.display_name, a.created_at
         FROM issue_activity a LEFT JOIN users u ON u.id=a.user_id
         WHERE a.issue_id=? ORDER BY a.created_at DESC, a.id DESC",
    )
    .bind(issue_id)
    .fetch_all(&state.db)
    .await?;
    let mut issue_value = serde_json::to_value(&issue)
        .map_err(|error| AppError::BadRequest(format!("could not render issue: {error}")))?;
    if let Some(object) = issue_value.as_object_mut() {
        object.insert(
            "tags".into(),
            json!(tags_for_issue(&state.db, issue_id).await?),
        );
    }
    if let Some(latest) = event_views.first()
        && let Ok(payload) = serde_json::from_str::<Value>(&latest.payload_json)
        && let Some(object) = issue_value.as_object_mut()
    {
        object.insert(
            "message".into(),
            payload.get("message").cloned().unwrap_or(Value::Null),
        );
        object.insert(
            "severity".into(),
            payload
                .get("severity")
                .cloned()
                .unwrap_or_else(|| json!("error")),
        );
        object.insert(
            "environment".into(),
            payload.get("environment").cloned().unwrap_or(Value::Null),
        );
        object.insert(
            "release".into(),
            payload.get("release").cloned().unwrap_or(Value::Null),
        );
        object.insert("stacktrace".into(), json!(format_stacktrace(&payload)));
    }
    Ok(IssueDetails {
        project,
        issue: issue_value,
        events: event_views,
        comments,
        activity,
    })
}

/// Validates the comma-separated `?tag=` filter value.
fn filter_tags(raw: Option<&str>) -> AppResult<Vec<String>> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    crate::tags::normalize_comma_separated(raw)
        .map_err(|error| AppError::BadRequest(format!("tag filter {error}")))
}

/// Distinct tags across a project, used for the filter autocomplete.
async fn project_tag_list(db: &sqlx::SqlitePool, project_id: i64) -> AppResult<Vec<String>> {
    let tags = sqlx::query_scalar(
        "SELECT DISTINCT t.tag FROM issue_tags t JOIN issues i ON i.id=t.issue_id
         WHERE i.project_id=? ORDER BY t.tag LIMIT 200",
    )
    .bind(project_id)
    .fetch_all(db)
    .await?;
    Ok(tags)
}

async fn tags_for_issue<'e, E>(db: E, issue_id: i64) -> AppResult<Vec<String>>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let tags = sqlx::query_scalar("SELECT tag FROM issue_tags WHERE issue_id=? ORDER BY tag")
        .bind(issue_id)
        .fetch_all(db)
        .await?;
    Ok(tags)
}

/// Lists issues for a project, newest activity first, optionally narrowed to
/// a status and to issues carrying every one of the given tags.
async fn fetch_issues(
    db: &sqlx::SqlitePool,
    project_id: i64,
    tags: &[String],
    status: Option<&str>,
    limit: i64,
    offset: i64,
) -> AppResult<Vec<IssueJson>> {
    // Only `?` placeholders and fixed SQL fragments are appended; every
    // dynamic value flows through push_bind.
    let mut builder = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
        "SELECT id, title, status, event_count, first_seen_at, last_seen_at, fingerprint
         FROM issues i WHERE i.project_id=",
    );
    builder.push_bind(project_id);
    if let Some(status) = status {
        builder.push(" AND i.status=").push_bind(status);
    }
    if !tags.is_empty() {
        builder.push(
            " AND (SELECT count(DISTINCT t.tag) FROM issue_tags t
               WHERE t.issue_id=i.id AND t.tag IN (",
        );
        let mut separated = builder.separated(", ");
        for tag in tags {
            separated.push_bind(tag);
        }
        separated.push_unseparated(")) = ");
        builder.push_bind(tags.len() as i64);
    }
    builder
        .push(" ORDER BY i.last_seen_at DESC LIMIT ")
        .push_bind(limit)
        .push(" OFFSET ")
        .push_bind(offset);
    let mut issues = builder.build_query_as::<IssueJson>().fetch_all(db).await?;
    if !issues.is_empty() {
        let mut builder = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
            "SELECT issue_id, tag FROM issue_tags WHERE issue_id IN (",
        );
        let mut separated = builder.separated(", ");
        for issue in &issues {
            separated.push_bind(issue.id);
        }
        separated.push_unseparated(") ORDER BY tag");
        let rows = builder.build().fetch_all(db).await?;
        let mut by_issue: std::collections::HashMap<i64, Vec<String>> =
            std::collections::HashMap::new();
        for row in rows {
            by_issue
                .entry(row.get::<i64, _>(0))
                .or_default()
                .push(row.get::<String, _>(1));
        }
        for issue in &mut issues {
            if let Some(tags) = by_issue.remove(&issue.id) {
                issue.tags = tags;
            }
        }
    }
    Ok(issues)
}

/// Replaces the tag set of one issue and records the change as activity.
async fn replace_issue_tags(
    db: &sqlx::SqlitePool,
    project_id: i64,
    issue_id: i64,
    user_id: Option<i64>,
    tags: Vec<String>,
) -> AppResult<Vec<String>> {
    let mut tx = db.begin().await?;
    sqlx::query_scalar::<_, i64>("SELECT id FROM issues WHERE id=? AND project_id=?")
        .bind(issue_id)
        .bind(project_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(AppError::NotFound)?;
    let previous = tags_for_issue(&mut *tx, issue_id).await?;
    sqlx::query("DELETE FROM issue_tags WHERE issue_id=?")
        .bind(issue_id)
        .execute(&mut *tx)
        .await?;
    for tag in &tags {
        sqlx::query(
            "INSERT INTO issue_tags (issue_id, tag) VALUES (?, ?)
             ON CONFLICT(issue_id, tag) DO NOTHING",
        )
        .bind(issue_id)
        .bind(tag)
        .execute(&mut *tx)
        .await?;
    }
    if previous != tags {
        sqlx::query(
            "INSERT INTO issue_activity (issue_id, user_id, kind, details_json)
             VALUES (?, ?, 'tags', ?)",
        )
        .bind(issue_id)
        .bind(user_id)
        .bind(json!({ "from": previous, "to": tags }).to_string())
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    // Return the stored (sorted) set so API responses match list output.
    tags_for_issue(db, issue_id).await
}

pub async fn issue(
    State(state): State<AppState>,
    cookies: Cookies,
    AxumPath((slug, issue_id)): AxumPath<(String, i64)>,
) -> AppResult<Html<String>> {
    let session = auth::require_session(&state, &cookies).await?;
    let details = load_issue_details(&state, session.user.id, &slug, issue_id).await?;
    let mut context = page_context(&session.user, &session.csrf_token);
    context.insert("slug", &slug);
    context.insert("project", &details.project);
    context.insert("issue", &details.issue);
    context.insert("events", &details.events);
    context.insert("comments", &details.comments);
    context.insert("activity", &details.activity);
    render(&state, "issue.html", context)
}

pub async fn export_issue_markdown(
    State(state): State<AppState>,
    cookies: Cookies,
    AxumPath((slug, issue_id)): AxumPath<(String, i64)>,
) -> AppResult<Response> {
    let session = auth::require_session(&state, &cookies).await?;
    let details = load_issue_details(&state, session.user.id, &slug, issue_id).await?;
    let markdown = issue_markdown(&details);
    Ok((
        [(header::CONTENT_TYPE, "text/markdown; charset=utf-8")],
        markdown,
    )
        .into_response())
}

pub async fn change_issue_status(
    State(state): State<AppState>,
    cookies: Cookies,
    AxumPath((slug, issue_id)): AxumPath<(String, i64)>,
    Form(form): Form<StatusForm>,
) -> AppResult<Redirect> {
    set_issue_status(state, cookies, slug, issue_id, form.csrf_token, form.status).await
}

pub async fn resolve_issue(
    State(state): State<AppState>,
    cookies: Cookies,
    AxumPath((slug, issue_id)): AxumPath<(String, i64)>,
    Form(form): Form<CsrfForm>,
) -> AppResult<Redirect> {
    set_issue_status(
        state,
        cookies,
        slug,
        issue_id,
        form.csrf_token,
        "resolved".into(),
    )
    .await
}

pub async fn reopen_issue(
    State(state): State<AppState>,
    cookies: Cookies,
    AxumPath((slug, issue_id)): AxumPath<(String, i64)>,
    Form(form): Form<CsrfForm>,
) -> AppResult<Redirect> {
    set_issue_status(
        state,
        cookies,
        slug,
        issue_id,
        form.csrf_token,
        "unresolved".into(),
    )
    .await
}

async fn set_issue_status(
    state: AppState,
    cookies: Cookies,
    slug: String,
    issue_id: i64,
    csrf_token: String,
    status: String,
) -> AppResult<Redirect> {
    let session = auth::require_session(&state, &cookies).await?;
    auth::check_csrf(&session, &csrf_token)?;
    let project_id =
        auth::require_project_role(&state, session.user.id, &slug, "developer").await?;
    if !["unresolved", "resolved", "ignored"].contains(&status.as_str()) {
        return Err(AppError::BadRequest("invalid issue status".into()));
    }
    let mut tx = state.db.begin().await?;
    let old_status =
        sqlx::query_scalar::<_, String>("SELECT status FROM issues WHERE id=? AND project_id=?")
            .bind(issue_id)
            .bind(project_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(AppError::NotFound)?;
    if old_status != status {
        sqlx::query("UPDATE issues SET status=? WHERE id=? AND project_id=?")
            .bind(&status)
            .bind(issue_id)
            .bind(project_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO issue_activity (issue_id, user_id, kind, details_json)
             VALUES (?, ?, 'status', ?)",
        )
        .bind(issue_id)
        .bind(session.user.id)
        .bind(json!({ "from": old_status, "to": status }).to_string())
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(Redirect::to(&format!("/projects/{slug}/issues/{issue_id}")))
}

pub async fn add_comment(
    State(state): State<AppState>,
    cookies: Cookies,
    AxumPath((slug, issue_id)): AxumPath<(String, i64)>,
    Form(form): Form<CommentForm>,
) -> AppResult<Redirect> {
    let session = auth::require_session(&state, &cookies).await?;
    auth::check_csrf(&session, &form.csrf_token)?;
    let project_id =
        auth::require_project_role(&state, session.user.id, &slug, "developer").await?;
    let body = required_text("comment", &form.body, 10_000)?;
    let mut tx = state.db.begin().await?;
    let result = sqlx::query(
        "INSERT INTO issue_comments (issue_id, user_id, body)
         SELECT id, ?, ? FROM issues WHERE id=? AND project_id=?",
    )
    .bind(session.user.id)
    .bind(body)
    .bind(issue_id)
    .bind(project_id)
    .execute(&mut *tx)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    sqlx::query(
        "INSERT INTO issue_activity (issue_id, user_id, kind, details_json)
         VALUES (?, ?, 'comment', ?)",
    )
    .bind(issue_id)
    .bind(session.user.id)
    .bind(json!({ "body": body }).to_string())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Redirect::to(&format!("/projects/{slug}/issues/{issue_id}")))
}

pub async fn update_issue_tags_form(
    State(state): State<AppState>,
    cookies: Cookies,
    AxumPath((slug, issue_id)): AxumPath<(String, i64)>,
    Form(form): Form<TagsForm>,
) -> AppResult<Redirect> {
    let session = auth::require_session(&state, &cookies).await?;
    auth::check_csrf(&session, &form.csrf_token)?;
    let project_id =
        auth::require_project_role(&state, session.user.id, &slug, "developer").await?;
    let tags = crate::tags::normalize_comma_separated(&form.tags).map_err(AppError::BadRequest)?;
    replace_issue_tags(&state.db, project_id, issue_id, Some(session.user.id), tags).await?;
    Ok(Redirect::to(&format!("/projects/{slug}/issues/{issue_id}")))
}

async fn settings_context(
    state: &AppState,
    session: &auth::Session,
    current_session_hash: Option<String>,
) -> AppResult<Context> {
    let projects = sqlx::query_as::<_, ProjectRow>(
        "SELECT p.slug AS id, p.slug, p.name, m.role, p.created_at, p.description, p.status,
                '/api/v1/projects/' || p.slug || '/events' AS ingest_url FROM projects p
         JOIN project_memberships m ON m.project_id=p.id
         WHERE m.user_id=? AND m.role IN ('owner', 'admin') ORDER BY p.name",
    )
    .bind(session.user.id)
    .fetch_all(&state.db)
    .await?;
    let endpoints = sqlx::query_as::<_, EndpointRow>(
        "SELECT n.id, n.name, n.kind, n.url, n.enabled, p.slug AS project_slug
         FROM notification_endpoints n JOIN projects p ON p.id=n.project_id
         JOIN project_memberships m ON m.project_id=n.project_id
         WHERE m.user_id=? AND m.role IN ('owner', 'admin') ORDER BY n.created_at DESC",
    )
    .bind(session.user.id)
    .fetch_all(&state.db)
    .await?;
    let mut context = page_context(&session.user, &session.csrf_token);
    context.insert("projects", &projects);
    context.insert("notification_endpoints", &endpoints);
    let sessions = sqlx::query_as::<_, SessionRow>(
        "SELECT id, created_at, expires_at, (token_hash = ?) AS is_current FROM sessions
         WHERE user_id=? AND expires_at > unixepoch() ORDER BY created_at DESC",
    )
    .bind(current_session_hash.unwrap_or_default())
    .bind(session.user.id)
    .fetch_all(&state.db)
    .await?;
    context.insert("sessions", &sessions);
    let api_tokens = sqlx::query_as::<_, ApiTokenRow>(
        "SELECT id, name, token_prefix, created_at, last_used_at FROM api_tokens
         WHERE user_id=? AND revoked_at IS NULL ORDER BY created_at DESC",
    )
    .bind(session.user.id)
    .fetch_all(&state.db)
    .await?;
    context.insert("api_tokens", &api_tokens);
    Ok(context)
}

pub async fn settings(State(state): State<AppState>, cookies: Cookies) -> AppResult<Html<String>> {
    let session = auth::require_session(&state, &cookies).await?;
    let current_hash = cookies
        .get(auth::SESSION_COOKIE)
        .map(|cookie| auth::token_hash(cookie.value()));
    let context = settings_context(&state, &session, current_hash).await?;
    render(&state, "settings.html", context)
}

pub async fn create_api_token(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<TokenForm>,
) -> AppResult<Html<String>> {
    let session = auth::require_session(&state, &cookies).await?;
    auth::check_csrf(&session, &form.csrf_token)?;
    let name = required_text("name", &form.name, 100)?;
    let token = format!("{}{}", auth::API_TOKEN_PREFIX, auth::random_token(32));
    sqlx::query(
        "INSERT INTO api_tokens (user_id, name, token_prefix, token_hash) VALUES (?, ?, ?, ?)",
    )
    .bind(session.user.id)
    .bind(name)
    .bind(&token[..auth::API_TOKEN_PREFIX.len() + 6])
    .bind(auth::token_hash(&token))
    .execute(&state.db)
    .await?;
    audit::record(
        &state.db,
        Some(session.user.id),
        "api_token.created",
        Some("api_token"),
        None,
        json!({}),
    )
    .await?;
    let current_hash = cookies
        .get(auth::SESSION_COOKIE)
        .map(|cookie| auth::token_hash(cookie.value()));
    let mut context = settings_context(&state, &session, current_hash).await?;
    context.insert("new_api_token", &token);
    render(&state, "settings.html", context)
}

pub async fn revoke_api_token(
    State(state): State<AppState>,
    cookies: Cookies,
    AxumPath(token_id): AxumPath<i64>,
    Form(form): Form<CsrfForm>,
) -> AppResult<Redirect> {
    let session = auth::require_session(&state, &cookies).await?;
    auth::check_csrf(&session, &form.csrf_token)?;
    sqlx::query(
        "UPDATE api_tokens SET revoked_at=unixepoch() WHERE id=? AND user_id=? AND revoked_at IS NULL",
    )
    .bind(token_id)
    .bind(session.user.id)
    .execute(&state.db)
    .await?;
    audit::record(
        &state.db,
        Some(session.user.id),
        "api_token.revoked",
        Some("api_token"),
        Some(token_id.to_string()),
        json!({}),
    )
    .await?;
    Ok(Redirect::to("/settings"))
}

pub async fn change_password(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<PasswordForm>,
) -> AppResult<Redirect> {
    let session = auth::require_session(&state, &cookies).await?;
    auth::check_csrf(&session, &form.csrf_token)?;
    let hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id=?")
        .bind(session.user.id)
        .fetch_one(&state.db)
        .await?;
    if !auth::verify_password(&form.current_password, &hash) {
        return Err(AppError::Unauthorized);
    }
    let new_hash = auth::hash_password(&form.new_password)?;
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE users SET password_hash=? WHERE id=?")
        .bind(&new_hash)
        .bind(session.user.id)
        .execute(&mut *tx)
        .await?;
    // Keep the current session alive, but evict every other one so a stolen
    // credential cannot survive a rotation.
    let current = cookies
        .get(auth::SESSION_COOKIE)
        .map(|cookie| auth::token_hash(cookie.value()))
        .unwrap_or_default();
    sqlx::query("DELETE FROM sessions WHERE user_id=? AND token_hash != ?")
        .bind(session.user.id)
        .bind(current)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    audit::record(
        &state.db,
        Some(session.user.id),
        "user.password_changed",
        Some("user"),
        Some(session.user.id.to_string()),
        json!({ "email": session.user.email }),
    )
    .await?;
    Ok(Redirect::to("/settings"))
}

pub async fn revoke_other_sessions(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<CsrfForm>,
) -> AppResult<Redirect> {
    let session = auth::require_session(&state, &cookies).await?;
    auth::check_csrf(&session, &form.csrf_token)?;
    let current = cookies
        .get(auth::SESSION_COOKIE)
        .map(|cookie| auth::token_hash(cookie.value()))
        .unwrap_or_default();
    sqlx::query("DELETE FROM sessions WHERE user_id=? AND token_hash != ?")
        .bind(session.user.id)
        .bind(current)
        .execute(&state.db)
        .await?;
    audit::record(
        &state.db,
        Some(session.user.id),
        "user.sessions_revoked_others",
        Some("user"),
        Some(session.user.id.to_string()),
        json!({}),
    )
    .await?;
    Ok(Redirect::to("/settings"))
}

pub async fn revoke_session(
    State(state): State<AppState>,
    cookies: Cookies,
    AxumPath(session_id): AxumPath<i64>,
    Form(form): Form<CsrfForm>,
) -> AppResult<Redirect> {
    let session = auth::require_session(&state, &cookies).await?;
    auth::check_csrf(&session, &form.csrf_token)?;
    sqlx::query("DELETE FROM sessions WHERE id=? AND user_id=?")
        .bind(session_id)
        .bind(session.user.id)
        .execute(&state.db)
        .await?;
    audit::record(
        &state.db,
        Some(session.user.id),
        "user.session_revoked",
        Some("session"),
        Some(session_id.to_string()),
        json!({}),
    )
    .await?;
    Ok(Redirect::to("/settings"))
}

pub async fn create_webhook(
    State(state): State<AppState>,
    cookies: Cookies,
    AxumPath(slug): AxumPath<String>,
    Form(form): Form<WebhookForm>,
) -> AppResult<Redirect> {
    let session = auth::require_session(&state, &cookies).await?;
    auth::check_csrf(&session, &form.csrf_token)?;
    let project_id = auth::require_project_role(&state, session.user.id, &slug, "admin").await?;
    let name = required_text("name", &form.name, 100)?;
    let url =
        Url::parse(&form.url).map_err(|_| AppError::BadRequest("invalid webhook URL".into()))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(AppError::BadRequest(
            "webhook URL must be HTTP or HTTPS".into(),
        ));
    }
    if !matches!(form.kind.as_str(), "webhook" | "discord") {
        return Err(AppError::BadRequest("invalid webhook kind".into()));
    }
    if form.kind == "discord" {
        let host = url.host_str().unwrap_or_default();
        if url.scheme() != "https" || !matches!(host, "discord.com" | "discordapp.com") {
            return Err(AppError::BadRequest("invalid Discord webhook URL".into()));
        }
    }
    // Reject destinations that resolve only to internal addresses; delivery
    // re-resolves and pins the addresses it will contact.
    let default_port = if url.scheme() == "https" { 443 } else { 80 };
    crate::net_policy::resolve_allowed_with(
        url.host_str().unwrap_or_default(),
        url.port_or_known_default().unwrap_or(default_port),
        |host, port| state.resolver.resolve(host, port),
    )
    .await
    .map_err(|error| AppError::BadRequest(format!("webhook destination rejected: {error}")))?;
    let (secret, secret_encrypted) = if form.kind == "webhook" {
        let secret = required_text("webhook secret", form.secret.as_deref().unwrap_or(""), 1024)?;
        if secret.len() < 16 {
            return Err(AppError::BadRequest(
                "webhook secret must contain at least 16 characters".into(),
            ));
        }
        let key = state.config.webhook_key.ok_or_else(|| {
            AppError::BadRequest(
                "ZBIERAK_SECRET_KEY must be configured to store webhook signing secrets".into(),
            )
        })?;
        (Some(crate::secrets::encrypt(&key, secret)?), 1)
    } else {
        (None, 0)
    };
    sqlx::query(
        "INSERT INTO notification_endpoints (project_id, name, kind, url, secret, secret_encrypted, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(project_id)
    .bind(name)
    .bind(form.kind.clone())
    .bind(url.as_str())
    .bind(secret)
    .bind(secret_encrypted)
    .bind(session.user.id)
    .execute(&state.db)
    .await?;
    audit::record(
        &state.db,
        Some(session.user.id),
        "webhook.created",
        Some("notification_endpoint"),
        None,
        json!({ "project": slug, "kind": form.kind }),
    )
    .await?;
    Ok(Redirect::to("/settings"))
}

pub async fn delete_webhook(
    State(state): State<AppState>,
    cookies: Cookies,
    AxumPath((slug, webhook_id)): AxumPath<(String, i64)>,
    Form(form): Form<CsrfForm>,
) -> AppResult<Redirect> {
    let session = auth::require_session(&state, &cookies).await?;
    auth::check_csrf(&session, &form.csrf_token)?;
    let project_id = auth::require_project_role(&state, session.user.id, &slug, "admin").await?;
    let result = sqlx::query("DELETE FROM notification_endpoints WHERE id=? AND project_id=?")
        .bind(webhook_id)
        .bind(project_id)
        .execute(&state.db)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    audit::record(
        &state.db,
        Some(session.user.id),
        "webhook.deleted",
        Some("notification_endpoint"),
        Some(webhook_id.to_string()),
        json!({ "project": slug }),
    )
    .await?;
    Ok(Redirect::to("/settings"))
}

#[cfg_attr(feature = "docs", derive(utoipa::ToSchema))]
#[derive(Serialize)]
pub struct IngestResponse {
    id: String,
    issue_id: i64,
    fingerprint: String,
    duplicate: bool,
}

#[cfg_attr(feature = "docs", utoipa::path(
    post,
    path = "/api/v1/projects/{slug}/events",
    tag = "events",
    operation_id = "ingestEvent",
    params(("slug" = String, Path, description = "Project slug")),
    request_body = zbierak_protocol::Event,
    security(("bearer_auth" = [])),
    responses(
        (status = 202, description = "Event accepted, or an idempotent duplicate", body = IngestResponse),
        (status = 400, description = "Malformed request body", body = ApiErrorResponse),
        (status = 401, description = "Missing or invalid ingest key", body = ApiErrorResponse),
        (status = 409, description = "Event ID reused with different content", body = ApiErrorResponse),
        (status = 413, description = "Event body exceeds 1 MiB", body = ApiErrorResponse),
        (status = 422, description = "Event failed protocol validation", body = ApiErrorResponse),
    )
))]
pub async fn ingest(
    State(state): State<AppState>,
    AxumPath(slug): AxumPath<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    if body.len() > 1_048_576 {
        return Err(AppError::PayloadTooLarge("event exceeds 1 MiB".into()).into());
    }
    let bearer = auth::bearer(&headers)?;
    let key_hash = auth::token_hash(bearer);
    let key = sqlx::query_as::<_, (i64, i64)>(
        "SELECT k.id, k.project_id FROM ingest_keys k JOIN projects p ON p.id=k.project_id
         WHERE p.slug=? AND k.key_hash=? AND k.revoked_at IS NULL",
    )
    .bind(&slug)
    .bind(&key_hash)
    .fetch_optional(&state.db)
    .await?;
    let Some((key_id, project_id)) = key else {
        return Err(AppError::Unauthorized.into());
    };
    let event: zbierak_protocol::Event = serde_json::from_slice(&body)
        .map_err(|error| AppError::BadRequest(format!("invalid event: {error}")))?;
    event.validate().map_err(|error| AppError::Unprocessable {
        field: Some(error.field().to_owned()),
        message: error.message().to_owned(),
    })?;
    let value: Value = serde_json::from_slice(&body)
        .map_err(|error| AppError::BadRequest(format!("invalid JSON: {error}")))?;
    let fingerprint = event_fingerprint(&value);
    let title: String = event.message.chars().take(200).collect();
    let event_labels = crate::tags::labels_from_event_tags(&event.tags);
    let producer_event_id = event.event_id;
    let storage_id = Uuid::new_v4().to_string();
    let payload = String::from_utf8(body.to_vec())
        .map_err(|_| AppError::BadRequest("event body must be UTF-8 JSON".into()))?;
    let body_hash = Sha256::digest(body.as_ref())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut tx = state.db.begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO raw_events (id, project_id, ingest_key_id, body, producer_event_id, body_hash)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(project_id, producer_event_id) DO NOTHING",
    )
    .bind(&storage_id)
    .bind(project_id)
    .bind(key_id)
    .bind(body.as_ref())
    .bind(&producer_event_id)
    .bind(&body_hash)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    if !inserted {
        let (existing_hash, issue_id, existing_fingerprint) =
            sqlx::query_as::<_, (Option<String>, i64, String)>(
                "SELECT r.body_hash, e.issue_id, e.fingerprint FROM events e
             JOIN raw_events r ON r.id=e.id
             WHERE r.project_id=? AND r.producer_event_id=?",
            )
            .bind(project_id)
            .bind(&producer_event_id)
            .fetch_one(&mut *tx)
            .await?;
        if existing_hash
            .as_deref()
            .is_some_and(|stored| stored != body_hash)
        {
            return Err(AppError::Conflict(format!(
                "event_id {producer_event_id} was already ingested with different content"
            ))
            .into());
        }
        sqlx::query("UPDATE ingest_keys SET last_used_at=unixepoch() WHERE id=?")
            .bind(key_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Ok((
            StatusCode::ACCEPTED,
            Json(IngestResponse {
                id: producer_event_id,
                issue_id,
                fingerprint: existing_fingerprint,
                duplicate: true,
            }),
        ));
    }

    let existing_issue = sqlx::query_as::<_, (i64, String)>(
        "SELECT id, status FROM issues WHERE project_id=? AND fingerprint=?",
    )
    .bind(project_id)
    .bind(&fingerprint)
    .fetch_optional(&mut *tx)
    .await?;
    let (issue_id, notification_kind) = match existing_issue {
        Some((issue_id, status)) => {
            let regression = status == "resolved";
            sqlx::query(
                "UPDATE issues SET event_count=event_count+1, last_seen_at=unixepoch(),
                 status=CASE WHEN status='resolved' THEN 'unresolved' ELSE status END
                 WHERE id=?",
            )
            .bind(issue_id)
            .execute(&mut *tx)
            .await?;
            if regression {
                sqlx::query(
                    "INSERT INTO issue_activity (issue_id, kind, details_json)
                     VALUES (?, 'regression', ?)",
                )
                .bind(issue_id)
                .bind(json!({ "event_id": &producer_event_id }).to_string())
                .execute(&mut *tx)
                .await?;
            }
            (issue_id, regression.then_some("issue.regressed"))
        }
        None => {
            let issue_id = sqlx::query(
                "INSERT INTO issues (project_id, fingerprint, title) VALUES (?, ?, ?) RETURNING id",
            )
            .bind(project_id)
            .bind(&fingerprint)
            .bind(&title)
            .fetch_one(&mut *tx)
            .await?
            .get::<i64, _>(0);
            (issue_id, Some("issue.created"))
        }
    };
    // Event tags become flat issue labels. The first event seeds the set and
    // later occurrences only add new labels; removing tags is a manual act.
    if !event_labels.is_empty() {
        let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM issue_tags WHERE issue_id=?")
            .bind(issue_id)
            .fetch_one(&mut *tx)
            .await?;
        let mut room = crate::tags::MAX_TAGS as i64 - stored;
        for label in &event_labels {
            if room <= 0 {
                break;
            }
            let inserted = sqlx::query(
                "INSERT INTO issue_tags (issue_id, tag) VALUES (?, ?)
                 ON CONFLICT(issue_id, tag) DO NOTHING",
            )
            .bind(issue_id)
            .bind(label)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            room -= inserted as i64;
        }
    }
    sqlx::query(
        "INSERT INTO events (id, project_id, issue_id, fingerprint, payload_json) VALUES (?, ?, ?, ?, ?)",
    ).bind(&storage_id).bind(project_id).bind(issue_id).bind(&fingerprint).bind(&payload)
        .execute(&mut *tx).await?;
    sqlx::query("UPDATE ingest_keys SET last_used_at=unixepoch() WHERE id=?")
        .bind(key_id)
        .execute(&mut *tx)
        .await?;
    if let Some(notification_kind) = notification_kind {
        let notification = json!({
            "content": format!("{} in {slug}: {title}", if notification_kind == "issue.created" { "New issue" } else { "Issue regressed" }),
            "event": notification_kind, "project": slug, "issue_id": issue_id,
            "event_id": &producer_event_id, "fingerprint": &fingerprint, "title": &title,
        })
        .to_string();
        sqlx::query(
            "INSERT INTO outbox (endpoint_id, event_type, payload_json)
             SELECT id, ?, ? FROM notification_endpoints
             WHERE project_id=? AND enabled=1",
        )
        .bind(notification_kind)
        .bind(notification)
        .bind(project_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(IngestResponse {
            id: producer_event_id,
            issue_id,
            fingerprint,
            duplicate: false,
        }),
    ))
}

#[cfg_attr(feature = "docs", utoipa::path(
    get,
    path = "/api/v1/projects/{slug}/issues",
    tag = "issues",
    operation_id = "listIssues",
    params(
        ("slug" = String, Path, description = "Project slug"),
        ("tag" = Option<String>, Query, description = "Comma-separated tags; issues must carry every listed tag"),
        ("status" = Option<String>, Query, description = "unresolved, resolved, or ignored"),
        ("limit" = Option<u32>, Query, description = "Page size, 1-200 (default 50)"),
        ("offset" = Option<u32>, Query, description = "Number of issues to skip"),
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Issues ordered by most recent activity", body = [IssueJson]),
        (status = 400, description = "Invalid tag or status filter", body = ApiErrorResponse),
        (status = 401, description = "Missing or invalid API token", body = ApiErrorResponse),
        (status = 404, description = "Unknown project or no membership", body = ApiErrorResponse),
    )
))]
pub async fn list_issues(
    State(state): State<AppState>,
    AxumPath(slug): AxumPath<String>,
    headers: HeaderMap,
    Query(query): Query<IssueListQuery>,
) -> Result<Json<Vec<IssueJson>>, ApiError> {
    let user_id = auth::api_token_user(&state, &headers).await?;
    let project_id = auth::require_project_role(&state, user_id, &slug, "viewer").await?;
    if let Some(status) = query.status.as_deref()
        && !["unresolved", "resolved", "ignored"].contains(&status)
    {
        return Err(
            AppError::BadRequest("status must be unresolved, resolved, or ignored".into()).into(),
        );
    }
    let tags = filter_tags(query.tag.as_deref())?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = i64::from(query.offset.unwrap_or(0));
    let issues = fetch_issues(
        &state.db,
        project_id,
        &tags,
        query.status.as_deref(),
        i64::from(limit),
        offset,
    )
    .await?;
    Ok(Json(issues))
}

#[cfg_attr(feature = "docs", utoipa::path(
    get,
    path = "/api/v1/projects/{slug}/issues/{issue_id}",
    tag = "issues",
    operation_id = "getIssue",
    params(
        ("slug" = String, Path, description = "Project slug"),
        ("issue_id" = i64, Path, description = "Issue identifier"),
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "The issue including its tags", body = IssueJson),
        (status = 401, description = "Missing or invalid API token", body = ApiErrorResponse),
        (status = 404, description = "Unknown project, issue, or no membership", body = ApiErrorResponse),
    )
))]
pub async fn get_issue(
    State(state): State<AppState>,
    AxumPath((slug, issue_id)): AxumPath<(String, i64)>,
    headers: HeaderMap,
) -> Result<Json<IssueJson>, ApiError> {
    let user_id = auth::api_token_user(&state, &headers).await?;
    let project_id = auth::require_project_role(&state, user_id, &slug, "viewer").await?;
    let mut issue = sqlx::query_as::<_, IssueJson>(
        "SELECT id, title, status, event_count, first_seen_at, last_seen_at, fingerprint
         FROM issues WHERE id=? AND project_id=?",
    )
    .bind(issue_id)
    .bind(project_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;
    issue.tags = tags_for_issue(&state.db, issue_id).await?;
    Ok(Json(issue))
}

#[cfg_attr(feature = "docs", utoipa::path(
    put,
    path = "/api/v1/projects/{slug}/issues/{issue_id}/tags",
    tag = "issues",
    operation_id = "updateIssueTags",
    params(
        ("slug" = String, Path, description = "Project slug"),
        ("issue_id" = i64, Path, description = "Issue identifier"),
    ),
    request_body = UpdateTagsPayload,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Replacement tag set stored", body = TagsResponse),
        (status = 401, description = "Missing or invalid API token", body = ApiErrorResponse),
        (status = 403, description = "Token owner is only a viewer on this project", body = ApiErrorResponse),
        (status = 404, description = "Unknown project, issue, or no membership", body = ApiErrorResponse),
        (status = 422, description = "Tags failed validation", body = ApiErrorResponse),
    )
))]
pub async fn update_issue_tags(
    State(state): State<AppState>,
    AxumPath((slug, issue_id)): AxumPath<(String, i64)>,
    headers: HeaderMap,
    Json(payload): Json<UpdateTagsPayload>,
) -> Result<Json<TagsResponse>, ApiError> {
    let user_id = auth::api_token_user(&state, &headers).await?;
    let project_id = auth::require_project_role(&state, user_id, &slug, "developer").await?;
    let tags =
        crate::tags::normalize_tags(payload.tags.iter().map(String::as_str)).map_err(|error| {
            AppError::Unprocessable {
                field: Some("tags".into()),
                message: error,
            }
        })?;
    let tags = replace_issue_tags(&state.db, project_id, issue_id, Some(user_id), tags).await?;
    Ok(Json(TagsResponse { tags }))
}

#[cfg_attr(feature = "docs", utoipa::path(
    get,
    path = "/health",
    tag = "system",
    operation_id = "health",
    responses(
        (status = 200, description = "Process is alive", body = String, content_type = "text/plain")
    )
))]
pub async fn health() -> &'static str {
    "ok"
}

#[cfg_attr(feature = "docs", utoipa::path(
    get,
    path = "/ready",
    tag = "system",
    operation_id = "ready",
    responses(
        (status = 200, description = "Database is reachable", body = String, content_type = "text/plain"),
        (status = 500, description = "Database check failed", body = ApiErrorResponse)
    )
))]
pub async fn ready(State(state): State<AppState>) -> Result<&'static str, ApiError> {
    sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&state.db)
        .await?;
    Ok("ready")
}

pub async fn static_asset(
    State(state): State<AppState>,
    AxumPath(path): AxumPath<String>,
) -> AppResult<Response> {
    let path = Path::new(&path);
    if path
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(AppError::NotFound);
    }
    let full_path = state.config.static_dir.join(path);
    let bytes = tokio::fs::read(&full_path).await.map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            AppError::NotFound
        } else {
            error.into()
        }
    })?;
    let content_type = match full_path.extension().and_then(|ext| ext.to_str()) {
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    };
    let cache_control = if path.starts_with("vendor") {
        "public, max-age=31536000, immutable"
    } else {
        "public, max-age=3600"
    };
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, cache_control)
        .body(Body::from(bytes))
        .expect("valid static response"))
}

fn page_context(user: &User, csrf: &str) -> Context {
    let mut context = Context::new();
    context.insert("user", user);
    context.insert("user_name", &user.display_name);
    context.insert("user_email", &user.email);
    context.insert("app_name", "Zbierak");
    context.insert("csrf_token", csrf);
    context
}

fn render(state: &AppState, template: &str, context: Context) -> AppResult<Html<String>> {
    Ok(Html(state.templates.render(template, &context)?))
}

fn required_text<'a>(field: &str, value: &'a str, maximum: usize) -> AppResult<&'a str> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > maximum {
        return Err(AppError::BadRequest(format!(
            "{field} must contain 1 to {maximum} characters"
        )));
    }
    Ok(value)
}

fn validate_identity(email: &str, display_name: &str) -> AppResult<()> {
    required_text("display name", display_name, 100)?;
    let email = required_text("email", email, 254)?;
    if !email.contains('@') || email.chars().any(char::is_whitespace) {
        return Err(AppError::BadRequest("invalid email address".into()));
    }
    Ok(())
}

fn validate_slug(slug: &str) -> AppResult<()> {
    if slug.len() < 2
        || slug.len() > 50
        || !slug
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || slug.starts_with('-')
        || slug.ends_with('-')
    {
        return Err(AppError::BadRequest(
            "slug must use 2-50 lowercase letters, digits, or hyphens".into(),
        ));
    }
    Ok(())
}

fn slugify(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
        .chars()
        .take(50)
        .collect()
}

fn event_view(row: EventRow) -> EventView {
    let payload = serde_json::from_str::<Value>(&row.payload_json).unwrap_or(Value::Null);
    let occurred_at = payload
        .get("timestamp")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| row.received_at.to_string());
    let user = payload
        .get("user")
        .and_then(Value::as_object)
        .and_then(|user| {
            ["email", "username", "id"]
                .iter()
                .find_map(|key| user.get(*key).and_then(Value::as_str).map(str::to_owned))
        });
    let context = payload
        .get("contexts")
        .and_then(|value| serde_json::to_string_pretty(value).ok())
        .unwrap_or_default();
    EventView {
        id: row.id,
        payload_json: row.payload_json,
        occurred_at_iso: occurred_at.clone(),
        occurred_at,
        environment: payload
            .get("environment")
            .and_then(Value::as_str)
            .unwrap_or("default")
            .to_owned(),
        release: payload
            .get("release")
            .and_then(Value::as_str)
            .map(str::to_owned),
        user,
        context,
    }
}

fn format_stacktrace(payload: &Value) -> String {
    let frames = payload
        .get("error")
        .and_then(|error| error.get("stack_frames"))
        .or_else(|| payload.get("stack_frames"))
        .and_then(Value::as_array);
    let Some(frames) = frames else {
        return String::new();
    };
    let mut lines = Vec::with_capacity(frames.len());
    for frame in frames {
        let function = frame
            .get("function")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>");
        let file = frame
            .get("filename")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>");
        let line = frame.get("line").and_then(Value::as_u64);
        if let Some(line) = line {
            lines.push(format!("{function} at {file}:{line}"));
        } else {
            lines.push(format!("{function} at {file}"));
        }
    }
    lines.join("\n")
}

fn issue_markdown(details: &IssueDetails) -> String {
    let issue = &details.issue;
    let mut out = String::new();

    let title = issue_field(issue, "title");
    let _ = writeln!(
        out,
        "# {}\n",
        if title.is_empty() {
            "Untitled issue"
        } else {
            &title
        }
    );

    let _ = writeln!(
        out,
        "- **Project:** {} ({})",
        details.project.name, details.project.slug
    );
    let _ = writeln!(out, "- **Issue ID:** {}", issue_field(issue, "id"));
    let status = issue_field(issue, "status");
    if !status.is_empty() {
        let _ = writeln!(out, "- **Status:** {status}");
    }
    let tags: Vec<&str> = issue
        .get("tags")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if !tags.is_empty() {
        let _ = writeln!(out, "- **Tags:** {}", tags.join(", "));
    }
    let severity = issue_field(issue, "severity");
    if !severity.is_empty() {
        let _ = writeln!(out, "- **Severity:** {severity}");
    }
    let fingerprint = issue_field(issue, "fingerprint");
    if !fingerprint.is_empty() {
        let _ = writeln!(out, "- **Fingerprint:** `{fingerprint}`");
    }
    let _ = writeln!(out, "- **Events:** {}", issue_field(issue, "event_count"));
    if let Some(first_seen) = issue.get("first_seen_at").and_then(Value::as_i64) {
        let _ = writeln!(out, "- **First seen:** {}", format_unix(first_seen));
    }
    if let Some(last_seen) = issue.get("last_seen_at").and_then(Value::as_i64) {
        let _ = writeln!(out, "- **Last seen:** {}", format_unix(last_seen));
    }
    let environment = issue_field(issue, "environment");
    if !environment.is_empty() {
        let _ = writeln!(out, "- **Environment:** {environment}");
    }
    let release = issue_field(issue, "release");
    if !release.is_empty() {
        let _ = writeln!(out, "- **Release:** {release}");
    }
    let _ = writeln!(out);

    let message = issue_field(issue, "message");
    if !message.is_empty() {
        let _ = writeln!(out, "## Message\n");
        let _ = writeln!(out, "{message}\n");
    }

    let stacktrace = issue_field(issue, "stacktrace");
    if !stacktrace.is_empty() {
        let fence = fence_for(&stacktrace);
        let _ = writeln!(out, "## Stack trace\n");
        let _ = writeln!(out, "{fence}");
        let _ = writeln!(out, "{stacktrace}");
        let _ = writeln!(out, "{fence}\n");
    }

    if !details.events.is_empty() {
        let _ = writeln!(out, "## Recent events\n");
        for event in &details.events {
            let mut meta = event.occurred_at_iso.clone();
            if !event.environment.is_empty() {
                meta.push_str(" · ");
                meta.push_str(&event.environment);
            }
            if let Some(release) = event.release.as_deref().filter(|value| !value.is_empty()) {
                meta.push_str(" · ");
                meta.push_str(release);
            }
            let _ = writeln!(out, "### `{}` — {meta}", event.id);
            let fence = fence_for(&event.payload_json);
            let _ = writeln!(out, "{fence}json");
            let _ = writeln!(out, "{}", event.payload_json);
            let _ = writeln!(out, "{fence}\n");
        }
    }

    if !details.comments.is_empty() {
        let _ = writeln!(out, "## Comments\n");
        for comment in &details.comments {
            let _ = writeln!(
                out,
                "### {} — {}",
                comment.display_name,
                format_unix(comment.created_at)
            );
            let _ = writeln!(out, "{}\n", comment.body);
        }
    }

    if !details.activity.is_empty() {
        let _ = writeln!(out, "## Activity\n");
        for item in &details.activity {
            let actor = item.display_name.as_deref().unwrap_or("System");
            let _ = write!(
                out,
                "- **{actor}** {} — {}",
                item.kind,
                format_unix(item.created_at)
            );
            let details = item.details_json.trim();
            if !details.is_empty() && details != "{}" && details != "null" {
                let _ = write!(out, " — details: `{details}`");
            }
            let _ = writeln!(out);
        }
        let _ = writeln!(out);
    }

    out
}

fn issue_field(issue: &Value, key: &str) -> String {
    issue.get(key).map(json_text).unwrap_or_default()
}

fn json_text(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn fence_for(content: &str) -> String {
    let mut longest = 0usize;
    let mut current = 0usize;
    for character in content.chars() {
        if character == '`' {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    "`".repeat(longest.max(2) + 1)
}

fn format_unix(timestamp: i64) -> String {
    OffsetDateTime::from_unix_timestamp(timestamp)
        .ok()
        .and_then(|value| value.format(&Rfc3339).ok())
        .unwrap_or_else(|| timestamp.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn details(issue: Value, events: Vec<EventView>) -> IssueDetails {
        IssueDetails {
            project: ProjectRow {
                id: "demo".into(),
                slug: "demo".into(),
                name: "Demo".into(),
                role: "viewer".into(),
                created_at: 0,
                description: String::new(),
                status: "active".into(),
                ingest_url: "/api/v1/projects/demo/events".into(),
            },
            issue,
            events,
            comments: vec![CommentRow {
                id: 1,
                body: "Investigated on staging.".into(),
                display_name: "Alice".into(),
                created_at: 0,
            }],
            activity: vec![ActivityRow {
                id: 1,
                kind: "status".into(),
                details_json: r#"{"from":"unresolved","to":"resolved"}"#.into(),
                display_name: Some("Alice".into()),
                created_at: 0,
            }],
        }
    }

    fn issue_value() -> Value {
        json!({
            "id": 7,
            "title": "TypeError: boom",
            "status": "unresolved",
            "severity": "error",
            "message": "boom happened",
            "fingerprint": "abc123",
            "event_count": 3,
            "first_seen_at": 0,
            "last_seen_at": 0,
            "environment": "production",
            "release": "1.2.3",
            "stacktrace": "main at src/main.rs:10",
        })
    }

    #[test]
    fn markdown_includes_all_sections() {
        let event = EventView {
            id: "evt-1".into(),
            payload_json: "{\"message\":\"boom\"}".into(),
            occurred_at: "2026-09-24T12:00:00Z".into(),
            occurred_at_iso: "2026-09-24T12:00:00Z".into(),
            environment: "production".into(),
            release: Some("1.2.3".into()),
            user: None,
            context: String::new(),
        };
        let markdown = issue_markdown(&details(issue_value(), vec![event]));

        assert!(markdown.starts_with("# TypeError: boom\n"));
        assert!(markdown.contains("- **Project:** Demo (demo)"));
        assert!(markdown.contains("- **Fingerprint:** `abc123`"));
        assert!(markdown.contains("- **First seen:** 1970-01-01T00:00:00Z"));
        assert!(markdown.contains("## Message\n\nboom happened"));
        assert!(markdown.contains("## Stack trace\n\n```\nmain at src/main.rs:10\n```"));
        assert!(markdown.contains("### `evt-1` — 2026-09-24T12:00:00Z · production · 1.2.3"));
        assert!(markdown.contains("```json\n{\"message\":\"boom\"}\n```"));
        assert!(markdown.contains("## Comments\n\n### Alice — 1970-01-01T00:00:00Z"));
        assert!(markdown.contains("## Activity\n\n- **Alice** status — 1970-01-01T00:00:00Z"));
        assert!(markdown.contains("details: `{\"from\":\"unresolved\",\"to\":\"resolved\"}`"));
    }

    #[test]
    fn markdown_omits_empty_sections() {
        let issue = json!({
            "id": 7,
            "title": "Bare issue",
            "status": "unresolved",
            "event_count": 1,
        });
        let mut value = details(issue, Vec::new());
        value.comments.clear();
        value.activity.clear();
        let markdown = issue_markdown(&value);

        assert!(markdown.contains("# Bare issue"));
        assert!(!markdown.contains("## Message"));
        assert!(!markdown.contains("## Stack trace"));
        assert!(!markdown.contains("## Recent events"));
        assert!(!markdown.contains("## Comments"));
        assert!(!markdown.contains("## Activity"));
    }

    #[test]
    fn fence_extends_past_content_backticks() {
        assert_eq!(fence_for("plain"), "```");
        assert_eq!(fence_for("a ``` b"), "````");
        assert_eq!(fence_for("a ```` b"), "`````");
    }
}
