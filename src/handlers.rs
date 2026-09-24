use std::fmt::Write as _;
use std::path::{Component, Path};

use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Form, Path as AxumPath, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{FromRow, Row};
use tera::Context;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tower_cookies::Cookies;
use url::Url;
use uuid::Uuid;

use crate::{
    AppError, AppResult, AppState,
    api_error::ApiError,
    auth::{self, User},
    fingerprint::event_fingerprint,
};

#[cfg(feature = "docs")]
use crate::api_error::ErrorResponse;

#[derive(Deserialize)]
pub struct BootstrapForm {
    email: String,
    display_name: String,
    password: String,
}

#[derive(Deserialize)]
pub struct LoginForm {
    email: String,
    password: String,
}

#[derive(Deserialize)]
pub struct CsrfForm {
    csrf_token: String,
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
struct ActivityRow {
    id: i64,
    kind: String,
    details_json: String,
    display_name: Option<String>,
    created_at: i64,
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

pub async fn login_page(State(state): State<AppState>) -> AppResult<Html<String>> {
    render(&state, "login.html", Context::new())
}

pub async fn login(
    State(state): State<AppState>,
    cookies: Cookies,
    Form(form): Form<LoginForm>,
) -> AppResult<Redirect> {
    let row = sqlx::query_as::<_, (i64, String)>(
        "SELECT id, password_hash FROM users WHERE email = ? COLLATE NOCASE",
    )
    .bind(form.email.trim())
    .fetch_optional(&state.db)
    .await?;
    let Some((user_id, hash)) = row else {
        return Err(AppError::Unauthorized);
    };
    if !auth::verify_password(&form.password, &hash) {
        return Err(AppError::Unauthorized);
    }
    auth::create_session(&state, &cookies, user_id).await?;
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
    let issues = sqlx::query_as::<_, IssueRow>(
        "SELECT id, title, status, event_count, first_seen_at, last_seen_at, fingerprint
         FROM issues WHERE project_id=? ORDER BY last_seen_at DESC LIMIT 100",
    )
    .bind(project_id)
    .fetch_all(&state.db)
    .await?;
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
    let issues = sqlx::query_as::<_, IssueRow>(
        "SELECT id, title, status, event_count, first_seen_at, last_seen_at, fingerprint
         FROM issues WHERE project_id=? ORDER BY last_seen_at DESC LIMIT 100",
    )
    .bind(project_id)
    .fetch_all(&state.db)
    .await?;
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
    context.insert("ingest_keys", &keys);
    context.insert("members", &members);
    context.insert("notification_endpoints", &endpoints);
    render(&state, "project.html", context)
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

pub async fn settings(State(state): State<AppState>, cookies: Cookies) -> AppResult<Html<String>> {
    let session = auth::require_session(&state, &cookies).await?;
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
    render(&state, "settings.html", context)
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
    let secret = if form.kind == "webhook" {
        let secret = required_text("webhook secret", form.secret.as_deref().unwrap_or(""), 1024)?;
        if secret.len() < 16 {
            return Err(AppError::BadRequest(
                "webhook secret must contain at least 16 characters".into(),
            ));
        }
        Some(secret.to_owned())
    } else {
        None
    };
    sqlx::query(
        "INSERT INTO notification_endpoints (project_id, name, kind, url, secret, created_by)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(project_id)
    .bind(name)
    .bind(form.kind)
    .bind(url.as_str())
    .bind(secret)
    .bind(session.user.id)
    .execute(&state.db)
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
        (status = 400, description = "Malformed request body", body = ErrorResponse),
        (status = 401, description = "Missing or invalid ingest key", body = ErrorResponse),
        (status = 422, description = "Event failed protocol validation", body = ErrorResponse),
    )
))]
pub async fn ingest(
    State(state): State<AppState>,
    AxumPath(slug): AxumPath<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    if body.len() > 1_048_576 {
        return Err(AppError::BadRequest("event exceeds 1 MiB".into()).into());
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
    let producer_event_id = event.event_id;
    let storage_id = Uuid::new_v4().to_string();
    let payload = String::from_utf8(body.to_vec())
        .map_err(|_| AppError::BadRequest("event body must be UTF-8 JSON".into()))?;
    let mut tx = state.db.begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO raw_events (id, project_id, ingest_key_id, body, producer_event_id)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(project_id, producer_event_id) DO NOTHING",
    )
    .bind(&storage_id)
    .bind(project_id)
    .bind(key_id)
    .bind(body.as_ref())
    .bind(&producer_event_id)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    if !inserted {
        let (issue_id, existing_fingerprint) = sqlx::query_as::<_, (i64, String)>(
            "SELECT e.issue_id, e.fingerprint FROM events e
             JOIN raw_events r ON r.id=e.id
             WHERE r.project_id=? AND r.producer_event_id=?",
        )
        .bind(project_id)
        .bind(&producer_event_id)
        .fetch_one(&mut *tx)
        .await?;
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
        (status = 500, description = "Database check failed", body = ErrorResponse)
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
