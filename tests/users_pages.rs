#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(missing_docs)]

mod common;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use common::{LoggedIn, app_with_templates, login, seed_membership, seed_project, test_pool};
use http_body_util::BodyExt;
use sqlx::SqlitePool;
use tower::ServiceExt;
use zbierak::hash_password;

const OWNER_EMAIL: &str = "owner@example.com";
const OWNER_PASSWORD: &str = "correct-horse-staple-12";

async fn body_text(response: axum::response::Response) -> String {
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

fn get(path: &str, logged_in: &LoggedIn) -> Request<Body> {
    Request::get(path.to_owned())
        .header("cookie", logged_in.cookie_header.clone())
        .body(Body::empty())
        .unwrap()
}

/// Seeds the instance owner (id 1, the bootstrap user) plus two members and
/// returns a router with real templates.
async fn seeded_app() -> (Router, SqlitePool, LoggedIn) {
    let db = test_pool().await;
    sqlx::query(
        "INSERT INTO users (id, email, display_name, password_hash) VALUES (1, ?, 'Owner', ?)",
    )
    .bind(OWNER_EMAIL)
    .bind(hash_password(OWNER_PASSWORD).unwrap())
    .execute(&db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO users (id, email, display_name, password_hash) VALUES (2, 'ada@example.com', 'Ada', ?)",
    )
    .bind(hash_password("ada-passphrase-long-1").unwrap())
    .execute(&db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO users (id, email, display_name, password_hash) VALUES (3, 'bob@example.com', 'Bob', ?)",
    )
    .bind(hash_password("bob-passphrase-long-2").unwrap())
    .execute(&db)
    .await
    .unwrap();
    let app = app_with_templates(db.clone());
    let logged_in = login(&app, &db, OWNER_EMAIL, OWNER_PASSWORD).await;
    (app, db, logged_in)
}

async fn seed_issue(db: &SqlitePool, issue_id: i64, project_id: i64, title: &str) {
    sqlx::query("INSERT INTO issues (id, project_id, fingerprint, title) VALUES (?, ?, ?, ?)")
        .bind(issue_id)
        .bind(project_id)
        .bind(format!("fp-{issue_id}"))
        .bind(title)
        .execute(db)
        .await
        .unwrap();
}

async fn seed_activity(db: &SqlitePool, issue_id: i64, user_id: i64, kind: &str, details: &str) {
    sqlx::query(
        "INSERT INTO issue_activity (issue_id, user_id, kind, details_json) VALUES (?, ?, ?, ?)",
    )
    .bind(issue_id)
    .bind(user_id)
    .bind(kind)
    .bind(details)
    .execute(db)
    .await
    .unwrap();
}

#[tokio::test]
async fn users_directory_requires_authentication() {
    let (app, _db, _logged_in) = seeded_app().await;
    let response = app
        .oneshot(Request::get("/users").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn users_directory_lists_everyone_and_flags_the_instance_owner() {
    let (app, _db, logged_in) = seeded_app().await;

    let response = app
        .clone()
        .oneshot(get("/users", &logged_in))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let page = body_text(response).await;
    assert!(page.contains("Ada"));
    assert!(page.contains("ada@example.com"));
    assert!(page.contains("Bob"));
    assert!(page.contains("instance owner"));
}

#[tokio::test]
async fn unknown_user_profile_is_not_found() {
    let (app, _db, logged_in) = seeded_app().await;
    let response = app.oneshot(get("/users/999", &logged_in)).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn profile_page_renders_identity_and_activity() {
    let (app, db, logged_in) = seeded_app().await;
    seed_project(&db, 1, "demo").await;
    seed_membership(&db, 1, 3, "developer").await;
    seed_issue(&db, 10, 1, "Crash on save").await;
    seed_activity(&db, 10, 3, "comment", r#"{"comment_id": 1}"#).await;
    seed_activity(
        &db,
        10,
        3,
        "status",
        r#"{"from": "unresolved", "to": "resolved"}"#,
    )
    .await;

    let response = app
        .clone()
        .oneshot(get("/users/3", &logged_in))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let page = body_text(response).await;
    assert!(page.contains("Bob"));
    assert!(page.contains("bob@example.com"));
    assert!(page.contains("Crash on save"));
    assert!(page.contains("commented on"));
    assert!(page.contains("changed status on"));
    assert!(page.contains("unresolved"));
    assert!(page.contains("resolved"));
    assert!(page.contains("/projects/demo/issues/10"), "page: {page}");
    // The instance owner viewing the page gets the edit button.
    assert!(page.contains("Change settings"));
}

#[tokio::test]
async fn profile_activity_is_limited_to_projects_shared_with_the_viewer() {
    let (app, db, owner_session) = seeded_app().await;
    // Project 1 is shared between Ada (2) and Bob (3); project 2 is Bob-only.
    seed_project(&db, 1, "shared").await;
    seed_membership(&db, 1, 2, "developer").await;
    seed_membership(&db, 1, 3, "developer").await;
    sqlx::query(
        "INSERT INTO projects (id, slug, name, created_by) VALUES (2, 'secret', 'Secret', 1)",
    )
    .execute(&db)
    .await
    .unwrap();
    seed_membership(&db, 2, 3, "developer").await;
    seed_issue(&db, 10, 1, "Shared crash").await;
    seed_issue(&db, 20, 2, "Secret crash").await;
    seed_activity(&db, 10, 3, "comment", r"{}").await;
    seed_activity(&db, 20, 3, "comment", r"{}").await;

    // Ada (a non-owner viewer) only sees the shared project's activity.
    let ada = login(&app, &db, "ada@example.com", "ada-passphrase-long-1").await;
    let response = app.clone().oneshot(get("/users/3", &ada)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let page = body_text(response).await;
    assert!(page.contains("Shared crash"));
    assert!(!page.contains("Secret crash"));

    // The instance owner sees every membership and activity entry.
    let response = app
        .clone()
        .oneshot(get("/users/3", &owner_session))
        .await
        .unwrap();
    let page = body_text(response).await;
    assert!(page.contains("Shared crash"));
    assert!(page.contains("Secret crash"));
}

#[tokio::test]
async fn settings_page_is_forbidden_for_non_owners() {
    let (app, db, _logged_in) = seeded_app().await;
    let ada = login(&app, &db, "ada@example.com", "ada-passphrase-long-1").await;

    let response = app
        .clone()
        .oneshot(get("/users/1/settings", &ada))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app
        .oneshot(ada.post_form(
            "/users/1/profile",
            &[("csrf_token", &ada.csrf), ("display_name", "Hacked")],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let stored: String = sqlx::query_scalar("SELECT display_name FROM users WHERE id=1")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(stored, "Owner");
}

#[tokio::test]
async fn instance_owner_can_edit_another_users_profile_but_not_credentials() {
    let (app, db, logged_in) = seeded_app().await;

    let response = app
        .clone()
        .oneshot(get("/users/2/settings", &logged_in))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let page = body_text(response).await;
    assert!(page.contains("Ada"));
    // Security sections are self-service only, even for the instance owner.
    assert!(!page.contains("Change password"));
    assert!(!page.contains("Active sessions"));

    let response = app
        .clone()
        .oneshot(logged_in.post_form(
            "/users/2/profile",
            &[("csrf_token", &logged_in.csrf), ("display_name", "Ada L.")],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(body_text(response).await.contains("Ada L."));
    let stored: String = sqlx::query_scalar("SELECT display_name FROM users WHERE id=2")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(stored, "Ada L.");
    // The audit trail records who made the change.
    let actor: String = sqlx::query_scalar(
        "SELECT details_json FROM audit_log
         WHERE action='user.updated' AND target_id='2'",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert!(actor.contains("\"actor_id\":1"), "details: {actor}");

    // Credentials stay strictly self-service.
    let response = app
        .oneshot(logged_in.post_form(
            "/users/2/password",
            &[
                ("csrf_token", &logged_in.csrf),
                ("current_password", "ada-passphrase-long-1"),
                ("new_password", "a much newer passphrase indeed"),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn own_settings_page_shows_security_sections() {
    let (app, _db, logged_in) = seeded_app().await;
    let response = app
        .clone()
        .oneshot(get("/users/1/settings", &logged_in))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let page = body_text(response).await;
    assert!(page.contains("Change password"));
    assert!(page.contains("Active sessions"));
}

#[tokio::test]
async fn session_revocation_rejects_other_users() {
    let (app, db, logged_in) = seeded_app().await;
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at)
         VALUES ('ada-session', 2, 'ada-csrf', unixepoch() + 3600)",
    )
    .execute(&db)
    .await
    .unwrap();
    let ada_session_id: i64 =
        sqlx::query_scalar("SELECT id FROM sessions WHERE token_hash='ada-session'")
            .fetch_one(&db)
            .await
            .unwrap();

    let response = app
        .clone()
        .oneshot(logged_in.post_form(
            &format!("/users/2/sessions/{ada_session_id}/revoke"),
            &[("csrf_token", &logged_in.csrf)],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app
        .oneshot(logged_in.post_form(
            "/users/2/sessions/revoke-others",
            &[("csrf_token", &logged_in.csrf)],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions WHERE user_id=2")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(remaining, 1);
}
