#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(missing_docs)]

mod common;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use common::{
    app_with_templates, response_json, seed_key, seed_membership, seed_project, seed_token,
    seed_user, test_app, test_pool,
};
use http_body_util::BodyExt;
use tower::ServiceExt;
use zbierak::token_hash;

async fn response_text(response: axum::response::Response) -> String {
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

/// Seeds the standard cast: user 1 owner, 2 viewer, 3 developer, 4 admin,
/// and 5 a second developer; project 1 "demo" plus project 2 "other" where
/// only the owner is a member.
async fn seed_world(db: &sqlx::SqlitePool) {
    seed_project(db, 1, "demo").await;
    seed_project(db, 2, "other").await;
    for (id, email, name) in [
        (1, "owner@example.com", "Owner"),
        (2, "viewer@example.com", "Viewer"),
        (3, "developer@example.com", "Developer"),
        (4, "admin@example.com", "Admin"),
        (5, "developer2@example.com", "Developer2"),
    ] {
        seed_user(db, id, email, name).await;
    }
    for (user_id, role) in [
        (1, "owner"),
        (2, "viewer"),
        (3, "developer"),
        (4, "admin"),
        (5, "developer"),
    ] {
        seed_membership(db, 1, user_id, role).await;
    }
    seed_membership(db, 2, 1, "owner").await;
    seed_key(db, 1, "zbk_test_key").await;
    for (user_id, token) in [
        (1, "zpat_owner_token"),
        (2, "zpat_viewer_token"),
        (3, "zpat_developer_token"),
        (4, "zpat_admin_token"),
        (5, "zpat_developer2_token"),
    ] {
        seed_token(db, user_id, token).await;
    }
}

async fn seed_issue(db: &sqlx::SqlitePool, app: &Router, slug: &str) -> i64 {
    let event = r#"{"event_id":"evt-1","timestamp":"2026-09-24T12:00:00Z","message":"boom"}"#;
    let response = app
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/projects/{slug}/events"))
                .header("content-type", "application/json")
                .header("authorization", "Bearer zbk_test_key")
                .body(Body::from(event))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    sqlx::query_scalar::<_, i64>("SELECT id FROM issues ORDER BY id DESC LIMIT 1")
        .fetch_one(db)
        .await
        .unwrap()
}

fn api_post_json(path: &str, token: &str, body: &str) -> Request<Body> {
    Request::post(path.to_owned())
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn api_put_json(path: &str, token: &str, body: &str) -> Request<Body> {
    Request::put(path.to_owned())
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn api_delete(path: &str, token: &str) -> Request<Body> {
    Request::delete(path.to_owned())
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn create_comment(app: &Router, issue_id: i64, body: &str) -> axum::response::Response {
    app.clone()
        .oneshot(api_post_json(
            &format!("/api/v1/projects/demo/issues/{issue_id}/comments"),
            "zpat_developer_token",
            &format!(r#"{{"body":"{body}"}}"#),
        ))
        .await
        .unwrap()
}

async fn comment_row(db: &sqlx::SqlitePool, comment_id: i64) -> (String, Option<i64>, Option<i64>) {
    sqlx::query_as::<_, (String, Option<i64>, Option<i64>)>(
        "SELECT body, deleted_at, updated_at FROM issue_comments WHERE id=?",
    )
    .bind(comment_id)
    .fetch_one(db)
    .await
    .unwrap()
}

async fn activity_count(db: &sqlx::SqlitePool, kind: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM issue_activity WHERE kind=?")
        .bind(kind)
        .fetch_one(db)
        .await
        .unwrap()
}

async fn seed_session(db: &sqlx::SqlitePool, token: &str, user_id: i64, csrf: &str) {
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at)
         VALUES (?, ?, ?, unixepoch() + 3600)",
    )
    .bind(token_hash(token))
    .bind(user_id)
    .bind(csrf)
    .execute(db)
    .await
    .unwrap();
}

#[tokio::test]
async fn comments_can_be_created_and_listed_via_the_api() {
    let db = test_pool().await;
    seed_world(&db).await;
    let app = test_app(db.clone());
    let issue_id = seed_issue(&db, &app, "demo").await;

    let response = create_comment(&app, issue_id, "first **finding**").await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let comment = response_json(response).await;
    let comment_id = comment["id"].as_i64().unwrap();
    assert_eq!(comment["body"], "first **finding**");
    assert_eq!(comment["author"], "Developer");
    assert_eq!(comment["user_id"], 3);
    assert!(comment["deleted_at"].is_null());
    assert!(comment["updated_at"].is_null());

    // Viewers read comments; body comes back as raw Markdown source.
    let response = app
        .clone()
        .oneshot(common::get_request(
            &format!("/api/v1/projects/demo/issues/{issue_id}/comments"),
            "zpat_viewer_token",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let list = response_json(response).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["id"], comment_id);

    // Missing credentials and unknown issues behave like the other endpoints.
    let response = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/projects/demo/issues/{issue_id}/comments"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = app
        .oneshot(common::get_request(
            "/api/v1/projects/demo/issues/999/comments",
            "zpat_owner_token",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn authors_can_edit_their_own_comments() {
    let db = test_pool().await;
    seed_world(&db).await;
    let app = test_app(db.clone());
    let issue_id = seed_issue(&db, &app, "demo").await;
    let response = create_comment(&app, issue_id, "draft").await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .clone()
        .oneshot(api_put_json(
            &format!("/api/v1/projects/demo/issues/{issue_id}/comments/1"),
            "zpat_developer_token",
            r#"{"body":"edited body"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let comment = response_json(response).await;
    assert_eq!(comment["body"], "edited body");
    assert!(!comment["updated_at"].is_null());
    assert_eq!(comment["updated_by"], "Developer");

    let (body, deleted_at, updated_at) = comment_row(&db, 1).await;
    assert_eq!(body, "edited body");
    assert!(deleted_at.is_none());
    assert!(updated_at.is_some());
    assert_eq!(activity_count(&db, "comment_edited").await, 1);
}

#[tokio::test]
async fn developers_cannot_modify_foreign_comments() {
    let db = test_pool().await;
    seed_world(&db).await;
    let app = test_app(db.clone());
    let issue_id = seed_issue(&db, &app, "demo").await;
    let response = create_comment(&app, issue_id, "not yours").await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let response = app
        .clone()
        .oneshot(api_put_json(
            &format!("/api/v1/projects/demo/issues/{issue_id}/comments/1"),
            "zpat_developer2_token",
            r#"{"body":"hijacked"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app
        .clone()
        .oneshot(api_delete(
            &format!("/api/v1/projects/demo/issues/{issue_id}/comments/1"),
            "zpat_developer2_token",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let (body, deleted_at, _) = comment_row(&db, 1).await;
    assert_eq!(body, "not yours");
    assert!(deleted_at.is_none());
    assert_eq!(activity_count(&db, "comment_deleted").await, 0);
}

#[tokio::test]
async fn admins_can_moderate_any_comment_and_deletion_is_soft() {
    let db = test_pool().await;
    seed_world(&db).await;
    let app = test_app(db.clone());
    let issue_id = seed_issue(&db, &app, "demo").await;
    let response = create_comment(&app, issue_id, "to moderate").await;
    assert_eq!(response.status(), StatusCode::CREATED);

    // An admin edits, then removes the developer's comment.
    let response = app
        .clone()
        .oneshot(api_put_json(
            &format!("/api/v1/projects/demo/issues/{issue_id}/comments/1"),
            "zpat_admin_token",
            r#"{"body":"moderated"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_json(response).await["updated_by"], "Admin");

    let response = app
        .clone()
        .oneshot(api_delete(
            &format!("/api/v1/projects/demo/issues/{issue_id}/comments/1"),
            "zpat_admin_token",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let (_, deleted_at, _) = comment_row(&db, 1).await;
    assert!(deleted_at.is_some(), "deletion must be a soft delete");
    assert_eq!(activity_count(&db, "comment_deleted").await, 1);

    // The listing shows a tombstone without the body.
    let response = app
        .clone()
        .oneshot(common::get_request(
            &format!("/api/v1/projects/demo/issues/{issue_id}/comments"),
            "zpat_viewer_token",
        ))
        .await
        .unwrap();
    let list = response_json(response).await;
    assert_eq!(list[0]["body"], serde_json::Value::Null);
    assert!(!list[0]["deleted_at"].is_null());

    // A removed comment can neither be edited nor removed again.
    let response = app
        .clone()
        .oneshot(api_put_json(
            &format!("/api/v1/projects/demo/issues/{issue_id}/comments/1"),
            "zpat_admin_token",
            r#"{"body":"again"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = app
        .oneshot(api_delete(
            &format!("/api/v1/projects/demo/issues/{issue_id}/comments/1"),
            "zpat_admin_token",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn viewers_cannot_create_edit_or_delete_comments() {
    let db = test_pool().await;
    seed_world(&db).await;
    let app = test_app(db.clone());
    let issue_id = seed_issue(&db, &app, "demo").await;

    let response = app
        .clone()
        .oneshot(api_post_json(
            &format!("/api/v1/projects/demo/issues/{issue_id}/comments"),
            "zpat_viewer_token",
            r#"{"body":"hi"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response_json(response).await["code"], "forbidden");

    // A viewer editing or deleting even a foreign, nonexistent comment fails
    // closed with 403 before existence is revealed.
    let response = app
        .clone()
        .oneshot(api_put_json(
            &format!("/api/v1/projects/demo/issues/{issue_id}/comments/1"),
            "zpat_viewer_token",
            r#"{"body":"hi"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = app
        .oneshot(api_delete(
            &format!("/api/v1/projects/demo/issues/{issue_id}/comments/1"),
            "zpat_viewer_token",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn comment_ids_are_scoped_to_their_project() {
    let db = test_pool().await;
    seed_world(&db).await;
    let app = test_app(db.clone());
    let issue_id = seed_issue(&db, &app, "demo").await;
    let response = create_comment(&app, issue_id, "scoped").await;
    assert_eq!(response.status(), StatusCode::CREATED);

    // The owner is also an owner of project 2, but issue and comment live in
    // project 1, so both mutations and reads through the other slug are 404.
    let response = app
        .clone()
        .oneshot(common::get_request(
            "/api/v1/projects/other/issues/1/comments",
            "zpat_owner_token",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = app
        .clone()
        .oneshot(api_put_json(
            "/api/v1/projects/other/issues/1/comments/1",
            "zpat_owner_token",
            r#"{"body":"x"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = app
        .oneshot(api_delete(
            "/api/v1/projects/other/issues/1/comments/1",
            "zpat_owner_token",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn comment_bodies_are_validated() {
    let db = test_pool().await;
    seed_world(&db).await;
    let app = test_app(db.clone());
    let issue_id = seed_issue(&db, &app, "demo").await;

    let response = app
        .clone()
        .oneshot(api_post_json(
            &format!("/api/v1/projects/demo/issues/{issue_id}/comments"),
            "zpat_developer_token",
            r#"{"body":"   "}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let error = response_json(response).await;
    assert_eq!(error["code"], "validation_failed");
    assert_eq!(error["field"], "body");

    let oversized = format!(r#"{{"body":"{}"}}"#, "x".repeat(10_001));
    let response = app
        .clone()
        .oneshot(api_post_json(
            &format!("/api/v1/projects/demo/issues/{issue_id}/comments"),
            "zpat_developer_token",
            &oversized,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // The boundary itself is accepted.
    let exact = format!(r#"{{"body":"{}"}}"#, "x".repeat(10_000));
    let response = app
        .oneshot(api_post_json(
            &format!("/api/v1/projects/demo/issues/{issue_id}/comments"),
            "zpat_developer_token",
            &exact,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn ui_forms_edit_and_delete_with_csrf_and_roles() {
    let db = test_pool().await;
    seed_world(&db).await;
    let app = test_app(db.clone());
    let issue_id = seed_issue(&db, &app, "demo").await;
    let response = create_comment(&app, issue_id, "original").await;
    assert_eq!(response.status(), StatusCode::CREATED);

    seed_session(&db, "developer-session", 3, "developer-csrf").await;
    seed_session(&db, "developer2-session", 5, "developer2-csrf").await;
    seed_session(&db, "admin-session", 4, "admin-csrf").await;

    let form = |session: &str, csrf: &str, body: &str| {
        Request::post(format!("/projects/demo/issues/{issue_id}/comments/1/edit"))
            .header("content-type", "application/x-www-form-urlencoded")
            .header("cookie", format!("zbierak_session={session}"))
            .body(Body::from(format!("csrf_token={csrf}&body={body}")))
            .unwrap()
    };

    // Wrong CSRF is rejected.
    let response = app
        .clone()
        .oneshot(form("developer-session", "wrong", "nope"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // The author edits their own comment.
    let response = app
        .clone()
        .oneshot(form("developer-session", "developer-csrf", "revised"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(comment_row(&db, 1).await.0, "revised");

    // Another developer cannot edit it; the admin can.
    let response = app
        .clone()
        .oneshot(form("developer2-session", "developer2-csrf", "hijacked"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app
        .clone()
        .oneshot(form("admin-session", "admin-csrf", "moderated"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(comment_row(&db, 1).await.0, "moderated");

    let delete = |session: &str, csrf: &str| {
        Request::post(format!(
            "/projects/demo/issues/{issue_id}/comments/1/delete"
        ))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("cookie", format!("zbierak_session={session}"))
        .body(Body::from(format!("csrf_token={csrf}")))
        .unwrap()
    };

    let response = app
        .clone()
        .oneshot(delete("developer2-session", "developer2-csrf"))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "non-author developer cannot delete"
    );

    let response = app
        .clone()
        .oneshot(delete("admin-session", "admin-csrf"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(comment_row(&db, 1).await.1.is_some());
    let response = app
        .oneshot(delete("admin-session", "admin-csrf"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(activity_count(&db, "comment_deleted").await, 1);
}

#[tokio::test]
async fn issue_page_renders_markdown_sanitized_with_tombstones() {
    let db = test_pool().await;
    seed_world(&db).await;
    let app = app_with_templates(db.clone());
    let issue_id = seed_issue(&db, &app, "demo").await;

    let payload = r##"{"body":"# heading\n\n**bold** and stuff\n\n<script>alert(1)</script>\n\n[x](javascript:alert(1)) <img src=\"https://example.com/i.png\" onerror=\"alert(1)\">"}"##;
    let response = app
        .clone()
        .oneshot(api_post_json(
            &format!("/api/v1/projects/demo/issues/{issue_id}/comments"),
            "zpat_developer_token",
            payload,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    seed_session(&db, "owner-session", 1, "owner-csrf").await;
    let page = |path: &str| {
        Request::get(path.to_owned())
            .header("cookie", "zbierak_session=owner-session")
            .body(Body::empty())
            .unwrap()
    };

    let response = app
        .clone()
        .oneshot(page(&format!("/projects/demo/issues/{issue_id}")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = response_text(response).await;
    // Rendered body: Markdown constructs survive sanitization.
    assert!(html.contains("<strong>bold</strong>"));
    assert!(html.contains("<h1>heading</h1>"));
    // Rendered body: dangerous constructs are gone. (The raw source appears
    // escaped inside the edit textarea, so the assertions target the
    // unescaped markup shapes.)
    assert!(!html.contains("<script>alert"));
    assert!(!html.contains("onerror=\""));
    assert!(!html.contains("href=\"javascript:"));
    assert!(
        html.contains(r#"rel="noopener noreferrer">x</a>"#),
        "scheme-stripped link keeps its text"
    );
    // The owner sees moderation controls on a foreign comment; the editor
    // textarea carries the raw Markdown source, escaped by the template.
    assert!(html.contains("/comments/1/edit"));
    assert!(html.contains("/comments/1/delete"));
    assert!(html.contains("**bold** and stuff"));

    // After deletion the page shows the tombstone without the body.
    let response = app
        .clone()
        .oneshot(api_delete(
            &format!("/api/v1/projects/demo/issues/{issue_id}/comments/1"),
            "zpat_admin_token",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = app
        .clone()
        .oneshot(page(&format!("/projects/demo/issues/{issue_id}")))
        .await
        .unwrap();
    let html = response_text(response).await;
    assert!(html.contains("Comment removed."));
    assert!(!html.contains("<strong>bold</strong>"));
    assert!(!html.contains("/comments/1/edit"));

    // The Markdown export replaces the removed body with a tombstone too.
    let response = app
        .clone()
        .oneshot(page(&format!("/projects/demo/issues/{issue_id}/export.md")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let markdown = response_text(response).await;
    assert!(markdown.contains("_Comment removed._"));
    // The Comments section shows only the tombstone; the original creation
    // activity row intentionally keeps its audit trail in the Activity
    // section, so the check is scoped to the section itself.
    let comments_section = markdown
        .split("## Comments\n")
        .nth(1)
        .unwrap()
        .split("## Activity")
        .next()
        .unwrap();
    assert!(!comments_section.contains("**bold**"));
    assert!(comments_section.contains("### Developer"));
}
