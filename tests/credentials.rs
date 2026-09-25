#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(missing_docs)]

mod common;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use common::{
    LoggedIn, app_with_templates_and_config, login as shared_login, test_config, test_pool,
};
use http_body_util::BodyExt;
use sqlx::SqlitePool;
use tower::ServiceExt;
use zbierak::{hash_password, token_hash, verify_password};

const EMAIL: &str = "owner@example.com";
const PASSWORD: &str = "correct-horse-staple-12";

struct TestApp {
    app: Router,
    db: SqlitePool,
}

async fn seeded_app() -> TestApp {
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
    let app = app_with_templates_and_config(db.clone(), test_config());
    TestApp { app, db }
}

/// Logs in through the real flow (CSRF pair included) and returns the session
/// cookie plus the session CSRF token used by authenticated forms.
async fn login(app: &Router, db: &SqlitePool) -> (String, String) {
    let LoggedIn {
        session_value,
        csrf,
        ..
    } = shared_login(app, db, EMAIL, PASSWORD).await;
    (session_value, csrf)
}

fn form(app: &Router, session: &str, csrf: &str, path: &str, extra: &str) -> Request<Body> {
    let _ = app;
    Request::post(path)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("cookie", format!("zbierak_session={session}"))
        .body(Body::from(format!("csrf_token={csrf}{extra}")))
        .unwrap()
}

#[tokio::test]
async fn settings_offer_browser_theme_preferences() {
    let TestApp { app, db } = seeded_app().await;
    let (session, _csrf) = login(&app, &db).await;
    let response = app
        .oneshot(
            Request::get("/settings")
                .header("cookie", format!("zbierak_session={session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();

    assert!(body.contains("data-theme-select"));
    assert!(body.contains("<option value=\"system\">System</option>"));
    assert!(body.contains("<option value=\"light\">Light</option>"));
    assert!(body.contains("<option value=\"dark\">Dark</option>"));
}

#[tokio::test]
async fn ingest_key_revocation_blocks_producers() {
    let TestApp { app, db } = seeded_app().await;
    sqlx::query(
        "INSERT INTO ingest_keys (project_id, name, key_prefix, key_hash, created_by)
         VALUES (1, 'old', 'zbk_old', ?, 1)",
    )
    .bind(token_hash("zbk_old_key"))
    .execute(&db)
    .await
    .unwrap();
    let key_id: i64 = sqlx::query_scalar("SELECT id FROM ingest_keys WHERE key_hash=?")
        .bind(token_hash("zbk_old_key"))
        .fetch_one(&db)
        .await
        .unwrap();
    let (session, csrf) = login(&app, &db).await;

    // Wrong CSRF token is rejected before any mutation.
    let response = app
        .clone()
        .oneshot(form(
            &app,
            &session,
            "wrong-token",
            &format!("/projects/demo/keys/{key_id}/revoke"),
            "",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app
        .clone()
        .oneshot(form(
            &app,
            &session,
            &csrf,
            &format!("/projects/demo/keys/{key_id}/revoke"),
            "",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let revoked_at: Option<i64> =
        sqlx::query_scalar("SELECT revoked_at FROM ingest_keys WHERE id=?")
            .bind(key_id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert!(revoked_at.is_some());
    let audited: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action='ingest_key.revoked'")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(audited, 1);

    // Revoking twice is a 404.
    let response = app
        .clone()
        .oneshot(form(
            &app,
            &session,
            &csrf,
            &format!("/projects/demo/keys/{key_id}/revoke"),
            "",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn password_change_requires_current_password_and_evicts_other_sessions() {
    let TestApp { app, db } = seeded_app().await;
    let (session, csrf) = login(&app, &db).await;
    // A second session acts as the "stolen" one.
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at)
                 VALUES ('stolen', 1, 'stolen-csrf', unixepoch() + 86400)",
    )
    .execute(&db)
    .await
    .unwrap();

    let response = app
        .clone()
        .oneshot(form(
            &app,
            &session,
            &csrf,
            "/users/1/password",
            "&current_password=not-the-password&new_password=new-correct-password",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .clone()
        .oneshot(form(
            &app,
            &session,
            &csrf,
            "/users/1/password",
            "&current_password=correct-horse-staple-12&new_password=new-correct-password",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let stored: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE email=?")
        .bind(EMAIL)
        .fetch_one(&db)
        .await
        .unwrap();
    assert!(verify_password("new-correct-password", &stored));
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sessions WHERE token_hash='stolen'")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(remaining, 0);
    let current_left: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(current_left, 1);
    let audited: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action='user.password_changed'")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(audited, 1);
}

#[tokio::test]
async fn session_revocation_removes_only_the_target() {
    let TestApp { app, db } = seeded_app().await;
    let (session, csrf) = login(&app, &db).await;
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at)
                 VALUES ('other-a', 1, 'csrf-a', unixepoch() + 86400),
                        ('other-b', 1, 'csrf-b', unixepoch() + 86400)",
    )
    .execute(&db)
    .await
    .unwrap();

    let response = app
        .clone()
        .oneshot(form(
            &app,
            &session,
            &csrf,
            "/users/1/sessions/revoke-others",
            "",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(remaining, 1);
}
