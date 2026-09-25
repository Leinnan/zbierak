#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(missing_docs)]

//! Verifies that every audited mutation and its audit entry share one
//! transaction: a failing audit insert must roll the mutation back.

mod common;

use std::sync::Arc;

use common::{
    LoggedIn, app_with_templates_and_config, login, seed_membership, seed_project, seed_user,
    test_config, test_pool,
};
use tower::ServiceExt;
use zbierak::{generate_key, hash_password, parse_key, verify_password};

const OWNER_EMAIL: &str = "owner@example.com";
const OWNER_PASSWORD: &str = "correct horse battery staple";

/// Installs a trigger that aborts every insert into the audit log.
async fn block_audit(db: &sqlx::SqlitePool) {
    sqlx::query(
        "CREATE TRIGGER block_audit BEFORE INSERT ON audit_log
         BEGIN SELECT RAISE(ABORT, 'audit blocked'); END;",
    )
    .execute(db)
    .await
    .unwrap();
}

async fn audit_count(db: &sqlx::SqlitePool, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = ?")
        .bind(action)
        .fetch_one(db)
        .await
        .unwrap()
}

async fn seeded_app() -> (sqlx::SqlitePool, axum::Router, LoggedIn) {
    let db = test_pool().await;
    seed_user(&db, 1, OWNER_EMAIL, "Owner").await;
    sqlx::query("UPDATE users SET password_hash = ? WHERE id = 1")
        .bind(hash_password(OWNER_PASSWORD).unwrap())
        .execute(&db)
        .await
        .unwrap();
    seed_project(&db, 1, "demo").await;
    seed_membership(&db, 1, 1, "owner").await;
    let app = app_with_templates_and_config(db.clone(), test_config());
    let session = login(&app, &db, OWNER_EMAIL, OWNER_PASSWORD).await;
    (db, app, session)
}

/// Same as [`seeded_app`] but with webhook signing secrets enabled so plain
/// webhook endpoints can be created.
async fn seeded_app_with_webhook_key() -> (sqlx::SqlitePool, axum::Router, LoggedIn) {
    let db = test_pool().await;
    seed_user(&db, 1, OWNER_EMAIL, "Owner").await;
    sqlx::query("UPDATE users SET password_hash = ? WHERE id = 1")
        .bind(hash_password(OWNER_PASSWORD).unwrap())
        .execute(&db)
        .await
        .unwrap();
    seed_project(&db, 1, "demo").await;
    seed_membership(&db, 1, 1, "owner").await;
    let mut config = test_config();
    config.webhook_key = Some(parse_key(&generate_key()).unwrap());
    let resolver = Arc::new(common::Pinned("93.184.216.34".parse().unwrap()));
    let app = common::app_with(db.clone(), config, resolver);
    let session = login(&app, &db, OWNER_EMAIL, OWNER_PASSWORD).await;
    (db, app, session)
}

#[tokio::test]
async fn successful_mutation_records_exactly_one_audit_row() {
    let (db, app, session) = seeded_app().await;
    let response = app
        .oneshot(session.post_form(
            "/settings/tokens",
            &[("csrf_token", &session.csrf), ("name", "cli")],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(audit_count(&db, "api_token.created").await, 1);
    let tokens: i64 = sqlx::query_scalar("SELECT count(*) FROM api_tokens")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(tokens, 1);
}

#[tokio::test]
async fn failed_audit_rolls_back_api_token_creation() {
    let (db, app, session) = seeded_app().await;
    block_audit(&db).await;

    let response = app
        .oneshot(session.post_form(
            "/settings/tokens",
            &[("csrf_token", &session.csrf), ("name", "cli")],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 500);

    let tokens: i64 = sqlx::query_scalar("SELECT count(*) FROM api_tokens")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(tokens, 0, "token creation must roll back when audit fails");
    assert_eq!(audit_count(&db, "api_token.created").await, 0);
}

#[tokio::test]
async fn failed_audit_rolls_back_webhook_creation() {
    let (db, app, session) = seeded_app_with_webhook_key().await;
    block_audit(&db).await;

    let response = app
        .oneshot(session.post_form(
            "/projects/demo/notifications/webhooks",
            &[
                ("csrf_token", &session.csrf),
                ("name", "ops"),
                ("url", "https://hooks.example.com/x"),
                ("kind", "webhook"),
                ("secret", "a-signing-secret-1234"),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 500);

    let endpoints: i64 = sqlx::query_scalar("SELECT count(*) FROM notification_endpoints")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(endpoints, 0, "webhook creation must roll back");
}

#[tokio::test]
async fn failed_audit_rolls_back_ingest_key_revocation() {
    let (db, app, session) = seeded_app().await;
    // Create a key directly; creation is not audited, revocation is.
    sqlx::query(
        "INSERT INTO ingest_keys (project_id, name, key_prefix, key_hash, created_by)
         VALUES (1, 'ci', 'zbk_ci', 'hash', 1)",
    )
    .execute(&db)
    .await
    .unwrap();

    block_audit(&db).await;
    let key_id: i64 = sqlx::query_scalar("SELECT id FROM ingest_keys LIMIT 1")
        .fetch_one(&db)
        .await
        .unwrap();
    let response = app
        .oneshot(session.post_form(
            &format!("/projects/demo/keys/{key_id}/revoke"),
            &[("csrf_token", &session.csrf)],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 500);

    let revoked: Option<i64> =
        sqlx::query_scalar("SELECT revoked_at FROM ingest_keys WHERE id = ?")
            .bind(key_id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(revoked, None, "revocation must roll back when audit fails");
    assert_eq!(audit_count(&db, "ingest_key.revoked").await, 0);
}

#[tokio::test]
async fn successful_revocation_records_exactly_one_audit_row() {
    let (db, app, session) = seeded_app().await;
    sqlx::query(
        "INSERT INTO ingest_keys (project_id, name, key_prefix, key_hash, created_by)
         VALUES (1, 'ci', 'zbk_ci', 'hash', 1)",
    )
    .execute(&db)
    .await
    .unwrap();
    let key_id: i64 = sqlx::query_scalar("SELECT id FROM ingest_keys LIMIT 1")
        .fetch_one(&db)
        .await
        .unwrap();

    let response = app
        .oneshot(session.post_form(
            &format!("/projects/demo/keys/{key_id}/revoke"),
            &[("csrf_token", &session.csrf)],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 303);
    assert_eq!(audit_count(&db, "ingest_key.revoked").await, 1);
}

#[tokio::test]
async fn failed_audit_rolls_back_password_change() {
    let (db, app, session) = seeded_app().await;
    block_audit(&db).await;

    let response = app
        .oneshot(session.post_form(
            "/users/1/password",
            &[
                ("csrf_token", &session.csrf),
                ("current_password", OWNER_PASSWORD),
                ("new_password", "a much newer passphrase indeed"),
            ],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 500);

    let stored: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = 1")
        .fetch_one(&db)
        .await
        .unwrap();
    assert!(
        verify_password(OWNER_PASSWORD, &stored),
        "password change must roll back when audit fails"
    );
    assert!(!verify_password("a much newer passphrase indeed", &stored));
    assert_eq!(audit_count(&db, "user.password_changed").await, 0);
}

#[tokio::test]
async fn failed_audit_rolls_back_session_revocation() {
    let (db, app, session) = seeded_app().await;
    // A second session for the same user.
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at)
         VALUES ('other-hash', 1, 'other-csrf', unixepoch() + 3600)",
    )
    .execute(&db)
    .await
    .unwrap();
    let other_id: i64 =
        sqlx::query_scalar("SELECT id FROM sessions WHERE token_hash = 'other-hash'")
            .fetch_one(&db)
            .await
            .unwrap();

    block_audit(&db).await;
    let response = app
        .oneshot(session.post_form(
            &format!("/users/1/sessions/{other_id}/revoke"),
            &[("csrf_token", &session.csrf)],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 500);

    let still_there: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions WHERE id = ?")
        .bind(other_id)
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(still_there, 1, "session revocation must roll back");
    assert_eq!(audit_count(&db, "user.session_revoked").await, 0);
}

#[tokio::test]
async fn mutation_works_again_after_audit_trigger_is_removed() {
    let (db, app, session) = seeded_app().await;
    block_audit(&db).await;
    let response = app
        .clone()
        .oneshot(session.post_form(
            "/settings/tokens",
            &[("csrf_token", &session.csrf), ("name", "blocked")],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 500);

    sqlx::query("DROP TRIGGER block_audit")
        .execute(&db)
        .await
        .unwrap();
    let response = app
        .oneshot(session.post_form(
            "/settings/tokens",
            &[("csrf_token", &session.csrf), ("name", "working")],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(audit_count(&db, "api_token.created").await, 1);
}
