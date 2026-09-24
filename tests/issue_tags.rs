use std::{path::PathBuf, sync::Arc};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};
use tower::ServiceExt;
use zbierak::{AppState, Config, router, token_hash};

async fn test_pool() -> SqlitePool {
    let db = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!().run(&db).await.unwrap();
    db
}

/// Seeds user 1 (owner), user 2 (viewer), and one project.
async fn seed_project(db: &SqlitePool, project_id: i64, slug: &str) {
    sqlx::query(
        "INSERT OR IGNORE INTO users (id, email, display_name, password_hash)
         VALUES (1, 'owner@example.com', 'Owner', 'unused'),
                (2, 'viewer@example.com', 'Viewer', 'unused')",
    )
    .execute(db)
    .await
    .unwrap();
    sqlx::query("INSERT INTO projects (id, slug, name, created_by) VALUES (?, ?, 'Demo', 1)")
        .bind(project_id)
        .bind(slug)
        .execute(db)
        .await
        .unwrap();
    for (user_id, role) in [(1, "owner"), (2, "viewer")] {
        sqlx::query("INSERT INTO project_memberships (project_id, user_id, role) VALUES (?, ?, ?)")
            .bind(project_id)
            .bind(user_id)
            .bind(role)
            .execute(db)
            .await
            .unwrap();
    }
}

async fn seed_key(db: &SqlitePool, project_id: i64, key: &str) {
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

async fn seed_token(db: &SqlitePool, user_id: i64, token: &str) {
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

fn test_app(db: SqlitePool) -> Router {
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
        resolver: std::sync::Arc::new(zbierak::SystemResolver),
    };
    router(state)
}

fn ingest_request(slug: &str, body: String) -> Request<Body> {
    Request::post(format!("/api/v1/projects/{slug}/events"))
        .header("content-type", "application/json")
        .header("authorization", "Bearer zbk_test_key")
        .body(Body::from(body))
        .unwrap()
}

fn event_body(event_id: &str, message: &str, tags: &str) -> String {
    let mut event = format!(
        r#"{{"event_id":"{event_id}","timestamp":"2026-09-24T12:00:00Z","message":"{message}""#
    );
    if !tags.is_empty() {
        event.push_str(&format!(r#","tags":{tags}"#));
    }
    event.push('}');
    event
}

fn api_get(path: &str, token: &str) -> Request<Body> {
    Request::get(path.to_owned())
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn api_put_json(path: &str, token: &str, body: &str) -> Request<Body> {
    Request::put(path.to_owned())
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_owned()))
        .unwrap()
}

async fn response_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(error) => panic!(
            "non-JSON response ({error}): {}",
            String::from_utf8_lossy(&bytes)
        ),
    }
}

async fn issue_tags(db: &SqlitePool, issue_id: i64) -> Vec<String> {
    sqlx::query_scalar("SELECT tag FROM issue_tags WHERE issue_id=? ORDER BY tag")
        .bind(issue_id)
        .fetch_all(db)
        .await
        .unwrap()
}

#[tokio::test]
async fn ingest_seeds_issue_tags_from_event_tags() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_key(&db, 1, "zbk_test_key").await;
    seed_token(&db, 1, "zpat_owner_token").await;
    let app = test_app(db.clone());
    let event = event_body("evt-1", "boom", r#"{"env":"prod","shard":""}"#);
    let response = app
        .clone()
        .oneshot(ingest_request("demo", event))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let response = app
        .oneshot(api_get("/api/v1/projects/demo/issues", "zpat_owner_token"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let issues = response_json(response).await;
    assert_eq!(issues.as_array().unwrap().len(), 1);
    assert_eq!(issues[0]["tags"], serde_json::json!(["env:prod", "shard"]));
    assert_eq!(issues[0]["title"], "boom");
}

#[tokio::test]
async fn ingest_merges_new_tags_additively() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_key(&db, 1, "zbk_test_key").await;
    seed_token(&db, 1, "zpat_owner_token").await;
    let app = test_app(db.clone());
    for (id, tags) in [
        ("evt-1", r#"{"env":"prod"}"#),
        ("evt-2", r#"{"region":"eu","env":"prod"}"#),
        ("evt-3", ""),
    ] {
        let response = app
            .clone()
            .oneshot(ingest_request("demo", event_body(id, "boom", tags)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }
    // Same message groups all three events onto one issue whose tag set only
    // ever grows.
    let tags = issue_tags(&db, 1).await;
    assert_eq!(tags, vec!["env:prod".to_owned(), "region:eu".to_owned()]);
    let count: i64 = sqlx::query_scalar("SELECT event_count FROM issues WHERE id=1")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(count, 3);
}

#[tokio::test]
async fn list_issues_filters_by_tag() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_key(&db, 1, "zbk_test_key").await;
    seed_token(&db, 1, "zpat_owner_token").await;
    let app = test_app(db.clone());
    for (id, message, tags) in [
        ("evt-1", "alpha", r#"{"env":"prod"}"#),
        ("evt-2", "beta", r#"{"env":"staging"}"#),
    ] {
        let response = app
            .clone()
            .oneshot(ingest_request("demo", event_body(id, message, tags)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    let response = app
        .clone()
        .oneshot(api_get(
            "/api/v1/projects/demo/issues?tag=env%3Aprod",
            "zpat_owner_token",
        ))
        .await
        .unwrap();
    let issues = response_json(response).await;
    assert_eq!(issues.as_array().unwrap().len(), 1);
    assert_eq!(issues[0]["title"], "alpha");

    // AND semantics: no issue carries both tags.
    for query in ["tag=env%3Aprod,env%3Astaging", "tag=missing"] {
        let response = app
            .clone()
            .oneshot(api_get(
                &format!("/api/v1/projects/demo/issues?{query}"),
                "zpat_owner_token",
            ))
            .await
            .unwrap();
        let issues = response_json(response).await;
        assert!(
            issues.as_array().unwrap().is_empty(),
            "expected no matches for {query}"
        );
    }
}

#[tokio::test]
async fn list_issues_filters_by_status_and_pages() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_key(&db, 1, "zbk_test_key").await;
    seed_token(&db, 1, "zpat_owner_token").await;
    let app = test_app(db.clone());
    for (id, message) in [("evt-1", "alpha"), ("evt-2", "beta")] {
        let response = app
            .clone()
            .oneshot(ingest_request("demo", event_body(id, message, "")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }
    sqlx::query("UPDATE issues SET status='resolved' WHERE title='alpha'")
        .execute(&db)
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(api_get(
            "/api/v1/projects/demo/issues?status=resolved",
            "zpat_owner_token",
        ))
        .await
        .unwrap();
    let issues = response_json(response).await;
    assert_eq!(issues.as_array().unwrap().len(), 1);
    assert_eq!(issues[0]["title"], "alpha");

    let response = app
        .clone()
        .oneshot(api_get(
            "/api/v1/projects/demo/issues?limit=1&offset=1",
            "zpat_owner_token",
        ))
        .await
        .unwrap();
    let issues = response_json(response).await;
    assert_eq!(issues.as_array().unwrap().len(), 1);

    let response = app
        .oneshot(api_get(
            "/api/v1/projects/demo/issues?status=bogus",
            "zpat_owner_token",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn update_issue_tags_replaces_the_set() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_key(&db, 1, "zbk_test_key").await;
    seed_token(&db, 1, "zpat_owner_token").await;
    let app = test_app(db.clone());
    let response = app
        .clone()
        .oneshot(ingest_request(
            "demo",
            event_body("evt-1", "boom", r#"{"env":"prod"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let response = app
        .clone()
        .oneshot(api_put_json(
            "/api/v1/projects/demo/issues/1/tags",
            "zpat_owner_token",
            r#"{"tags":["team:core","env:prod"]}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response_json(response).await;
    assert_eq!(body["tags"], serde_json::json!(["env:prod", "team:core"]));

    // Replacing the set removes tags that are no longer listed.
    let response = app
        .clone()
        .oneshot(api_put_json(
            "/api/v1/projects/demo/issues/1/tags",
            "zpat_owner_token",
            r#"{"tags":["team:core"]}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(issue_tags(&db, 1).await, vec!["team:core".to_owned()]);

    let activity: i64 = sqlx::query_scalar("SELECT count(*) FROM issue_activity WHERE kind='tags'")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(activity, 2);
}

#[tokio::test]
async fn viewer_token_can_list_but_not_update_tags() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_key(&db, 1, "zbk_test_key").await;
    seed_token(&db, 1, "zpat_owner_token").await;
    seed_token(&db, 2, "zpat_viewer_token").await;
    let app = test_app(db.clone());
    let response = app
        .clone()
        .oneshot(ingest_request("demo", event_body("evt-1", "boom", "")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let response = app
        .clone()
        .oneshot(api_get("/api/v1/projects/demo/issues", "zpat_viewer_token"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(api_put_json(
            "/api/v1/projects/demo/issues/1/tags",
            "zpat_viewer_token",
            r#"{"tags":["x"]}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn invalid_tags_are_unprocessable() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_key(&db, 1, "zbk_test_key").await;
    seed_token(&db, 1, "zpat_owner_token").await;
    let app = test_app(db.clone());
    let response = app
        .clone()
        .oneshot(ingest_request("demo", event_body("evt-1", "boom", "")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    for body in [
        r#"{"tags":["bad tag"]}"#.to_owned(),
        r#"{"tags":["a,b"]}"#.to_owned(),
        format!(r#"{{"tags":["{}"]}}"#, "x".repeat(65)),
    ] {
        let response = app
            .clone()
            .oneshot(api_put_json(
                "/api/v1/projects/demo/issues/1/tags",
                "zpat_owner_token",
                &body,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let error = response_json(response).await;
        assert_eq!(error["code"], "validation_failed");
        assert_eq!(error["field"], "tags");
    }
}

#[tokio::test]
async fn api_tokens_are_validated_and_scoped() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_project(&db, 2, "other").await;
    seed_key(&db, 1, "zbk_test_key").await;
    seed_token(&db, 1, "zpat_owner_token").await;
    // User 3 owns a token but no project membership.
    sqlx::query(
        "INSERT OR IGNORE INTO users (id, email, display_name, password_hash)
         VALUES (3, 'outsider@example.com', 'Outsider', 'unused')",
    )
    .execute(&db)
    .await
    .unwrap();
    seed_token(&db, 3, "zpat_outsider_token").await;
    let app = test_app(db.clone());

    // Missing, non-token, and unknown credentials are all 401.
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/v1/projects/demo/issues")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = app
        .clone()
        .oneshot(api_get("/api/v1/projects/demo/issues", "zbk_test_key"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = app
        .clone()
        .oneshot(api_get("/api/v1/projects/demo/issues", "zpat_missing"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Tokens only reach projects the owning user is a member of.
    let response = app
        .clone()
        .oneshot(api_get(
            "/api/v1/projects/other/issues",
            "zpat_outsider_token",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Revocation takes effect immediately.
    sqlx::query("UPDATE api_tokens SET revoked_at=unixepoch() WHERE token_hash=?")
        .bind(token_hash("zpat_owner_token"))
        .execute(&db)
        .await
        .unwrap();
    let response = app
        .oneshot(api_get("/api/v1/projects/demo/issues", "zpat_owner_token"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ui_tag_form_edits_tags_with_csrf_and_roles() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_key(&db, 1, "zbk_test_key").await;
    let app = test_app(db.clone());
    let response = app
        .clone()
        .oneshot(ingest_request(
            "demo",
            event_body("evt-1", "boom", r#"{"env":"prod"}"#),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    // Owner session.
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at)
         VALUES (?, 1, 'owner-csrf', unixepoch() + 3600)",
    )
    .bind(token_hash("owner-session-token"))
    .execute(&db)
    .await
    .unwrap();
    // Viewer session.
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at)
         VALUES (?, 2, 'viewer-csrf', unixepoch() + 3600)",
    )
    .bind(token_hash("viewer-session-token"))
    .execute(&db)
    .await
    .unwrap();

    let form = |csrf: &str, tags: &str| {
        Request::post("/projects/demo/issues/1/tags")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("cookie", "zbierak_session=owner-session-token")
            .body(Body::from(format!("csrf_token={csrf}&tags={tags}")))
            .unwrap()
    };

    let response = app
        .clone()
        .oneshot(form("owner-csrf", "team%3Acore%2C%20env%3Aprod"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        issue_tags(&db, 1).await,
        vec!["env:prod".to_owned(), "team:core".to_owned()]
    );

    // A wrong CSRF token is rejected.
    let response = app.clone().oneshot(form("wrong-csrf", "x")).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Viewers cannot edit tags.
    let response = app
        .clone()
        .oneshot(
            Request::post("/projects/demo/issues/1/tags")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("cookie", "zbierak_session=viewer-session-token")
                .body(Body::from("csrf_token=viewer-csrf&tags=x"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // Invalid tags are rejected without changing anything.
    let response = app.oneshot(form("owner-csrf", "bad%20tag")).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        issue_tags(&db, 1).await,
        vec!["env:prod".to_owned(), "team:core".to_owned()]
    );
}

#[tokio::test]
async fn get_issue_returns_single_issue_with_tags() {
    let db = test_pool().await;
    seed_project(&db, 1, "demo").await;
    seed_key(&db, 1, "zbk_test_key").await;
    seed_token(&db, 1, "zpat_owner_token").await;
    let app = test_app(db.clone());
    let response = app
        .clone()
        .oneshot(ingest_request(
            "demo",
            event_body("evt-1", "boom", r#"{"env":"prod"}"#),
        ))
        .await
        .unwrap();
    let body = response_json(response).await;
    let issue_id = body["issue_id"].as_i64().unwrap();

    let response = app
        .clone()
        .oneshot(api_get(
            &format!("/api/v1/projects/demo/issues/{issue_id}"),
            "zpat_owner_token",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let issue = response_json(response).await;
    assert_eq!(issue["id"], issue_id);
    assert_eq!(issue["tags"], serde_json::json!(["env:prod"]));

    let response = app
        .oneshot(api_get(
            "/api/v1/projects/demo/issues/999",
            "zpat_owner_token",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
