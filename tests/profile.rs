#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(missing_docs)]

mod common;

use std::io::Cursor;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use common::{LoggedIn, app_with_templates, login, test_pool};
use http_body_util::BodyExt;
use image::{DynamicImage, ImageFormat, Rgb, RgbImage};
use sqlx::SqlitePool;
use tower::ServiceExt;
use zbierak::hash_password;

const EMAIL: &str = "owner@example.com";
const PASSWORD: &str = "correct-horse-staple-12";
const BOUNDARY: &str = "zbierak-test-boundary";

async fn seeded_app() -> (Router, SqlitePool, LoggedIn) {
    let db = test_pool().await;
    sqlx::query("INSERT INTO users (email, display_name, password_hash) VALUES (?, 'Owner', ?)")
        .bind(EMAIL)
        .bind(hash_password(PASSWORD).unwrap())
        .execute(&db)
        .await
        .unwrap();
    let app = app_with_templates(db.clone());
    let logged_in = login(&app, &db, EMAIL, PASSWORD).await;
    (app, db, logged_in)
}

fn png_bytes(width: u32, height: u32) -> Vec<u8> {
    let image = DynamicImage::ImageRgb8(RgbImage::from_pixel(width, height, Rgb([20, 110, 80])));
    let mut bytes = Vec::new();
    image
        .write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
        .unwrap();
    bytes
}

fn multipart_body(csrf: &str, filename: &str, content_type: &str, bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"csrf_token\"\r\n\r\n");
    body.extend_from_slice(csrf.as_bytes());
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    body.extend_from_slice(
        format!("Content-Disposition: form-data; name=\"avatar\"; filename=\"{filename}\"\r\n")
            .as_bytes(),
    );
    body.extend_from_slice(format!("Content-Type: {content_type}\r\n\r\n").as_bytes());
    body.extend_from_slice(bytes);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    body
}

fn upload_request(
    logged_in: &LoggedIn,
    csrf: &str,
    filename: &str,
    content_type: &str,
    bytes: &[u8],
) -> Request<Body> {
    Request::post("/users/1/avatar")
        .header("cookie", logged_in.cookie_header.clone())
        .header(
            "content-type",
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .body(Body::from(multipart_body(
            csrf,
            filename,
            content_type,
            bytes,
        )))
        .unwrap()
}

fn avatar_get(logged_in: &LoggedIn, user_id: i64) -> Request<Body> {
    Request::get(format!("/users/{user_id}/avatar"))
        .header("cookie", logged_in.cookie_header.clone())
        .body(Body::empty())
        .unwrap()
}

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

#[tokio::test]
async fn display_name_change_updates_sidebar_and_is_audited() {
    let (app, db, logged_in) = seeded_app().await;

    let response = app
        .clone()
        .oneshot(logged_in.post_form(
            "/users/1/profile",
            &[("csrf_token", &logged_in.csrf), ("display_name", "Renamed")],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(body_text(response).await.contains("Renamed"));

    let stored: String = sqlx::query_scalar("SELECT display_name FROM users WHERE id=1")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(stored, "Renamed");
    let audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action='user.updated' AND user_id=1",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(audits, 1);
}

#[tokio::test]
async fn display_name_change_rejects_a_blank_name() {
    let (app, db, logged_in) = seeded_app().await;

    let response = app
        .oneshot(logged_in.post_form(
            "/users/1/profile",
            &[("csrf_token", &logged_in.csrf), ("display_name", "")],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let stored: String = sqlx::query_scalar("SELECT display_name FROM users WHERE id=1")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(stored, "Owner");
}

#[tokio::test]
async fn display_name_change_requires_csrf() {
    let (app, _db, logged_in) = seeded_app().await;

    let response = app
        .oneshot(logged_in.post_form(
            "/users/1/profile",
            &[("csrf_token", "wrong"), ("display_name", "Nope")],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn avatar_upload_serves_conditional_content_and_can_be_removed() {
    let (app, db, logged_in) = seeded_app().await;
    let upload = png_bytes(400, 120);

    let response = app
        .clone()
        .oneshot(upload_request(
            &logged_in,
            &logged_in.csrf,
            "photo.png",
            "image/png",
            &upload,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let (content_type, sha256, stored): (String, String, Vec<u8>) =
        sqlx::query_as("SELECT content_type, sha256, bytes FROM user_avatars WHERE user_id=1")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(content_type, "image/png");
    assert!(stored.starts_with(&[0x89, b'P', b'N', b'G']));

    let served = app
        .clone()
        .oneshot(avatar_get(&logged_in, 1))
        .await
        .unwrap();
    assert_eq!(served.status(), StatusCode::OK);
    assert_eq!(
        served.headers().get(header::CONTENT_TYPE).unwrap(),
        "image/png"
    );
    let etag = served
        .headers()
        .get(header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(etag, format!("\"{sha256}\""));

    let mut conditional = avatar_get(&logged_in, 1);
    conditional
        .headers_mut()
        .insert(header::IF_NONE_MATCH, etag.parse().unwrap());
    let cached = app.clone().oneshot(conditional).await.unwrap();
    assert_eq!(cached.status(), StatusCode::NOT_MODIFIED);

    let removed = app
        .clone()
        .oneshot(logged_in.post_form("/users/1/avatar/delete", &[("csrf_token", &logged_in.csrf)]))
        .await
        .unwrap();
    assert_eq!(removed.status(), StatusCode::OK);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM user_avatars WHERE user_id=1")
            .fetch_one(&db)
            .await
            .unwrap(),
        0
    );
    let gone = app.oneshot(avatar_get(&logged_in, 1)).await.unwrap();
    assert_eq!(gone.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn avatar_upload_rejects_non_image_and_wrong_csrf() {
    let (app, db, logged_in) = seeded_app().await;

    let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>";
    let response = app
        .clone()
        .oneshot(upload_request(
            &logged_in,
            &logged_in.csrf,
            "avatar.svg",
            "image/svg+xml",
            svg,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let response = app
        .clone()
        .oneshot(upload_request(
            &logged_in,
            "wrong",
            "photo.png",
            "image/png",
            &png_bytes(64, 64),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM user_avatars WHERE user_id=1")
            .fetch_one(&db)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn avatar_requires_an_authenticated_session() {
    let (app, _db, _logged_in) = seeded_app().await;

    let response = app
        .oneshot(Request::get("/users/1/avatar").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
