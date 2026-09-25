use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::http::HeaderMap;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::FromRow;
use subtle::ConstantTimeEq;
use tower_cookies::{Cookie, Cookies, cookie::SameSite};

use crate::{AppError, AppResult, AppState, domain::ProjectRole};

pub const SESSION_COOKIE: &str = "zbierak_session";
pub const LOGIN_CSRF_COOKIE: &str = "zbierak_login_csrf";
const LOGIN_FAILURE_LIMIT: i64 = 5;
const LOGIN_LOCK_SECONDS: i64 = 900;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .cast_signed()
}

/// Login throttling is keyed by the SHA-256 of the lowercased email so the raw
/// address never rests in the throttle table.
fn login_identity(email: &str) -> String {
    token_hash(&email.trim().to_ascii_lowercase())
}

/// Returns true when login attempts for this email are currently locked out.
pub async fn login_locked(state: &AppState, email: &str) -> AppResult<bool> {
    let locked_until: Option<Option<i64>> =
        sqlx::query_scalar("SELECT locked_until FROM login_throttle WHERE identity_hash = ?")
            .bind(login_identity(email))
            .fetch_optional(&state.db)
            .await?;
    Ok(locked_until.flatten().is_some_and(|until| until > now()))
}

/// Records a failed login attempt. After [`LOGIN_FAILURE_LIMIT`] consecutive
/// failures the identity is locked out for [`LOGIN_LOCK_SECONDS`].
pub async fn login_failure(state: &AppState, email: &str) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO login_throttle (identity_hash, failures, locked_until, updated_at)
         VALUES (?, 1, NULL, unixepoch())
         ON CONFLICT(identity_hash) DO UPDATE SET
           failures = CASE
             WHEN login_throttle.locked_until IS NOT NULL AND login_throttle.locked_until > unixepoch()
               THEN login_throttle.failures
             WHEN login_throttle.locked_until IS NOT NULL
               THEN 1
             ELSE login_throttle.failures + 1 END,
           locked_until = CASE
             WHEN login_throttle.locked_until IS NOT NULL AND login_throttle.locked_until > unixepoch()
               THEN login_throttle.locked_until
             WHEN login_throttle.locked_until IS NOT NULL
               THEN NULL
             WHEN login_throttle.failures + 1 >= ?
               THEN unixepoch() + ?
             ELSE NULL END,
           updated_at = unixepoch()",
    )
    .bind(login_identity(email))
    .bind(LOGIN_FAILURE_LIMIT)
    .bind(LOGIN_LOCK_SECONDS)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// Clears throttling state after a successful login.
pub async fn login_success(state: &AppState, email: &str) -> AppResult<()> {
    sqlx::query("DELETE FROM login_throttle WHERE identity_hash = ?")
        .bind(login_identity(email))
        .execute(&state.db)
        .await?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub display_name: String,
    /// Uploaded avatar reference, or `None` to render generated initials.
    #[sqlx(skip)]
    pub avatar: Option<AvatarRef>,
}

/// Cache-busting handle for a stored avatar, exposed to templates.
#[derive(Debug, Clone, Serialize)]
pub struct AvatarRef {
    /// Same-origin URL that serves the avatar bytes.
    pub url: String,
    /// Short content digest used to version the URL.
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub user: User,
    pub csrf_token: String,
}

/// Hashes a password with Argon2id for storage.
///
/// # Errors
///
/// Returns [`AppError::BadRequest`] when the password is outside the
/// 12-1024 character limit, and an internal error when hashing fails.
pub fn hash_password(password: &str) -> AppResult<String> {
    // Counted in characters to match the error message (and `required_text`).
    let length = password.chars().count();
    if !(12..=1024).contains(&length) {
        return Err(AppError::BadRequest(
            "password must contain between 12 and 1024 characters".into(),
        ));
    }
    Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map(|hash| hash.to_string())
        .map_err(|error| AppError::Config(format!("password hashing failed: {error}")))
}

/// Verifies a password against a stored Argon2 hash. Malformed stored
/// hashes verify as `false` rather than panicking.
#[must_use]
pub fn verify_password(password: &str, encoded: &str) -> bool {
    let Ok(hash) = PasswordHash::new(encoded) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &hash)
        .is_ok()
}

pub fn random_token(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    rand::thread_rng().fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

/// Lowercase hexadecimal SHA-256 digest of a token, the form stored in the
/// database; raw tokens are never persisted.
#[must_use]
pub fn token_hash(token: &str) -> String {
    sha256_hex(token.as_bytes())
}

/// Lowercase hexadecimal SHA-256 digest shared by token hashing and event
/// body hashing so the encoding stays identical across security surfaces.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(2 * digest.len());
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

pub fn secure_eq(left: &str, right: &str) -> bool {
    left.len() == right.len() && left.as_bytes().ct_eq(right.as_bytes()).into()
}

pub async fn session(state: &AppState, cookies: &Cookies) -> AppResult<Option<Session>> {
    let Some(cookie) = cookies.get(SESSION_COOKIE) else {
        return Ok(None);
    };
    let hash = token_hash(cookie.value());
    let row = sqlx::query_as::<_, (i64, String, String, String, Option<String>)>(
        "SELECT u.id, u.email, u.display_name, s.csrf_token, a.sha256
         FROM sessions s
         JOIN users u ON u.id = s.user_id
         LEFT JOIN user_avatars a ON a.user_id = u.id
         WHERE s.token_hash = ? AND s.expires_at > unixepoch()",
    )
    .bind(hash)
    .fetch_optional(&state.db)
    .await?;
    Ok(row.map(
        |(id, email, display_name, csrf_token, avatar_sha256)| Session {
            user: User {
                id,
                email,
                display_name,
                avatar: avatar_sha256.map(|sha256| AvatarRef {
                    url: format!("/users/{id}/avatar?v={}", &sha256[..sha256.len().min(16)]),
                    version: sha256,
                }),
            },
            csrf_token,
        },
    ))
}

pub async fn require_session(state: &AppState, cookies: &Cookies) -> AppResult<Session> {
    session(state, cookies).await?.ok_or(AppError::Unauthorized)
}

pub fn check_csrf(session: &Session, supplied: &str) -> AppResult<()> {
    if secure_eq(&session.csrf_token, supplied) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

pub async fn create_session(state: &AppState, cookies: &Cookies, user_id: i64) -> AppResult<()> {
    let token = random_token(32);
    let csrf = random_token(24);
    let expires_at = now() + state.config.session_days * 86_400;
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)",
    )
    .bind(token_hash(&token))
    .bind(user_id)
    .bind(csrf)
    .bind(expires_at)
    .execute(&state.db)
    .await?;
    let cookie = Cookie::build((SESSION_COOKIE, token))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(state.config.cookie_secure)
        .max_age(tower_cookies::cookie::time::Duration::days(
            state.config.session_days,
        ))
        .build();
    cookies.add(cookie);
    Ok(())
}

pub async fn destroy_session(state: &AppState, cookies: &Cookies) -> AppResult<()> {
    if let Some(cookie) = cookies.get(SESSION_COOKIE) {
        sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
            .bind(token_hash(cookie.value()))
            .execute(&state.db)
            .await?;
    }
    let removal = Cookie::build(SESSION_COOKIE).path("/").build();
    cookies.remove(removal);
    Ok(())
}

/// Extracts the credential from an `Authorization: Bearer …` header.
///
/// The scheme comparison is case-insensitive per RFC 9110; the credential
/// itself is preserved exactly.
pub fn bearer(headers: &HeaderMap) -> AppResult<&str> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    let (scheme, credential) = value.split_once(' ').ok_or(AppError::Unauthorized)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(AppError::Unauthorized);
    }
    let credential = credential.trim();
    if credential.is_empty() {
        return Err(AppError::Unauthorized);
    }
    Ok(credential)
}

/// Prefix identifying a personal API token issued from the settings page.
pub const API_TOKEN_PREFIX: &str = "zpat_";

/// Resolves an `Authorization: Bearer zpat_…` personal API token to the
/// owning user id. Revoked or unknown tokens are rejected with 401, and the
/// last-used timestamp is refreshed on success.
pub async fn api_token_user(state: &AppState, headers: &HeaderMap) -> AppResult<i64> {
    let bearer = bearer(headers)?;
    if !bearer.starts_with(API_TOKEN_PREFIX) {
        return Err(AppError::Unauthorized);
    }
    let hash = token_hash(bearer);
    let user_id = sqlx::query_scalar::<_, i64>(
        "SELECT user_id FROM api_tokens WHERE token_hash=? AND revoked_at IS NULL",
    )
    .bind(&hash)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::Unauthorized)?;
    sqlx::query("UPDATE api_tokens SET last_used_at=unixepoch() WHERE token_hash=?")
        .bind(&hash)
        .execute(&state.db)
        .await?;
    Ok(user_id)
}

/// Resolves an `Authorization: Bearer zbk_…` ingest key for one project slug
/// to `(key_id, project_id)`. Unknown slugs, unknown keys, and revoked keys
/// all produce the same 401 so project existence is never revealed.
pub async fn ingest_key_project(
    state: &AppState,
    headers: &HeaderMap,
    slug: &str,
) -> AppResult<(i64, i64)> {
    let bearer = bearer(headers)?;
    let key_hash = token_hash(bearer);
    sqlx::query_as::<_, (i64, i64)>(
        "SELECT k.id, k.project_id FROM ingest_keys k JOIN projects p ON p.id=k.project_id
         WHERE p.slug=? AND k.key_hash=? AND k.revoked_at IS NULL",
    )
    .bind(slug)
    .bind(&key_hash)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::Unauthorized)
}

/// Returns true when `user_id` is the instance owner, defined as the first
/// user ever created (bootstrap). Users are never deleted, so the lowest id
/// always identifies the bootstrap account.
pub async fn is_instance_owner(state: &AppState, user_id: i64) -> AppResult<bool> {
    let first: Option<i64> = sqlx::query_scalar("SELECT MIN(id) FROM users")
        .fetch_one(&state.db)
        .await?;
    Ok(first == Some(user_id))
}

/// Loads a user by id, attaching the avatar reference when one is stored.
/// Returns `None` for unknown ids.
pub async fn user_by_id(state: &AppState, user_id: i64) -> AppResult<Option<User>> {
    let row = sqlx::query_as::<_, (i64, String, String, Option<String>)>(
        "SELECT u.id, u.email, u.display_name, a.sha256
         FROM users u
         LEFT JOIN user_avatars a ON a.user_id = u.id
         WHERE u.id = ?",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(row.map(|(id, email, display_name, avatar_sha256)| User {
        id,
        email,
        display_name,
        avatar: avatar_sha256.map(|sha256| AvatarRef {
            url: format!("/users/{id}/avatar?v={}", &sha256[..sha256.len().min(16)]),
            version: sha256,
        }),
    }))
}

/// Requires membership in the project identified by `slug` with at least
/// `minimum` capability. Unknown roles stored in the database fail closed.
/// Returns the project id on success.
pub async fn require_project_role(
    state: &AppState,
    user_id: i64,
    slug: &str,
    minimum: ProjectRole,
) -> AppResult<i64> {
    let row = sqlx::query_as::<_, (i64, String)>(
        "SELECT p.id, m.role FROM projects p JOIN project_memberships m ON m.project_id = p.id
         WHERE p.slug = ? AND m.user_id = ?",
    )
    .bind(slug)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)?;
    let actual = ProjectRole::parse(&row.1).ok_or(AppError::Forbidden)?;
    if actual < minimum {
        return Err(AppError::Forbidden);
    }
    Ok(row.0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    use axum::http::{HeaderMap, HeaderValue, header};

    use super::{bearer, hash_password, secure_eq, token_hash, verify_password};
    use crate::domain::ProjectRole;

    fn authorization(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn password_round_trip() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("incorrect password", &hash));
    }

    #[test]
    fn password_length_is_counted_in_characters() {
        // 12 bytes but only 3 characters: rejected despite sufficient bytes.
        assert!(hash_password("\u{1F600}\u{1F600}\u{1F600}").is_err());
        // 4 emoji = 4 characters but 16 bytes: still rejected.
        assert!(hash_password("\u{1F600}".repeat(4).as_str()).is_err());
        // 12 characters of emoji: accepted.
        assert!(hash_password("\u{1F600}".repeat(12).as_str()).is_ok());
        assert!(hash_password("short").is_err());
    }

    #[test]
    fn tokens_are_hashed_and_compared() {
        assert_eq!(token_hash("key"), token_hash("key"));
        assert!(secure_eq("abc", "abc"));
        assert!(!secure_eq("abc", "abd"));
    }

    #[test]
    fn roles_are_ordered_by_capability() {
        assert!(ProjectRole::Owner > ProjectRole::Admin);
        assert!(ProjectRole::Admin > ProjectRole::Developer);
        assert!(ProjectRole::Developer > ProjectRole::Viewer);
        assert_eq!(ProjectRole::parse("unknown"), None);
    }

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        for scheme in ["Bearer", "bearer", "BEARER", "bEaReR"] {
            let headers = authorization(&format!("{scheme} zbk_test_key"));
            assert_eq!(bearer(&headers).unwrap(), "zbk_test_key");
        }
    }

    #[test]
    fn bearer_rejects_missing_malformed_and_empty_credentials() {
        assert!(bearer(&HeaderMap::new()).is_err());
        assert!(bearer(&authorization("zbk_test_key")).is_err());
        assert!(bearer(&authorization("Basic zbk_test_key")).is_err());
        assert!(bearer(&authorization("Bearer ")).is_err());
        assert!(bearer(&authorization("Bearer    ")).is_err());
    }
}
