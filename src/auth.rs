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

use crate::{AppError, AppResult, AppState};

pub const SESSION_COOKIE: &str = "zbierak_session";
pub const LOGIN_CSRF_COOKIE: &str = "zbierak_login_csrf";
const LOGIN_FAILURE_LIMIT: i64 = 5;
const LOGIN_LOCK_SECONDS: i64 = 900;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
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
}

#[derive(Debug, Clone)]
pub struct Session {
    pub user: User,
    pub csrf_token: String,
}

pub fn hash_password(password: &str) -> AppResult<String> {
    if password.len() < 12 || password.len() > 1024 {
        return Err(AppError::BadRequest(
            "password must contain between 12 and 1024 characters".into(),
        ));
    }
    Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map(|hash| hash.to_string())
        .map_err(|error| AppError::Config(format!("password hashing failed: {error}")))
}

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

pub fn token_hash(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn secure_eq(left: &str, right: &str) -> bool {
    left.len() == right.len() && left.as_bytes().ct_eq(right.as_bytes()).into()
}

pub async fn session(state: &AppState, cookies: &Cookies) -> AppResult<Option<Session>> {
    let Some(cookie) = cookies.get(SESSION_COOKIE) else {
        return Ok(None);
    };
    let hash = token_hash(cookie.value());
    let row = sqlx::query_as::<_, (i64, String, String, String)>(
        "SELECT u.id, u.email, u.display_name, s.csrf_token
         FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ? AND s.expires_at > unixepoch()",
    )
    .bind(hash)
    .fetch_optional(&state.db)
    .await?;
    Ok(row.map(|(id, email, display_name, csrf_token)| Session {
        user: User {
            id,
            email,
            display_name,
        },
        csrf_token,
    }))
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
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let expires_at = now + state.config.session_days * 86_400;
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

pub fn bearer(headers: &HeaderMap) -> AppResult<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or(AppError::Unauthorized)
}

pub async fn require_project_role(
    state: &AppState,
    user_id: i64,
    slug: &str,
    minimum: &str,
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
    if role_rank(&row.1) < role_rank(minimum) {
        return Err(AppError::Forbidden);
    }
    Ok(row.0)
}

pub(crate) fn role_rank(role: &str) -> u8 {
    match role {
        "owner" => 4,
        "admin" => 3,
        "developer" => 2,
        "viewer" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::{hash_password, role_rank, secure_eq, token_hash, verify_password};

    #[test]
    fn password_round_trip() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("incorrect password", &hash));
    }

    #[test]
    fn tokens_are_hashed_and_compared() {
        assert_eq!(token_hash("key"), token_hash("key"));
        assert!(secure_eq("abc", "abc"));
        assert!(!secure_eq("abc", "abd"));
    }

    #[test]
    fn roles_are_ordered_by_capability() {
        assert!(role_rank("owner") > role_rank("admin"));
        assert!(role_rank("admin") > role_rank("developer"));
        assert!(role_rank("developer") > role_rank("viewer"));
        assert_eq!(role_rank("unknown"), 0);
    }
}
