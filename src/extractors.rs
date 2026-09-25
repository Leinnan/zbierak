//! Typed Axum extractors that enforce the HTTP contract at the boundary.
//!
//! Every extractor rejects with the application's own error types, so
//! clients never receive Axum's default rejection bodies: the JSON API
//! answers with the JSON error format, the operator UI with the HTML error
//! surface. Authentication extractors ([`ApiPrincipal`], [`IngestProject`],
//! [`UiSession`]) implement [`FromRequestParts`], which lets them run
//! before any body extractor so unauthenticated requests never pay for
//! body parsing or buffering.

use axum::{
    extract::{
        DefaultBodyLimit, FromRequest, FromRequestParts, Path as AxumPath, Query as AxumQuery,
        Request,
        rejection::{
            BytesRejection, FailedToBufferBody, FormRejection, JsonRejection, PathRejection,
            QueryRejection,
        },
    },
    http::{header::CONTENT_TYPE, request::Parts},
};
use serde::de::DeserializeOwned;
use tower_cookies::Cookies;

use crate::{AppError, AppState, api_error::ApiError, auth};

/// Maximum accepted ingestion body, enforced by [`ApiEventBody`].
pub const EVENT_BODY_LIMIT: usize = 1_048_576;

/// Maximum body size for operator UI forms and small management JSON payloads.
pub const FORM_BODY_LIMIT: usize = 65_536;

/// `Path` extractor for API routes that rejects with the JSON error format.
pub struct ApiPath<T>(pub T);

impl<S, T> FromRequestParts<S> for ApiPath<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match AxumPath::<T>::from_request_parts(parts, state).await {
            Ok(value) => Ok(Self(value.0)),
            Err(rejection) => Err(path_rejection_error(&rejection).into()),
        }
    }
}

/// `Query` extractor for API routes that rejects with the JSON error format.
pub struct ApiQuery<T>(pub T);

impl<S, T> FromRequestParts<S> for ApiQuery<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match AxumQuery::<T>::from_request_parts(parts, state).await {
            Ok(value) => Ok(Self(value.0)),
            Err(rejection) => Err(query_rejection_error(&rejection).into()),
        }
    }
}

/// `Json` extractor for API routes that rejects with the JSON error format.
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        axum::Json::<T>::from_request(req, state)
            .await
            .map(|axum::Json(value)| Self(value))
            .map_err(|rejection| json_rejection_error(&rejection).into())
    }
}

/// Raw ingestion body: requires a JSON media type and enforces the 1 MiB
/// event limit at the boundary, replacing the former post-buffering check.
pub struct ApiEventBody {
    /// The buffered request body, at most [`EVENT_BODY_LIMIT`] bytes.
    pub bytes: axum::body::Bytes,
}

impl<S> FromRequest<S> for ApiEventBody
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        if !is_json_media_type(req.headers()) {
            return Err(AppError::UnsupportedMediaType.into());
        }
        let mut req = req;
        DefaultBodyLimit::max(EVENT_BODY_LIMIT).apply(&mut req);
        let bytes = axum::body::Bytes::from_request(req, state)
            .await
            .map_err(|rejection| body_rejection_error(&rejection))?;
        Ok(Self { bytes })
    }
}

/// `Form` extractor for operator UI routes that rejects with the HTML error
/// surface instead of Axum's plain-text rejections.
pub struct UiForm<T>(pub T);

impl<S, T> FromRequest<S> for UiForm<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        axum::Form::<T>::from_request(req, state)
            .await
            .map(|axum::Form(value)| Self(value))
            .map_err(|rejection| match &rejection {
                FormRejection::BytesRejection(bytes) => body_rejection_error(bytes),
                other => AppError::BadRequest(other.body_text()),
            })
    }
}

/// Authenticated operator session resolved before the request body is read.
///
/// Carries the [`Cookies`] handle because several session lifecycle handlers
/// (logout, settings) must read or replace the session cookie themselves.
pub struct UiSession {
    /// The authenticated operator session.
    pub session: auth::Session,
    /// Cookie handle for handlers that rotate or destroy the session cookie.
    pub cookies: Cookies,
}

impl FromRequestParts<AppState> for UiSession {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let cookies = Cookies::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::Unauthorized)?;
        let session = auth::require_session(state, &cookies).await?;
        Ok(Self { session, cookies })
    }
}

/// Personal API token principal (`zpat_…`) resolved from the
/// `Authorization` header before any body extractor runs.
pub struct ApiPrincipal {
    /// Owning user of the personal API token.
    pub user_id: i64,
}

impl FromRequestParts<AppState> for ApiPrincipal {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let user_id = auth::api_token_user(state, &parts.headers).await?;
        Ok(Self { user_id })
    }
}

/// Ingest credentials (`zbk_…`) bound to the project slug in the path,
/// resolved before the event body is buffered.
pub struct IngestProject {
    /// Database id of the ingest key used for authentication.
    pub key_id: i64,
    /// Database id of the project the key belongs to.
    pub project_id: i64,
    /// Project slug from the request path.
    pub slug: String,
}

impl FromRequestParts<AppState> for IngestProject {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let AxumPath(slug) = AxumPath::<String>::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::NotFound)?;
        let (key_id, project_id) = auth::ingest_key_project(state, &parts.headers, &slug).await?;
        Ok(Self {
            key_id,
            project_id,
            slug,
        })
    }
}

fn path_rejection_error(rejection: &PathRejection) -> AppError {
    AppError::BadRequest(rejection.body_text())
}

fn query_rejection_error(rejection: &QueryRejection) -> AppError {
    AppError::BadRequest(rejection.body_text())
}

fn json_rejection_error(rejection: &JsonRejection) -> AppError {
    match rejection {
        JsonRejection::JsonSyntaxError(error) => AppError::BadRequest(error.body_text()),
        JsonRejection::JsonDataError(error) => AppError::Unprocessable {
            field: None,
            message: error.body_text(),
        },
        JsonRejection::MissingJsonContentType(_) => AppError::UnsupportedMediaType,
        JsonRejection::BytesRejection(bytes) => body_rejection_error(bytes),
        _ => AppError::BadRequest("invalid JSON request body".into()),
    }
}

fn body_rejection_error(rejection: &BytesRejection) -> AppError {
    match rejection {
        BytesRejection::FailedToBufferBody(FailedToBufferBody::LengthLimitError(_)) => {
            AppError::PayloadTooLarge("request body exceeds the allowed size".into())
        }
        BytesRejection::FailedToBufferBody(FailedToBufferBody::UnknownBodyError(error)) => {
            AppError::BadRequest(format!("could not read request body: {error}"))
        }
        _ => AppError::BadRequest("could not read request body".into()),
    }
}

/// Accepts `application/json` and structured-syntax `+json` subtypes, with
/// optional media-type parameters (`; charset=utf-8`).
fn is_json_media_type(headers: &axum::http::HeaderMap) -> bool {
    let Some(raw) = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let base = raw
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    base == "application/json" || base.ends_with("+json")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    use super::{CONTENT_TYPE, is_json_media_type};
    use axum::http::HeaderMap;

    fn media_type(value: Option<&str>) -> bool {
        let mut headers = HeaderMap::new();
        if let Some(value) = value
            && let Ok(parsed) = axum::http::HeaderValue::from_str(value)
        {
            headers.insert(CONTENT_TYPE, parsed);
        }
        is_json_media_type(&headers)
    }

    #[test]
    fn json_media_types_are_recognized() {
        assert!(media_type(Some("application/json")));
        assert!(media_type(Some("application/json; charset=utf-8")));
        assert!(media_type(Some("application/vnd.api+json")));
        assert!(media_type(Some("APPLICATION/JSON")));
        assert!(!media_type(Some("text/plain")));
        assert!(!media_type(Some("application/x-www-form-urlencoded")));
        assert!(!media_type(None));
    }
}
