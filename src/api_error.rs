use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::AppError;

/// JSON error body returned by the versioned HTTP API.
///
/// The operator UI keeps rendering HTML errors; only `/api/v1/*` handlers wrap
/// failures in [`ApiError`] so clients receive a machine-readable body. The
/// shape is the protocol crate's [`zbierak_protocol::ApiErrorResponse`].
pub use zbierak_protocol::ApiErrorResponse;

/// Adapter that renders [`AppError`] as a JSON response for API routes.
pub struct ApiError(pub AppError);

impl<E> From<E> for ApiError
where
    AppError: From<E>,
{
    fn from(error: E) -> Self {
        Self(AppError::from(error))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, field) = match &self.0 {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", None),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "forbidden", None),
            AppError::NotFound => (StatusCode::NOT_FOUND, "not_found", None),
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request", None),
            AppError::Conflict(_) => (StatusCode::CONFLICT, "event_id_conflict", None),
            AppError::PayloadTooLarge(_) => {
                (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", None)
            }
            AppError::Unprocessable { field, .. } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "validation_failed",
                field.clone(),
            ),
            _ => {
                tracing::error!(error = %self.0, "api request failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", None)
            }
        };
        (
            status,
            Json(ApiErrorResponse {
                code: code.to_owned(),
                message: self.0.to_string(),
                field,
            }),
        )
            .into_response()
    }
}
