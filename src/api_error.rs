use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::AppError;

/// JSON error body returned by the versioned HTTP API.
///
/// The operator UI keeps rendering HTML errors; only `/api/v1/*` handlers wrap
/// failures in [`ApiError`] so clients receive a machine-readable body.
#[cfg_attr(feature = "docs", derive(utoipa::ToSchema))]
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    /// Stable machine-readable error code.
    pub code: String,
    /// Human-readable explanation.
    pub message: String,
    /// Field that caused the error, when the failure is field-scoped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

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
            Json(ErrorResponse {
                code: code.to_owned(),
                message: self.0.to_string(),
                field,
            }),
        )
            .into_response()
    }
}
