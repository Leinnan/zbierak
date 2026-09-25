use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
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
///
/// Classification (status, code, client-safe message) comes from
/// [`AppError`] itself, so both response surfaces stay consistent and
/// internal failures never leak their source text.
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
        let status = self.0.status();
        if self.0.is_internal() {
            tracing::error!(error = %self.0, "api request failed");
        }
        let mut response = (
            status,
            Json(ApiErrorResponse {
                code: self.0.code().to_owned(),
                message: self.0.public_message().into_owned(),
                field: self.0.field().map(str::to_owned),
            }),
        )
            .into_response();
        if status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    use axum::http::StatusCode;
    use http_body_util::BodyExt;
    use serde_json::Value;
    use sqlx::Error as SqlxError;

    use super::{ApiError, ApiErrorResponse};
    use crate::AppError;

    /// Renders an error to `(status, www-authenticate, json-body)`, asserting
    /// the JSON content type along the way.
    async fn render(error: ApiError) -> (StatusCode, Option<String>, Value) {
        let response = axum::response::IntoResponse::into_response(error);
        let status = response.status();
        let www_authenticate = response
            .headers()
            .get("www-authenticate")
            .map(|value| value.to_str().unwrap().to_owned());
        let content_type = response
            .headers()
            .get("content-type")
            .map(|value| value.to_str().unwrap().to_owned())
            .unwrap_or_default();
        assert!(content_type.starts_with("application/json"));
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        (status, www_authenticate, body)
    }

    #[tokio::test]
    async fn internal_database_errors_are_redacted() {
        let (status, www_authenticate, body) =
            render(ApiError(SqlxError::RowNotFound.into())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["code"], "internal_error");
        assert_eq!(body["message"], "internal server error");
        assert!(body["field"].is_null());
        assert!(www_authenticate.is_none());
    }

    #[tokio::test]
    async fn unauthorized_responses_challenge_the_client() {
        let (status, www_authenticate, body) = render(ApiError(AppError::Unauthorized)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(www_authenticate.as_deref(), Some("Bearer"));
        assert_eq!(body["code"], "unauthorized");
        assert_eq!(body["message"], "authentication required");
    }

    #[tokio::test]
    async fn event_conflicts_use_the_dedicated_code() {
        let (status, www_authenticate, body) =
            render(ApiError(AppError::EventConflict("evt-1".into()))).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(www_authenticate.is_none());
        assert_eq!(body["code"], "event_id_conflict");
        assert!(body["message"].as_str().unwrap().contains("evt-1"));
    }

    #[tokio::test]
    async fn generic_conflicts_do_not_claim_event_ids() {
        let (status, _, body) = render(ApiError(AppError::Conflict("slug taken".into()))).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["code"], "conflict");
    }

    #[tokio::test]
    async fn validation_errors_carry_the_field() {
        let (status, _, body) = render(ApiError(AppError::Unprocessable {
            field: Some("tags".into()),
            message: "tag must not contain whitespace".into(),
        }))
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["code"], "validation_failed");
        assert_eq!(body["field"], "tags");
    }

    #[tokio::test]
    async fn payload_too_large_keeps_its_message() {
        let (status, _, body) = render(ApiError(AppError::PayloadTooLarge(
            "event exceeds 1 MiB".into(),
        )))
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body["code"], "payload_too_large");
        assert_eq!(body["message"], "payload too large: event exceeds 1 MiB");
    }

    /// The error body must deserialize into the published protocol type.
    #[tokio::test]
    async fn bodies_match_the_protocol_error_schema() {
        let response = axum::response::IntoResponse::into_response(ApiError(AppError::BadRequest(
            "nope".into(),
        )));
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let decoded: ApiErrorResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.code, "bad_request");
        assert_eq!(decoded.message, "nope");
        assert!(decoded.field.is_none());
    }
}
