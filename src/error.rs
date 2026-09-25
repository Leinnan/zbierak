use std::borrow::Cow;

use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

/// Result alias for application fallibility; every handler returns this.
pub type AppResult<T> = Result<T, AppError>;

/// The single application error type shared by the HTML and JSON surfaces.
///
/// Both response adapters classify through [`AppError::status`],
/// [`AppError::code`], and [`AppError::public_message`], so the two surfaces
/// always agree and internal failures never leak their source text.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// Server-side misconfiguration; the operator, not the caller, must fix it.
    #[error("{0}")]
    Config(String),
    /// No or invalid credentials.
    #[error("authentication required")]
    Unauthorized,
    /// Authenticated, but not allowed to perform the action.
    #[error("forbidden")]
    Forbidden,
    /// The requested resource does not exist (or existence is withheld).
    #[error("not found")]
    NotFound,
    /// The HTTP method is not defined for the route.
    #[error("method not allowed")]
    MethodNotAllowed,
    /// The request media type is not accepted by the route.
    #[error("unsupported media type")]
    UnsupportedMediaType,
    /// Client input failed validation; the message is safe to display.
    #[error("{0}")]
    BadRequest(String),
    /// A generic client-facing conflict (e.g. duplicate slug).
    #[error("{0}")]
    Conflict(String),
    /// A producer event id was reused with different content.
    #[error("event_id {0} was already ingested with different content")]
    EventConflict(String),
    /// The request body exceeds the route's size limit.
    #[error("payload too large: {0}")]
    PayloadTooLarge(String),
    /// Structurally valid input failed domain validation.
    #[error("{message}")]
    Unprocessable {
        /// Request field that caused the failure, when one applies.
        field: Option<String>,
        /// Validation explanation, safe to display.
        message: String,
    },
    /// A database error occurred.
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    /// A database migration failed (startup only).
    #[error(transparent)]
    Migration(#[from] sqlx::migrate::MigrateError),
    /// Template rendering failed.
    #[error(transparent)]
    Template(#[from] tera::Error),
    /// An outbound HTTP request failed.
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    /// A filesystem operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl AppError {
    /// HTTP status this error maps to, shared by the HTML and JSON surfaces.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Conflict(_) | Self::EventConflict(_) => StatusCode::CONFLICT,
            Self::PayloadTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Unprocessable { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            // Configuration problems are server-side: the operator, not the
            // caller, has to fix them.
            Self::Config(_)
            | Self::Database(_)
            | Self::Migration(_)
            | Self::Template(_)
            | Self::Http(_)
            | Self::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Stable machine-readable error code for the JSON API.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::BadRequest(_) => "bad_request",
            Self::Conflict(_) => "conflict",
            Self::EventConflict(_) => "event_id_conflict",
            Self::PayloadTooLarge(_) => "payload_too_large",
            Self::Unprocessable { .. } => "validation_failed",
            Self::Config(_)
            | Self::Database(_)
            | Self::Migration(_)
            | Self::Template(_)
            | Self::Http(_)
            | Self::Io(_) => "internal_error",
        }
    }

    /// Message that is safe to send to clients. Only variants whose text is
    /// fully constructed by application code keep their message; every
    /// internal source (SQL, templates, HTTP client, filesystem, environment)
    /// is redacted so implementation details never leak into a response.
    #[must_use]
    pub fn public_message(&self) -> Cow<'_, str> {
        match self {
            Self::Unauthorized
            | Self::Forbidden
            | Self::NotFound
            | Self::MethodNotAllowed
            | Self::UnsupportedMediaType
            | Self::BadRequest(_)
            | Self::Conflict(_)
            | Self::EventConflict(_)
            | Self::PayloadTooLarge(_)
            | Self::Unprocessable { .. } => Cow::Owned(self.to_string()),
            Self::Config(_)
            | Self::Database(_)
            | Self::Migration(_)
            | Self::Template(_)
            | Self::Http(_)
            | Self::Io(_) => Cow::Borrowed("internal server error"),
        }
    }

    /// Request field that caused the error, when one applies.
    #[must_use]
    pub fn field(&self) -> Option<&str> {
        match self {
            Self::Unprocessable { field, .. } => field.as_deref(),
            _ => None,
        }
    }

    /// True when the error represents an unexpected server-side failure and
    /// should be logged at error level with its full internals.
    #[must_use]
    pub fn is_internal(&self) -> bool {
        matches!(
            self,
            Self::Config(_)
                | Self::Database(_)
                | Self::Migration(_)
                | Self::Template(_)
                | Self::Http(_)
                | Self::Io(_)
        )
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();
        let message = self.public_message();
        if self.is_internal() {
            tracing::error!(error = %self, "request failed");
        }
        let code = status.as_u16();
        let heading = status.canonical_reason().unwrap_or("Request failed");
        (
            status,
            Html(format!(
                r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>{code} · Zbierak</title>
  <script src="/static/theme-init.js"></script>
  <link rel="stylesheet" href="/static/vendor/tabler/tabler.min.css">
  <link rel="stylesheet" href="/static/app.css?v=2">
</head>
<body>
  <main id="main-content">
    <section class="error-shell">
      <div class="error-code" aria-hidden="true">{code}</div>
      <p class="eyebrow">Request interrupted</p>
      <h1>{heading}</h1>
      <p>{message}</p>
      <div class="error-actions"><a class="btn btn-primary" href="/">Return home</a><button class="btn btn-outline-secondary" type="button" data-history-back>Go back</button></div>
    </section>
  </main>
  <script src="/static/app.js?v=2" defer></script>
</body>
</html>"#,
                message = escape(&message)
            )),
        )
            .into_response()
    }
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    use axum::http::StatusCode;
    use sqlx::Error as SqlxError;

    use super::AppError;

    #[test]
    fn client_facing_variants_keep_their_messages() {
        let bad_request = AppError::BadRequest("name must not be empty".into());
        assert_eq!(bad_request.status(), StatusCode::BAD_REQUEST);
        assert_eq!(bad_request.code(), "bad_request");
        assert_eq!(bad_request.public_message(), "name must not be empty");

        let unprocessable = AppError::Unprocessable {
            field: Some("timestamp".into()),
            message: "must be an RFC 3339 timestamp".into(),
        };
        assert_eq!(unprocessable.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(unprocessable.code(), "validation_failed");
        assert_eq!(unprocessable.field(), Some("timestamp"));
        assert_eq!(
            unprocessable.public_message(),
            "must be an RFC 3339 timestamp"
        );
    }

    #[test]
    fn internal_variants_are_redacted_to_500() {
        let database = AppError::Database(SqlxError::RowNotFound);
        assert_eq!(database.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(database.code(), "internal_error");
        assert_eq!(database.public_message(), "internal server error");
        assert!(database.is_internal());
        assert!(!database.public_message().contains("no rows"));
    }

    #[test]
    fn config_errors_are_server_side() {
        let config = AppError::Config("ZBIERAK_DATABASE_URL must be a SQLite URL".into());
        assert_eq!(config.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(config.code(), "internal_error");
        assert_eq!(config.public_message(), "internal server error");
    }

    #[test]
    fn conflicts_split_generic_and_event_specific_codes() {
        let event_conflict = AppError::EventConflict("evt-1".into());
        assert_eq!(event_conflict.status(), StatusCode::CONFLICT);
        assert_eq!(event_conflict.code(), "event_id_conflict");
        assert!(event_conflict.public_message().contains("evt-1"));

        let conflict = AppError::Conflict("slug already exists".into());
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        assert_eq!(conflict.code(), "conflict");
        assert_eq!(conflict.public_message(), "slug already exists");
    }

    #[test]
    fn simple_variants_map_to_expected_statuses() {
        assert_eq!(AppError::Unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(AppError::Forbidden.status(), StatusCode::FORBIDDEN);
        assert_eq!(AppError::NotFound.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            AppError::PayloadTooLarge("event exceeds 1 MiB".into()).status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            AppError::PayloadTooLarge("x".into()).code(),
            "payload_too_large"
        );
        assert_eq!(AppError::Unauthorized.code(), "unauthorized");
        assert_eq!(AppError::Forbidden.code(), "forbidden");
        assert_eq!(AppError::NotFound.code(), "not_found");
    }
}
