use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    Config(String),
    #[error("authentication required")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Conflict(String),
    #[error("payload too large: {0}")]
    PayloadTooLarge(String),
    #[error("{message}")]
    Unprocessable {
        field: Option<String>,
        message: String,
    },
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error(transparent)]
    Template(#[from] tera::Error),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            Self::Forbidden => (StatusCode::FORBIDDEN, self.to_string()),
            Self::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            Self::BadRequest(_) | Self::Config(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::Conflict(_) => (StatusCode::CONFLICT, self.to_string()),
            Self::PayloadTooLarge(_) => (StatusCode::PAYLOAD_TOO_LARGE, self.to_string()),
            Self::Unprocessable { .. } => (StatusCode::UNPROCESSABLE_ENTITY, self.to_string()),
            _ => {
                tracing::error!(error = %self, "request failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".into(),
                )
            }
        };
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
