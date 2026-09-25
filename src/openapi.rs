//! `OpenAPI` document and Scalar documentation UI.
//!
//! This module is compiled only when the `docs` Cargo feature is enabled, so
//! release builds and container images do not link `utoipa` or ship the
//! documentation assets.

use axum::{
    Json, Router,
    body::Body,
    http::{HeaderValue, Request, header},
    middleware::{self, Next},
    response::Response,
    routing::get,
};
use utoipa::{
    Modify, OpenApi,
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
};
use utoipa_scalar::{Scalar, Servable};

use crate::handlers;
use zbierak_protocol::{self as protocol, ApiErrorResponse as ApiErrorSchema};

/// `OpenAPI` document for the versioned HTTP API.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Zbierak API",
        version = env!("CARGO_PKG_VERSION"),
        description = "Project-scoped event ingestion for the Zbierak error collector.",
        license(name = "MIT"),
    ),
    paths(
        handlers::ingest,
        handlers::list_issues,
        handlers::get_issue,
        handlers::update_issue_tags,
        handlers::list_comments,
        handlers::create_comment,
        handlers::update_comment,
        handlers::delete_comment,
        handlers::health,
        handlers::ready,
    ),
    components(schemas(
        protocol::Event,
        protocol::ErrorInfo,
        protocol::Severity,
        protocol::StackFrame,
        protocol::Breadcrumb,
        protocol::User,
        protocol::IngestResponse,
        handlers::IssueJson,
        handlers::UpdateTagsPayload,
        handlers::TagsResponse,
        handlers::CommentJson,
        handlers::CommentPayload,
        ApiErrorSchema,
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "events", description = "Event ingestion"),
        (name = "issues", description = "Issue listing, filtering, and tags"),
        (
            name = "comments",
            description = "Comment reading, authoring, and moderation",
        ),
        (name = "system", description = "Health and readiness"),
    ),
)]
pub struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_auth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("zbk")
                    .build(),
            ),
        );
    }
}

/// The vendored Scalar browser bundle, embedded only in `docs` builds.
const SCALAR_JS: &[u8] = include_bytes!("docs/scalar/scalar.standalone.js");

/// Scalar page that loads the locally served bundle and disables the default
/// webfonts so no third-party requests are made.
const SCALAR_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <title>$title</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <meta name="color-scheme" content="light dark"/>
</head>
<body>
  <script id="api-reference" type="application/json"
          data-configuration='{"withDefaultFonts":false,"hideDarkModeToggle":true}'>$spec</script>
  <script src="/static/theme-init.js"></script>
  <script src="/scalar/scalar.standalone.js"></script>
</body>
</html>
"#;

/// Builds the documentation router: raw `OpenAPI` JSON plus the Scalar UI.
pub fn docs_router() -> Router {
    Router::new()
        .route(
            "/api-docs/openapi.json",
            get(|| async { Json(ApiDoc::openapi()) }),
        )
        .route("/scalar/scalar.standalone.js", get(scalar_bundle))
        .merge(
            Scalar::with_url("/scalar", ApiDoc::openapi())
                .custom_html(SCALAR_HTML)
                .title("Zbierak API"),
        )
        .layer(middleware::from_fn(docs_security_headers))
}

async fn scalar_bundle() -> Response {
    // Built without the fallible response builder: the header values are
    // static, so there is no error path to panic on.
    let mut response = Response::new(Body::from(SCALAR_JS));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/javascript; charset=utf-8"),
    );
    response
}

/// Documentation pages need a relaxed CSP so Scalar's inline bootstrap can run.
async fn docs_security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; \
             style-src 'self' 'unsafe-inline'; img-src 'self' data:; \
             font-src 'self' data:; connect-src 'self'; worker-src 'self' blob:; \
             frame-ancestors 'none'; object-src 'none'",
        ),
    );
    response
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::docs_router;

    #[tokio::test]
    async fn scalar_uses_the_shared_theme_before_mounting() {
        let response = docs_router()
            .oneshot(Request::get("/scalar").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();

        assert!(body.contains("\"hideDarkModeToggle\":true"));
        let initializer = body.find("/static/theme-init.js").unwrap();
        let scalar = body.find("/scalar/scalar.standalone.js").unwrap();
        assert!(initializer < scalar);
    }
}
