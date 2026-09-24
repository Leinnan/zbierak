# zbierak

Zbierak is a self-hosted error collection service written in Rust. It provides a
server-rendered operator UI, project-scoped event ingestion, issue grouping,
comments and status changes, project membership, and webhook/Discord
notifications. A Rust SDK and shared wire-protocol crate are included in the
workspace.

Zbierak is an error inbox, not a complete observability or crash-processing
platform. It does not symbolicate native crashes, upload or serve artifacts,
resolve source maps, enforce data retention, export metrics, or provide proven
throughput guarantees. See [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md) for
the completed functionality and current limitations.

## Architecture

```text
Rust SDK / HTTP clients
        |
        | POST JSON + project bearer key
        v
  zbierak (Axum)
    |       |       |
    |       |       +-- local Tera templates and Tabler/htmx assets
    |       +---------- background webhook/Discord outbox worker
    +------------------ SQLite database on /data
```

One process serves the UI, API, static files, health endpoints, and notification
worker. SQLx opens SQLite in WAL mode with full synchronous writes, foreign keys,
a five-second busy timeout, and a ten-connection pool. Migrations run at startup.

The supported deployment is one Zbierak process using one local persistent
volume. Do not run multiple replicas against the same database file or put the
database on a shared/network filesystem. The process and volume remain single
points of failure. Use a TLS-terminating reverse proxy for Internet-facing
deployments.

## Docker Compose Setup

Requirements: Docker Engine with the Compose plugin.

```sh
cp .env.example .env
docker compose up --build -d
docker compose ps
```

Open `http://127.0.0.1:3000`. On an empty database, `/` redirects to
`/bootstrap`, where the first user enters an email address, display name, and
password interactively. The password must contain 12 to 1024 bytes. Bootstrap is
disabled after the first user is created. There are no administrator credentials
or session secrets to place in `.env`.

Compose publishes the service on loopback by default. Set
`ZBIERAK_PUBLISH_ADDRESS=0.0.0.0` only when a firewall or reverse proxy controls
access.

## Configuration

Copy `.env.example` to `.env`. The container accepts these variables:

| Variable | Purpose | Default |
| --- | --- | --- |
| `ZBIERAK_PUBLISH_ADDRESS` | Host address used by the Compose port mapping | `127.0.0.1` |
| `ZBIERAK_LISTEN_ADDR` | Address listened on inside the container | `0.0.0.0:3000` |
| `ZBIERAK_DATABASE_URL` | SQLx SQLite URL | `sqlite:///data/zbierak.db?mode=rwc` |
| `ZBIERAK_COOKIE_SECURE` | Add `Secure` to the session cookie (`true`, `false`, `1`, `0`, `yes`, or `no`) | `false` |
| `ZBIERAK_SESSION_DAYS` | Session lifetime, from 1 through 365 days | `30` |
| `ZBIERAK_STATIC_DIR` | Static asset directory | `/app/static` |
| `ZBIERAK_TEMPLATE_DIR` | Tera template directory | `/app/templates` |
| `RUST_LOG` | `tracing-subscriber` filter | `zbierak=info,tower_http=info` |

Set `ZBIERAK_COOKIE_SECURE=true` whenever users access Zbierak over HTTPS. The
application uses an opaque random session token stored as a SHA-256 hash in
SQLite. The cookie is HTTP-only and `SameSite=Lax`; its lifetime is controlled by
`ZBIERAK_SESSION_DAYS`.

For source runs, asset discovery uses `./templates` or `./static` when present,
then falls back to `src/templates` and `src/static`. The two directory variables
override discovery. `ZBIERAK_BIND` and `DATABASE_URL` remain accepted as legacy
fallbacks when their namespaced equivalents are absent.

`GET /health` is a process liveness response. `GET /ready` also executes
`SELECT 1` against SQLite and is used by the container health check.

## Projects And Ingest Keys

Any authenticated user can create a project and becomes its owner. Project roles
are `owner`, `admin`, `developer`, and `viewer`. Owners and admins can create
ingestion keys, configure notification endpoints, and add or update members;
only owners can assign or modify owner/admin-level membership. Developers can
change issue status and comment, while viewers have read-only issue access.
Creating a previously unknown member also creates that user's password login. A
new ingestion key is shown once; only its SHA-256 hash and prefix are stored.

Use the project slug and generated key to submit events:

```sh
curl --fail-with-body \
  -X POST http://127.0.0.1:3000/api/v1/projects/storefront/events \
  -H 'Authorization: Bearer zbk_REPLACE_WITH_PROJECT_KEY' \
  -H 'Content-Type: application/json' \
  -d '{
    "version": 1,
    "event_id": "01J8A7M4Y2JXG3J4M5N6P7Q8R9",
    "timestamp": "2026-09-24T12:00:00Z",
    "message": "checkout failed",
    "severity": "error",
    "release": "2026.09.24",
    "environment": "production",
    "platform": "rust",
    "error": {
      "type": "CheckoutError",
      "value": "payment provider unavailable",
      "stack_frames": [
        {"filename": "src/checkout.rs", "function": "submit", "line": 42, "in_app": true}
      ]
    },
    "breadcrumbs": [
      {"timestamp": "2026-09-24T11:59:59Z", "message": "payment submitted", "severity": "info"}
    ],
    "tags": {"region": "eu-central-1"},
    "contexts": {"request": {"request_id": "req_123"}},
    "user": {"id": "customer-42"},
    "fingerprint": ["checkout", "provider-unavailable"]
  }'
```

`event_id`, `timestamp`, and `message` are required. `version` defaults to `1`
and must equal `1`; `severity` defaults to `error` and accepts `debug`, `info`,
`warning`, `error`, or `fatal`. Optional fields are `error`, `release`,
`environment`, `platform`, `stack_frames`, `breadcrumbs`, `tags`, `contexts`,
`user`, and `fingerprint`. The protocol crate documents their nested shapes and
validation limits. Requests are capped at 1 MiB.

The event's `tags` map seeds the issue's tags as flat `key:value` labels (a tag
with an empty value becomes just `key`). The first occurrence sets them, and
later occurrences only add labels that are not present yet, so tags can be
curated manually without being erased by the next event.

A new event returns HTTP `202 Accepted`:

```json
{"id":"01J8A7M4Y2JXG3J4M5N6P7Q8R9","issue_id":1,"fingerprint":"BLAKE3_HEX","duplicate":false}
```

`event_id` is idempotent within a project. Repeating it returns HTTP 202 with the
original issue and fingerprint plus `"duplicate":true`; it does not increment
the issue or enqueue another notification. API errors use the protocol crate's
JSON error shape (`{"code":"...","message":"...","field":"..."}`) with status
`400` for malformed requests, `401` for a missing or invalid ingest key, and
`422` when the event fails protocol validation. The operator UI continues to
return HTML errors.

## API Documentation

The versioned HTTP API is described by an OpenAPI 3.1 document. Documentation
tooling is not part of release builds; enable the `docs` Cargo feature for local
use:

```sh
cargo run --features docs
```

The Scalar UI is served at `/scalar` and the raw document at
`/api-docs/openapi.json`. Scalar is loaded from the bundle vendored under
`src/docs/scalar` and embedded in the binary only for `docs` builds; its default
webfonts are disabled, so the page makes no third-party browser requests. These
routes intentionally use a relaxed Content-Security-Policy and are
unauthenticated, so keep them on loopback or behind a reverse proxy that
restricts access in production.

## Issue Tags And The Management API

Issues carry flat string tags (labels). Rules: trimmed, 1–64 characters, no
whitespace or commas, at most 50 tags per issue. Event tags are merged in at
ingest time (see above); manual edits replace the whole set and are recorded in
the issue activity stream. The project page filters the issue list by tag, and
the issue page has a tag editor for members with the developer role or above.

Management endpoints authenticate with **personal API tokens**, created under
Settings → API tokens (prefix `zpat_`, shown once). A token acts as your user
account, so project role checks still apply: listing requires `viewer`, editing
tags requires `developer`.

List and filter issues (`tag` accepts a comma-separated list with AND
semantics; `status` is `unresolved`, `resolved`, or `ignored`):

```sh
curl --fail-with-body \
  -H 'Authorization: Bearer zpat_REPLACE_WITH_API_TOKEN' \
  'http://127.0.0.1:3000/api/v1/projects/storefront/issues?tag=env:prod&status=unresolved&limit=50'
```

Read one issue:

```sh
curl --fail-with-body \
  -H 'Authorization: Bearer zpat_REPLACE_WITH_API_TOKEN' \
  'http://127.0.0.1:3000/api/v1/projects/storefront/issues/1'
```

Replace an issue's tag set:

```sh
curl --fail-with-body -X PUT \
  -H 'Authorization: Bearer zpat_REPLACE_WITH_API_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"tags": ["env:prod", "team:payments"]}' \
  'http://127.0.0.1:3000/api/v1/projects/storefront/issues/1/tags'
```

List responses return issues ordered by most recent activity with a `tags`
array per issue. Tag edits return the stored (sorted) set. Errors use the same
JSON shape as ingestion, with `401` for a missing, invalid, or revoked token,
`404` for unknown projects or issues outside your memberships, `403` when the
token owner is only a viewer, and `422` when tags fail validation.

## Rust SDK

`crates/zbierak-sdk` sends protocol events on a bounded background thread. It can
attach tracing breadcrumbs, apply a caller-provided redactor, fill release,
environment, and platform defaults, and persist retryable events to a bounded
local spool. Configure the SDK with the complete project ingestion URL shown
above and the generated bearer key.

```rust
use std::time::Duration;
use zbierak_protocol::Severity;
use zbierak_sdk::Client;

let client = Client::builder(
    "https://errors.example.com/api/v1/projects/storefront/events",
)
.auth_token("zbk_REPLACE_WITH_PROJECT_KEY")
.release("2026.09.24")
.environment("production")
.build()?;

let event_id = client.capture_message("checkout failed", Severity::Error)?;
let report = client.flush(Duration::from_secs(2))?;
```

The SDK retries transport errors, HTTP 408, HTTP 429, and server errors. Other
non-success responses are permanent failures and are removed from its spool.
The SDK preserves generated event IDs across spool retries, allowing the server's
project-scoped idempotency check to suppress duplicate processing.

## Issue Workflow And Notifications

Incoming events are grouped by a BLAKE3 fingerprint. Clients can provide up to
ten explicit fingerprint components; otherwise the service derives grouping
from error/message and frame data. Issues can be `unresolved`, `resolved`, or
`ignored`. A new occurrence reopens a resolved issue as a regression; ignored
issues remain ignored. Status changes, comments, tag edits, and regressions are
recorded in the issue activity stream, and tags are included in the Markdown
export. See [Issue Tags And The Management API](#issue-tags-and-the-management-api)
for tag rules and API usage.

Notifications are queued only when an issue is first created or when a resolved
issue regresses. The durable SQLite outbox is committed with the event, then a
background worker posts JSON to enabled endpoints. Generic HTTP/HTTPS webhooks
require a secret of at least 16 characters and receive an
`x-zbierak-signature: sha256=<base64-hmac>` header. Discord endpoints must be
HTTPS URLs hosted by `discord.com` or `discordapp.com`. Deliveries resolve the
destination, pin the connection to public addresses only, and never follow
redirects. Failed deliveries retry with exponential delays and remain pending
until they succeed or the endpoint is deleted.

## Local Development

Rust development requires a current stable toolchain with edition 2024 support
and a C toolchain for SQLite dependencies.

```sh
cp .env.example .env
just check
just test
just run
```

Run `just` to list all recipes. `just docker-up` builds and starts the container;
`just logs`, `just backup`, and `just restore <archive>` cover common operations.

## Local Tabler Policy

The UI serves pinned Tabler 1.4.0 and htmx 2.0.7 files from
`src/static/vendor`; templates do not load a CDN or remote font service. The
optional API documentation UI likewise serves a pinned Scalar 1.72.0 bundle from
`src/docs/scalar` (embedded only in `docs` builds) with its default webfonts
disabled. Keep frontend assets local and version-pinned. Update them
deliberately and maintain `src/static/THIRD_PARTY_NOTICES` with the distributed
licenses. This preserves offline operation and avoids adding third-party browser
requests.

## Security

- Terminate TLS at a maintained reverse proxy and set
  `ZBIERAK_COOKIE_SECURE=true` in HTTPS deployments.
- Keep the published port on loopback unless external access is intentionally
  controlled.
- Protect `.env`, the `/data` volume, and backups. Event payloads and webhook
  configuration may contain credentials, personal data, stack traces, and source
  details.
- Scope ingestion keys per project. Revoke compromised keys from the project
  page and create a replacement to rotate credentials.
- Apply request-rate limits at the reverse proxy. The application limits an event
  body to 1 MiB, throttles repeated login failures, but has no built-in rate
  limiter for the ingestion API.
- Treat webhook URLs as privileged configuration. Destinations are validated
  against the public internet at creation and pinned to freshly resolved
  public addresses at delivery; redirects are never followed. Layer
  deployment-level egress controls for defense in depth.
- Webhook signing secrets are encrypted at rest with ChaCha20-Poly1305 under
  `ZBIERAK_SECRET_KEY` (set it in `.env`; generate with `openssl rand -base64
  32`). They are used to produce an `x-zbierak-signature` HMAC-SHA256 header
  with a Base64 digest.
- Browser state-changing authenticated handlers validate a per-session CSRF
  token, and login is protected by a double-submit CSRF token plus lockout
  after repeated failures. Responses set a restrictive
  Content Security Policy, `X-Content-Type-Options`, `Referrer-Policy`, and
  `Permissions-Policy`.
- The Compose service runs as UID/GID `10001`, drops Linux capabilities, prevents
  privilege escalation, uses a read-only root filesystem, and writes only to
  `/data` and `/tmp`.
- Review and update Rust, Debian, Tabler, and htmx dependencies regularly.

## Backup And Restore

`just backup` stops the application, archives the complete named volume, and
restarts it. The brief outage ensures the SQLite database, WAL/SHM files, and
adjacent state are consistent without installing SQLite tools in the image.

```sh
just backup
just restore backups/zbierak-20260924T120000Z.tar.gz
```

Restore is destructive: it stops the stack and replaces `/data`. Keep encrypted,
access-controlled copies off-host and test restoration separately. A raw copy of
the live database file is not a safe backup procedure. Use SQLite's online backup
API or an equivalent application-aware process if downtime is unacceptable.

## Capacity And Availability

SQLite keeps operation simple but makes this a single-node service. WAL mode and
a busy timeout help routine concurrency; they do not provide clustering,
automatic failover, or horizontal write scaling.

No measured sustained-ingestion throughput is published. Results depend on CPU,
storage fsync latency, payload size, database size, concurrent dashboard reads,
and notification load. Benchmark the exact release and deployment on
representative hardware before setting capacity expectations, and keep free disk
space for the database and WAL.

## License

Zbierak is licensed under the [MIT License](LICENSE). Vendored frontend assets
retain the notices in `src/static/THIRD_PARTY_NOTICES`.
