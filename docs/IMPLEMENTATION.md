# Implementation Status And Next Steps

This document describes the functionality present in the current source tree and
separates it from potential future work.

## Completed Components

### Service And Storage

- A single Axum service hosts the operator UI, ingestion API, static assets,
  liveness/readiness endpoints, and notification worker.
- SQLx opens SQLite with WAL journaling, full synchronous writes, foreign keys, a
  five-second busy timeout, and at most ten pooled connections.
- Embedded migrations run during startup and create users, sessions, projects,
  memberships, ingestion keys, issues, raw and normalized event records,
  comments, notification endpoints, an outbox, and reserved release/artifact
  metadata tables.
- `GET /health` returns `ok` without checking dependencies. `GET /ready` executes
  `SELECT 1` and returns `ready` when SQLite responds; both respond with JSON
  error bodies on failure.
- `RUST_LOG` controls structured application logging through
  `tracing-subscriber`.
- With the `docs` feature enabled, the service serves an OpenAPI document at
  `/api-docs/openapi.json` and a Scalar API browser at `/scalar` backed by a
  vendored Scalar bundle. These routes are unauthenticated and carry a relaxed
  content security policy.

### Authentication And Authorization

- An empty installation redirects to `/bootstrap`. The first user supplies an
  email address, display name, and password interactively; a transaction and
  bootstrap lock prevent a second first user.
- Passwords are validated to 12 through 1024 bytes and stored as Argon2 hashes.
- Login creates an opaque random session token. SQLite stores its SHA-256 hash,
  user association, CSRF token, and expiry.
- Session cookies are HTTP-only, `SameSite=Lax`, optionally `Secure`, and expire
  after `ZBIERAK_SESSION_DAYS` (1 through 365 days).
- The login form carries a double-submit CSRF token backed by an anonymous
  cookie. Failed logins are throttled per identity: five consecutive failures
  lock the account for fifteen minutes; successful logins reset the counter.
- Users can change their password from the settings page (which signs out all
  other sessions), list active sessions, revoke individual sessions, and sign
  out everywhere except the current browser.
- Users can change their display name and upload a profile avatar from the
  Settings profile card. Uploads are limited to PNG, JPEG, or WebP, decoded by
  magic bytes, center-cropped and resized to 256×256, and re-encoded to PNG
  before being stored as a BLOB in the `user_avatars` table (so no SVG or other
  active content is ever served). Avatars are served same-origin at
  `GET /users/{user_id}/avatar` with an `ETag` and private caching. Accounts
  without an uploaded avatar render deterministic generated initials. Changing a
  display name or avatar is recorded in the audit log.
- Logins, failures, and every privileged mutation are recorded in an
  `audit_log` table.
- Responses include a self-only Content Security Policy, MIME-sniffing
  protection, same-origin referrer policy, and a restrictive permissions policy.
- Project roles are `owner`, `admin`, `developer`, and `viewer`, ordered by
  capability. Owners and admins manage keys, endpoints, and membership; only
  owners can assign or modify owner/admin-level membership. Developers can
  change issue status and comment. Viewers have read-only project and issue
  access. Comment edits and removals additionally follow an author-or-admin
  policy: authors manage their own comments, and owners/admins can moderate
  any comment in their project.

### Projects And Issue Review

- Users can create projects with unique lowercase slugs containing letters,
  digits, and hyphens.
- Owners and admins can add a new password user or attach an existing user to a
  project. Owner/admin assignment and modification require an owner.
- Ingestion keys are random `zbk_` tokens. The database stores a SHA-256 hash and
  display prefix rather than the full key. Owners and admins can revoke keys
  from the project page; revoked keys immediately stop accepting events.
- Personal API tokens (`zpat_` prefix) authenticate the management API as the
  owning user. They are created in Settings, shown once, stored as a SHA-256
  hash with a display prefix, and can be revoked at any time. Role checks still
  apply per project: `viewer` can list issues, `developer` can edit tags.
- Events are grouped into issues with BLAKE3 fingerprints. An explicit
  `fingerprint` array controls grouping; otherwise selected error/message and
  frame fields are collected. A new event reopens a resolved issue but does not
  reopen an ignored issue.
- The UI lists up to 100 issues per project and the most recent 20 event rows per
  issue. It supports status values `unresolved`, `resolved`, and `ignored`, plus
  comments up to 10,000 characters. Comments are stored as raw Markdown and
  rendered server-side with `pulldown-cmark`; the HTML is sanitized with
  `ammonia` (scripts, event handlers, `javascript:`/`data:` URLs, styles, and
  element ids stripped) before it is embedded in the issue page. The browser
  uses a vendored EasyMDE editor with a plain-textarea fallback. Authors can
  edit and remove their own comments, and project owners/admins can edit and
  remove any comment in their project; edits are attributed (`updated_at`,
  `updated_by`) and removals are soft deletes that leave a visible tombstone.
  The project page can filter the issue list
  by tags via `?tag=a,b` (AND semantics) with an autocomplete over the
  project's distinct tags.
- Issues carry flat string tags stored in the `issue_tags` table (one row per
  issue/tag pair). Tags are trimmed, 1–64 characters, may not contain
  whitespace or commas, and an issue holds at most 50. Event tags seed the set
  at ingest (`key:value` labels, `key` for empty values) and later occurrences
  merge additively; manual edits replace the whole set and record a `tags`
  activity entry. The issue page offers a comma-separated tag editor for
  members with the developer role or above, and tags appear in the Markdown
  export.
- Status changes, comments, comment edits (`comment_edited`), and comment
  removals (`comment_deleted`) are recorded in an issue activity stream. An
  event matching a resolved issue reopens it and records a system regression
  entry; ignored issues are not automatically reopened.
- Any issue can be exported as Markdown via
  `GET /projects/{slug}/issues/{issue_id}/export.md`, including title, status,
  event metadata, comment bodies (removed comments export as a tombstone), and
  the full activity stream.
- Projects carry an `active`/`archived` status column reserved for future use;
  no archive flow exists yet.

### Event Protocol And Ingestion

- `POST /api/v1/projects/{slug}/events` accepts a project ingestion key as an
  `Authorization: Bearer` token.
- The body is limited to 1 MiB, decoded as UTF-8 JSON, deserialized through
  `zbierak-protocol`, validated, and stored in both raw and JSON event records.
- Required protocol fields are `event_id`, `timestamp`, and `message`. `version`
  defaults to and must equal `1`; `severity` defaults to `error`.
- Severity values are `debug`, `info`, `warning`, `error`, and `fatal`.
- Optional data includes structured error details, release, environment,
  platform, top-level and error stack frames, breadcrumbs, tags, contexts, user
  data, and explicit fingerprint components.
- Validation bounds message length, tags, contexts, breadcrumbs, and fingerprint
  components. Timestamps must parse as RFC 3339 and fall between years 2000 and
  2100, in addition to a 64-byte length limit.
- Producer `event_id` is unique within a project. Repeating an ID with identical
  content returns the existing issue and fingerprint without changing issue
  counts or creating outbox work. Reusing an ID with different content fails
  with HTTP 409 and an `event_id_conflict` code.
- Successful new and duplicate ingestion returns HTTP 202 with producer event
  ID, issue ID, fingerprint, and a `duplicate` boolean. Oversized bodies return
  413 `payload_too_large`.
- The management API authenticates with a personal API token as
  `Authorization: Bearer zpat_…`:
  - `GET /api/v1/projects/{slug}/issues` lists issues ordered by most recent
    activity with `tag` (comma-separated, AND semantics), `status`, `limit`
    (1–200, default 50), and `offset` query parameters, including a sorted
    `tags` array per issue.
  - `GET /api/v1/projects/{slug}/issues/{issue_id}` returns a single issue with
    tags.
  - `PUT /api/v1/projects/{slug}/issues/{issue_id}/tags` replaces the tag set
    (`{"tags": [...]}`), requires the developer role, and returns the stored
    set. Invalid tags fail with 422 `validation_failed` on the `tags` field.
  - `GET /api/v1/projects/{slug}/issues/{issue_id}/comments` lists comments in
    chronological order; `POST` to the same path creates one (`{"body": "…"}`
    as Markdown, developer role required, 201 response). `PUT`/`DELETE` on
    `/comments/{comment_id}` edit or soft-delete a comment; both require the
    author or a project admin/owner with at least the developer role. Edited
    comments return updated attribution, deleted ones remain as tombstones
    with a `null` body, and removing or editing a tombstone returns 404.
    Invalid bodies fail with 422 `validation_failed` on the `body` field.

### Rust SDK

- `zbierak-sdk` captures protocol events through a bounded in-memory queue and a
  dedicated blocking HTTP sender thread.
- It fills missing event IDs and RFC 3339 timestamps, supports release,
  environment, and platform defaults, and accepts a synchronous redaction hook.
- `BreadcrumbLayer` retains a bounded set of tracing events and attaches them to
  captured events.
- Retryable events can be stored in a size-bounded disk spool. Transport errors,
  HTTP 408, HTTP 429, and 5xx responses are retryable; other HTTP failures are
  treated as permanent.
- `flush` waits for queued/spooled delivery up to a caller-provided deadline.

### Notifications

- Admins and owners can configure generic HTTP/HTTPS webhooks and Discord
  webhooks. Discord destinations are restricted to HTTPS URLs on `discord.com`
  or `discordapp.com`.
- Webhook destinations are validated against the public internet both when
  created and at every delivery: DNS is resolved and the client is pinned to
  only globally routable addresses, blocking loopback, private-network,
  link-local (including cloud metadata), CGNAT, and documentation ranges as
  well as DNS rebinding. Redirects are never followed; a 3xx response counts as
  a failed delivery.
- Webhook signing secrets are encrypted at rest with ChaCha20-Poly1305 under
  `ZBIERAK_SECRET_KEY` and stored as versioned ciphertext. Creating a
  webhook-kind endpoint requires that key; legacy plaintext rows keep
  delivering with a logged warning. Rotation of stored secrets is manual
  (re-create the endpoint).
- A newly created issue or regression inserts one durable outbox row per enabled
  project endpoint in the same database transaction as event storage. Ordinary
  occurrences and idempotent duplicates do not notify.
- The worker claims pending rows, sends JSON with a ten-second HTTP timeout, and
  marks successful 2xx responses delivered.
- Generic webhook requests include `x-zbierak-signature` containing a Base64
  HMAC-SHA256 digest prefixed with `sha256=`.
- Failed deliveries use exponential delays capped at one hour through the first
  attempts and one day from attempt 12 onward. They remain pending indefinitely;
  there is no terminal failure state or operator replay UI. Claimed rows carry a
  60-second lease so deliveries interrupted by a crash are retried.

### Packaging And Frontend Assets

- The Docker build copies the complete workspace, so both local path crates are
  available during the package build.
- The runtime image includes the binary, templates at `/app/templates`, and
  static files at `/app/static`, uses `/app` as its working directory, and runs
  as UID/GID `10001`.
- The image configures the namespaced listener, database, cookie, session,
  template, static-directory, and webhook-secret-key variables read directly by
  the binary.
- Compose persists `/data`, publishes to loopback by default, uses a read-only
  root filesystem and writable `/tmp`, drops all capabilities, and prevents
  privilege escalation.
- Tabler 1.4.0, htmx 2.0.7, and EasyMDE 2.21.0 are vendored under
  `src/static/vendor`. The UI uses local files only, and
  `src/static/THIRD_PARTY_NOTICES` carries their notices.
- The justfile provides manual `backup` and `restore` recipes that archive and
  restore the data volume while the service is stopped.

## Current Limitations

### Deployment And Availability

- SQLite is the only database backend. The supported topology is one process and
  one local persistent volume; there is no clustering or automatic failover.
- `ZBIERAK_LISTEN_ADDR` and `ZBIERAK_DATABASE_URL` are primary configuration;
  `ZBIERAK_BIND` and `DATABASE_URL` are legacy fallbacks. Template and static
  paths are configurable but assets are not embedded in the executable.
- `Cargo.lock` is committed and the container uses a locked release build.
- No rolling upgrade, downgrade migration, automated in-service backup,
  replication, or disaster-recovery mechanism is built into the service; the
  justfile recipes are manual and require downtime.

### API And Event Processing

- Idempotency compares a stored SHA-256 body hash; events ingested before the
  hash column existed carry no hash and keep the legacy duplicate behavior.
- Only the ingestion and readiness endpoints return JSON errors (in the
  protocol crate's `ApiErrorResponse` shape). Every other failure, including UI
  handlers, renders escaped HTML error pages.
- Ingestion performs storage, issue update, and outbox insertion synchronously in
  one request transaction. There is no admission queue or backpressure metric.
- Events are grouped and displayed as received. There is no Linux ELF/DWARF
  symbolication, debug-symbol lookup, JavaScript source-map resolution, or stack
  frame enrichment.
- `raw_events` and `events` both retain event content, increasing storage use.

### UI And Administration

- There are no UI actions for deleting projects/users, removing memberships, or
  rotating a key in one step (revoke plus create is the current rotation path).
- User creation is coupled to adding a project member. There is no installation-
  wide user administration or password reset flow.
- Login has no second factor and no external identity provider integration.

### Notifications And Network Security

- Destination URLs remain plaintext in SQLite; only signing secrets are
  encrypted. Changing `ZBIERAK_SECRET_KEY` invalidates stored ciphertexts
  until endpoints are re-created; there is no automated key-rotation flow.
- All enabled endpoints receive every new-issue and regression notification.
  There are no severity/environment filters, grouping windows, quiet hours,
  muting, rate budgets, custom templates, or endpoint-specific event selection.
- Every non-2xx notification response is retried indefinitely. The worker ignores
  `Retry-After`, adds no jitter, has no dead-letter state, and exposes no delivery
  history or retry controls in the UI.
- Delivery is at least once at the outbox level, not exactly once. A destination
  may process a request even if Zbierak fails to record the successful response.

### Data Lifecycle And Observability

- Release and artifact tables exist only as reserved schema. There are no routes,
  storage backend, upload flow, checksum validation, or artifact lookup.
- There is no configurable retention or automated deletion worker.
- There are no Prometheus/OpenTelemetry metrics, audit log, request IDs, or
  operational dashboards. Health endpoints do not inspect notification backlog,
  free disk space, migrations, or end-to-end ingestion.
- Event payloads are not automatically scrubbed server-side. SDK users can supply
  a redactor, but other clients are responsible for data minimization.
- No measured throughput, latency distribution, maximum database size, or
  notification capacity has been established. SQLite write/fsync latency,
  dashboard reads, payload size, and webhook behavior materially affect capacity.

## Prioritized Potential Next Steps

These are not implemented features. Priorities reflect correctness and
operational risk before product breadth.

### Priority 0: Correctness And Security

- Detect conflicting payload reuse for an existing project/event ID. DONE.
- Parse RFC 3339 timestamps strictly. DONE. Returning documented JSON API
  errors remains open for routes beyond ingestion and readiness.
- Add request tracing, explicit body/concurrency limits, proxy-aware client IP
  handling, rate limiting. Integration tests now cover every ingestion API
  status. Login throttling is in place; ingestion-path rate limiting is not.
- Add ingestion-key revocation/rotation, password changes/resets, session
  revocation, login CSRF protection, login throttling, and an audit log.
  DONE, except password reset without a current password.
- Prevent webhook SSRF with destination policy, DNS/IP validation, redirect
  restrictions, and deployment-level egress controls. DONE in the service;
  deployment egress controls remain an operator task.
- Encrypt webhook secrets with a rotatable external key. DONE for writing;
  automated rotation of stored secrets is still open.

### Priority 1: Operability And Data Lifecycle

- Implement per-project age/count/storage retention with bounded deletion batches
  across raw events, normalized events, issues, and outbox rows.
- Define WAL checkpoint and `VACUUM`/incremental-vacuum maintenance behavior;
  deleting rows does not immediately return filesystem space.
- Export low-cardinality metrics for ingestion outcomes, request/database
  latency, authentication failures, issue updates, outbox depth/age/attempts,
  webhook outcomes, and process/disk health. Do not use event data as labels.
- Add richer readiness diagnostics without exposing sensitive payloads or secrets.
- Build reproducible load and recovery tests covering realistic payloads, bursts,
  dashboard reads, slow webhooks, disk-full behavior, restart recovery, migrations,
  and backup restoration. Publish hardware, SQLite settings, p50/p95/p99 latency,
  sustained rate, errors, and WAL growth for each tested release.
- Add notification filters, grouping windows, quiet hours, muting, rate budgets,
  custom templates, maximum attempts, jitter, `Retry-After` handling, terminal
  failure state, delivery history, and operator replay.
- Document reverse proxies, resource limits, upgrades, rollback, recovery
  objectives, and an online SQLite backup option.

### Priority 2: Symbolication And Build Artifacts

- Extend the protocol with module load addresses and build IDs needed for native
  frame resolution.
- Implement bounded Linux ELF/DWARF symbolication for stripped binaries,
  separate/compressed debug files, inline frames, split DWARF, and ASLR-adjusted
  addresses. Isolate malformed inputs with CPU, memory, and time limits.
- Add authenticated artifact upload and lookup keyed by project, release, and
  build ID. Existing `releases` and `artifacts` tables are placeholders only.
- Use immutable content-addressed artifact storage, checksums, quotas, explicit
  deletion, parser isolation, and optional object storage; keep blobs outside
  SQLite.
- Add JavaScript source-map storage and bounded asynchronous resolution keyed by
  project, release, and asset identity, with URL isolation and source privacy
  controls.
- Test symbolication across compilers, optimization levels, architectures,
  malformed files, and debug-file layouts before advertising native crash
  processing.

### Architecture Trigger

Revisit PostgreSQL or a queue-backed architecture only when measured workload or
availability requirements exceed the documented SQLite single-node model.
