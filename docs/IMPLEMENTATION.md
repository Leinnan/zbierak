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
  `SELECT 1` and returns `ready` when SQLite responds.
- `RUST_LOG` controls structured application logging through
  `tracing-subscriber`.

### Authentication And Authorization

- An empty installation redirects to `/bootstrap`. The first user supplies an
  email address, display name, and password interactively; a transaction and
  bootstrap lock prevent a second first user.
- Passwords are validated to 12 through 1024 bytes and stored as Argon2 hashes.
- Login creates an opaque random session token. SQLite stores its SHA-256 hash,
  user association, CSRF token, and expiry.
- Session cookies are HTTP-only, `SameSite=Lax`, optionally `Secure`, and expire
  after `ZBIERAK_SESSION_DAYS` (1 through 365 days).
- Implemented state-changing authenticated handlers verify the session CSRF
  token.
- Responses include a self-only Content Security Policy, MIME-sniffing
  protection, same-origin referrer policy, and a restrictive permissions policy.
- Project roles are `owner`, `admin`, `developer`, and `viewer`, ordered by
  capability. Owners and admins manage keys, endpoints, and membership; only
  owners can assign or modify owner/admin-level membership. Developers can change
  issue status and comment. Viewers have read-only project and issue access.

### Projects And Issue Review

- Users can create projects with unique lowercase slugs containing letters,
  digits, and hyphens.
- Owners and admins can add a new password user or attach an existing user to a
  project. Owner/admin assignment and modification require an owner.
- Ingestion keys are random `zbk_` tokens. The database stores a SHA-256 hash and
  display prefix rather than the full key.
- Events are grouped into issues with BLAKE3 fingerprints. An explicit
  `fingerprint` array controls grouping; otherwise selected error/message and
  frame fields are collected. A new event reopens a resolved issue but does not
  reopen an ignored issue.
- The UI lists up to 100 issues per project and the most recent 20 event rows per
  issue. It supports status values `unresolved`, `resolved`, and `ignored`, plus
  comments up to 10,000 characters.
- Status changes and comments are recorded in an issue activity stream. An event
  matching a resolved issue reopens it and records a system regression entry;
  ignored issues are not automatically reopened.

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
  components. The protocol describes timestamps as RFC 3339, but current
  validation only checks that the timestamp is nonempty and at most 64 bytes.
- Producer `event_id` is unique within a project. Repeated IDs return the existing
  issue and fingerprint without changing issue counts or creating outbox work.
- Successful new and duplicate ingestion returns HTTP 202 with producer event
  ID, issue ID, fingerprint, and a `duplicate` boolean.

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
- A newly created issue or regression inserts one durable outbox row per enabled
  project endpoint in the same database transaction as event storage. Ordinary
  occurrences and idempotent duplicates do not notify.
- The worker claims pending rows, sends JSON with a ten-second HTTP timeout, and
  marks successful 2xx responses delivered.
- Generic webhook requests include `x-zbierak-signature` containing a Base64
  HMAC-SHA256 digest prefixed with `sha256=`.
- Failed deliveries use exponential delays capped at one hour through the first
  attempts and one day from attempt 12 onward. They remain pending indefinitely;
  there is no terminal failure state or operator replay UI.

### Packaging And Frontend Assets

- The Docker build copies the complete workspace, so both local path crates are
  available during the package build.
- The runtime image includes the binary, templates at `/app/templates`, and
  static files at `/app/static`, uses `/app` as its working directory, and runs
  as UID/GID `10001`.
- The image configures the namespaced listener, database, cookie, session,
  template, and static-directory variables read directly by the binary.
- Compose persists `/data`, publishes to loopback by default, uses a read-only
  root filesystem and writable `/tmp`, drops all capabilities, and prevents
  privilege escalation.
- Tabler 1.4.0 and htmx 2.0.7 are vendored under `src/static/vendor`. The UI uses
  local files only, and `src/static/THIRD_PARTY_NOTICES` carries their notices.

## Current Limitations

### Deployment And Availability

- SQLite is the only database backend. The supported topology is one process and
  one local persistent volume; there is no clustering or automatic failover.
- `ZBIERAK_LISTEN_ADDR` and `ZBIERAK_DATABASE_URL` are primary configuration;
  `ZBIERAK_BIND` and `DATABASE_URL` are legacy fallbacks. Template and static
  paths are configurable but assets are not embedded in the executable.
- `Cargo.lock` is committed and the container uses a locked release build.
- No rolling upgrade, downgrade migration, automated backup, replication, or
  disaster-recovery mechanism is built into the service.

### API And Event Processing

- Idempotency is scoped to `(project, event_id)`. Reusing an ID for different
  content in the same project returns the first stored result rather than
  reporting a payload conflict.
- API failures use escaped HTML error pages rather than the protocol crate's
  `ApiErrorResponse` JSON shape.
- Timestamp strings are not parsed or semantically validated by the server.
- Ingestion performs storage, issue update, and outbox insertion synchronously in
  one request transaction. There is no admission queue or backpressure metric.
- Events are grouped and displayed as received. There is no Linux ELF/DWARF
  symbolication, debug-symbol lookup, JavaScript source-map resolution, or stack
  frame enrichment.
- `raw_events` and `events` both retain event content, increasing storage use.

### UI And Administration

- There are no UI actions for deleting projects/users, removing memberships,
  revoking ingestion keys, changing passwords, ending other sessions, or
  rotating credentials.
- User creation is coupled to adding a project member. There is no installation-
  wide user administration or password reset flow.
- Login has no CSRF token, throttling, lockout, second factor, or external
  identity provider integration.

### Notifications And Network Security

- Generic webhook URLs accept arbitrary HTTP/HTTPS hosts. The service does not
  block loopback, link-local, private-network, or cloud-metadata destinations and
  does not constrain redirects, leaving SSRF risk for privileged administrators.
- Generic webhook secrets and destination URLs are stored in plaintext in
  SQLite. There is no encryption-at-rest key or secret rotation flow.
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

- Detect conflicting payload reuse for an existing project/event ID.
- Return documented JSON API errors and parse RFC 3339 timestamps strictly.
- Add request tracing, explicit body/concurrency limits, proxy-aware client IP
  handling, rate limiting, and integration tests for every API status.
- Add ingestion-key revocation/rotation, password changes/resets, session
  revocation, login CSRF protection, login throttling, and an audit log.
- Prevent webhook SSRF with destination policy, DNS/IP validation, redirect
  restrictions, and deployment-level egress controls.
- Encrypt webhook secrets with a rotatable external key.

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
