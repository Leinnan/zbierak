//! A runtime-independent client for reporting events to Zbierak.
//!
//! Sending happens on one bounded background worker. Application threads and tasks never
//! perform an HTTP request: when the in-memory queue is full, events are written to the
//! bounded disk spool instead. Add [`BreadcrumbLayer`] to a `tracing_subscriber` registry
//! to attach recent tracing events to subsequently captured events.
//!
//! Two runtimes are supported, selected by Cargo feature:
//!
//! * `blocking` (enabled by default): `Client` sends on a dedicated OS thread.
//! * `async`: `AsyncClient` sends on a spawned Tokio task; capture stays synchronous,
//!   while `flush` and `shutdown` are awaited.
//!
//! With the `bevy` feature the crate additionally exposes a Bevy integration
//! in the `bevy` module: it captures Bevy log events through `LogPlugin`,
//! wires a drain system, and installs the panic hook from one call.
//!
//! The protocol types the API takes and returns are re-exported, so depending on this
//! crate alone is enough to build and send events.
#![cfg_attr(
    feature = "blocking",
    doc = "# Example (blocking)",
    doc = "",
    doc = "```no_run",
    doc = "use std::time::Duration;",
    doc = "",
    doc = "use zbierak_sdk::{Client, Severity};",
    doc = "",
    doc = "let client = Client::builder(",
    doc = "    \"https://errors.example.com/api/v1/projects/storefront/events\",",
    doc = ")",
    doc = ".auth_token(\"zbk_REPLACE_WITH_PROJECT_KEY\")",
    doc = ".release(\"2026.09.24\")",
    doc = ".environment(\"production\")",
    doc = ".build()?;",
    doc = "",
    doc = "let event_id = client.capture_message(\"checkout failed\", Severity::Error)?;",
    doc = "println!(\"captured {event_id}\");",
    doc = "client.flush(Duration::from_secs(2))?;",
    doc = "# Ok::<(), Box<dyn std::error::Error>>(())",
    doc = "```"
)]
#![cfg_attr(
    feature = "async",
    doc = "# Example (async)",
    doc = "",
    doc = "Capture is synchronous; only `flush` and `shutdown` are awaited.",
    doc = "",
    doc = "```no_run",
    doc = "use zbierak_sdk::{AsyncClient, Severity};",
    doc = "",
    doc = "let client = AsyncClient::builder(",
    doc = "    \"https://errors.example.com/api/v1/projects/storefront/events\",",
    doc = ")",
    doc = ".auth_token(\"zbk_REPLACE_WITH_PROJECT_KEY\")",
    doc = ".build()?;",
    doc = "",
    doc = "let event_id = client.capture_message(\"checkout failed\", Severity::Error)?;",
    doc = "println!(\"captured {event_id}\");",
    doc = "# Ok::<(), Box<dyn std::error::Error>>(())",
    doc = "```"
)]
#![forbid(unsafe_code)]
// With no client feature selected the crate only exposes shared machinery.
#![cfg_attr(not(any(feature = "blocking", feature = "async")), allow(dead_code))]

#[cfg(feature = "async")]
mod async_client;
#[cfg(feature = "bevy")]
pub mod bevy;
#[cfg(feature = "blocking")]
mod blocking;
#[cfg(feature = "stacktraces")]
mod stacktrace;
#[cfg(not(feature = "stacktraces"))]
mod stacktrace {
    /// Stack capture is compiled out; events carry no frames.
    pub(crate) fn capture_frames() -> Vec<zbierak_protocol::StackFrame> {
        Vec::new()
    }
}

#[cfg(feature = "async")]
pub use async_client::{AsyncClient, AsyncClientBuilder};
#[cfg(feature = "blocking")]
pub use blocking::{Client, ClientBuilder};
pub use zbierak_protocol::{
    Breadcrumb, ErrorInfo, Event, Severity, StackFrame, User, ValidationError,
};

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::fs;
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::StatusCode;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::field::{Field, Visit};
use tracing::{Event as TracingEvent, Subscriber};
use tracing_subscriber::Layer;
use uuid::Uuid;

/// A callback that can remove or transform sensitive event data before persistence or sending.
pub type Redactor = Arc<dyn Fn(&mut Event) + Send + Sync + 'static>;

/// Defaults and shared state used to prepare events before queueing.
pub(crate) struct CaptureContext {
    pub(crate) release: Option<String>,
    pub(crate) environment: Option<String>,
    pub(crate) platform: Option<String>,
    pub(crate) breadcrumbs: Arc<Mutex<VecDeque<Breadcrumb>>>,
    pub(crate) breadcrumb_capacity: usize,
    pub(crate) redactor: Option<Redactor>,
}

impl CaptureContext {
    /// Fills caller omissions, applies the redactor, and validates the event.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError::RedactorPanicked`] if the redactor panics and
    /// [`CaptureError::InvalidEvent`] when validation fails.
    pub(crate) fn prepare(&self, mut event: Event) -> Result<Event, CaptureError> {
        if event.event_id.is_empty() {
            event.event_id = Uuid::new_v4().to_string();
        }
        if event.timestamp.is_empty() {
            event.timestamp = now_timestamp();
        }
        if event.release.is_none() {
            event.release.clone_from(&self.release);
        }
        if event.environment.is_none() {
            event.environment.clone_from(&self.environment);
        }
        if event.platform.is_none() {
            event.platform.clone_from(&self.platform);
        }
        if event.breadcrumbs.is_empty() {
            event.breadcrumbs = lock(&self.breadcrumbs).iter().cloned().collect();
        }
        if self.redactor.as_ref().is_some_and(|redactor| {
            panic::catch_unwind(AssertUnwindSafe(|| redactor(&mut event))).is_err()
        }) {
            return Err(CaptureError::RedactorPanicked);
        }
        event.validate()?;
        Ok(event)
    }
}

/// A `tracing_subscriber` layer that records tracing events as breadcrumbs.
#[derive(Clone)]
pub struct BreadcrumbLayer {
    breadcrumbs: Arc<Mutex<VecDeque<Breadcrumb>>>,
    capacity: usize,
}

impl<S> Layer<S> for BreadcrumbLayer
where
    S: Subscriber,
{
    fn on_event(
        &self,
        event: &TracingEvent<'_>,
        _context: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if self.capacity == 0 {
            return;
        }
        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);
        let metadata = event.metadata();
        let message = visitor
            .message
            .take()
            .unwrap_or_else(|| metadata.name().to_owned());
        let breadcrumb = Breadcrumb {
            timestamp: now_timestamp(),
            message,
            severity: tracing_severity(*metadata.level()),
            category: Some(metadata.target().to_owned()),
            data: visitor.data,
        };
        push_breadcrumb(&self.breadcrumbs, self.capacity, breadcrumb);
    }
}

#[derive(Default)]
struct EventVisitor {
    message: Option<String>,
    data: BTreeMap<String, serde_json::Value>,
}

impl Visit for EventVisitor {
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.data.insert(field.name().into(), value.into());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.data.insert(field.name().into(), value.into());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.data.insert(field.name().into(), value.into());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_owned());
        } else {
            self.data.insert(field.name().into(), value.into());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let value = format!("{value:?}");
        if field.name() == "message" {
            self.message = Some(value);
        } else {
            self.data.insert(field.name().into(), value.into());
        }
    }
}

/// Outcome of a single delivery attempt, shared by both workers.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Delivery {
    Delivered,
    PermanentFailure,
    Retry,
}

/// HTTP statuses worth retrying from the offline spool.
pub(crate) fn is_retryable(status: StatusCode) -> bool {
    status.is_server_error()
        || status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
}

pub(crate) struct Spool {
    directory: PathBuf,
    max_bytes: u64,
}

impl Spool {
    pub(crate) fn new(directory: PathBuf, max_bytes: u64) -> io::Result<Self> {
        if max_bytes > 0 {
            fs::create_dir_all(&directory)?;
        }
        Ok(Self {
            directory,
            max_bytes,
        })
    }

    pub(crate) fn store(&mut self, event: &Event) -> Result<(), SpoolError> {
        if self.max_bytes == 0 {
            return Err(SpoolError::Disabled);
        }
        let bytes = serde_json::to_vec(event)?;
        if bytes.len() as u64 > self.max_bytes {
            return Err(SpoolError::EventTooLarge);
        }
        let sequence = SPOOL_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let name = format!("{timestamp:020}-{sequence:020}-{}.json", Uuid::new_v4());
        let path = self.directory.join(name);
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, bytes)?;
        fs::rename(&temporary, &path)?;
        self.enforce_bound()?;
        Ok(())
    }

    /// Returns the oldest readable spool entry. Files confirmed to hold
    /// corrupt JSON are deleted so the spool can drain; transient read
    /// failures are surfaced instead of silently dropping events.
    pub(crate) fn oldest(&self) -> Result<Option<(PathBuf, Event)>, SpoolError> {
        for path in self.paths()? {
            let bytes = match fs::read(&path) {
                Ok(bytes) => bytes,
                // The file vanished concurrently; nothing to drain.
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(SpoolError::Io(error)),
            };
            match serde_json::from_slice::<Event>(&bytes) {
                Ok(event) => return Ok(Some((path, event))),
                Err(_) => {
                    let _ = fs::remove_file(&path);
                }
            }
        }
        Ok(None)
    }

    pub(crate) fn remove(path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }

    /// Number of spool files currently on disk.
    pub(crate) fn len(&self) -> io::Result<usize> {
        Ok(self.paths()?.len())
    }

    /// Lists spool files oldest first. A missing directory counts as an
    /// empty spool; every other error is surfaced.
    fn paths(&self) -> io::Result<Vec<PathBuf>> {
        let entries = match fs::read_dir(&self.directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut paths: Vec<PathBuf> = entries
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<io::Result<_>>()?;
        paths.retain(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        });
        paths.sort();
        Ok(paths)
    }

    fn enforce_bound(&self) -> io::Result<()> {
        // Build (path, size) pairs in one pass instead of a path vector plus
        // a second sizes vector.
        let sized: Vec<(PathBuf, u64)> = self
            .paths()?
            .into_iter()
            .map(|path| {
                let size = fs::metadata(&path)?.len();
                Ok((path, size))
            })
            .collect::<io::Result<_>>()?;
        let mut total = sized.iter().map(|(_, size)| size).sum::<u64>();
        for (path, size) in sized {
            if total <= self.max_bytes {
                break;
            }
            fs::remove_file(&path)?;
            total = total.saturating_sub(size);
        }
        Ok(())
    }
}

static SPOOL_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) fn push_breadcrumb(
    breadcrumbs: &Mutex<VecDeque<Breadcrumb>>,
    capacity: usize,
    breadcrumb: Breadcrumb,
) {
    if capacity == 0 {
        return;
    }
    let mut breadcrumbs = lock(breadcrumbs);
    if breadcrumbs.len() == capacity {
        breadcrumbs.pop_front();
    }
    breadcrumbs.push_back(breadcrumb);
}

fn tracing_severity(level: tracing::Level) -> Severity {
    match level {
        tracing::Level::TRACE | tracing::Level::DEBUG => Severity::Debug,
        tracing::Level::INFO => Severity::Info,
        tracing::Level::WARN => Severity::Warning,
        tracing::Level::ERROR => Severity::Error,
    }
}

fn now_timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Splits a panic into its rendered location and payload parts.
fn panic_parts(info: &panic::PanicHookInfo<'_>) -> (String, String) {
    let payload = info
        .payload()
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload")
        .to_owned();
    let location = info.location().map_or_else(
        || "unknown location".into(),
        |location| {
            format!(
                "{}:{}:{}",
                location.file(),
                location.line(),
                location.column()
            )
        },
    );
    (location, payload)
}

/// Builds the full event sent by the panic hook: the flat panic message the
/// rest of the SDK keys on, plus structured error details and stack frames.
pub(crate) fn panic_event(info: &panic::PanicHookInfo<'_>) -> Event {
    let (location, payload) = panic_parts(info);
    panic_event_parts(&location, &payload)
}

/// [`panic_event`] without the hook-info wrapper, so the shape is testable
/// without constructing `PanicHookInfo` (private on stable).
fn panic_event_parts(location: &str, payload: &str) -> Event {
    Event {
        message: format!("panic at {location}: {payload}"),
        severity: Severity::Fatal,
        error: Some(ErrorInfo {
            type_name: "panic".into(),
            value: Some(payload.to_owned()),
            stack_frames: stacktrace::capture_frames(),
        }),
        ..Event::default()
    }
}

/// Upper bound on cause-chain entries recorded per event.
const MAX_ERROR_CHAIN: usize = 10;

/// Flattens an error's `source()` chain into `error_chain` context entries,
/// newest first, so the UI can show what an error originated from.
fn error_chain_context(error: &(dyn std::error::Error + 'static)) -> Vec<serde_json::Value> {
    let mut chain = Vec::new();
    let mut source = error.source();
    while let Some(cause) = source {
        if chain.len() >= MAX_ERROR_CHAIN {
            break;
        }
        chain.push(serde_json::json!({
            "type": "cause",
            "value": cause.to_string(),
        }));
        source = cause.source();
    }
    chain
}

/// Builds a complete event for a captured error: the error text as the
/// message, the concrete type and stack in [`ErrorInfo`], and the cause chain
/// in the `error_chain` context.
pub(crate) fn error_event<E: std::error::Error + 'static>(error: &E, severity: Severity) -> Event {
    let message = error.to_string();
    let chain = error_chain_context(error);
    let mut contexts = BTreeMap::new();
    if !chain.is_empty() {
        contexts.insert("error_chain".into(), serde_json::Value::Array(chain));
    }
    Event {
        message: message.clone(),
        severity,
        error: Some(ErrorInfo {
            type_name: std::any::type_name::<E>().to_owned(),
            value: Some(message),
            stack_frames: stacktrace::capture_frames(),
        }),
        contexts,
        ..Event::default()
    }
}

/// Error returned while constructing a client.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// The endpoint was empty.
    #[error("ingestion endpoint must not be empty")]
    EmptyEndpoint,
    /// The HTTP client could not be constructed.
    #[error("failed to build HTTP client: {0}")]
    Http(#[from] reqwest::Error),
    /// The spool directory or sender thread could not be created.
    #[error("failed to initialize SDK: {0}")]
    Io(#[from] io::Error),
}

/// Error returned before an event is accepted by the sender or spool.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// The event violates the protocol contract.
    #[error("invalid event: {0}")]
    InvalidEvent(#[from] ValidationError),
    /// The redaction callback panicked.
    #[error("event redaction callback panicked")]
    RedactorPanicked,
    /// The sender thread has stopped.
    #[error("sender thread has stopped")]
    SenderStopped,
    /// The full queue could not spill the event to disk.
    #[error("failed to spool event: {0}")]
    Spool(#[from] SpoolError),
}

/// Disk spool failure.
#[derive(Debug, thiserror::Error)]
pub enum SpoolError {
    /// Disk spooling was explicitly disabled.
    #[error("disk spool is disabled")]
    Disabled,
    /// One serialized event exceeds the configured total spool bound.
    #[error("event exceeds the configured spool size")]
    EventTooLarge,
    /// Serialization failed.
    #[error("failed to serialize event: {0}")]
    Serialize(#[from] serde_json::Error),
    /// A filesystem operation failed.
    #[error("spool I/O failed: {0}")]
    Io(#[from] io::Error),
}

/// Result of a completed flush attempt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlushReport {
    /// Events delivered from the offline spool during this flush.
    pub delivered: usize,
    /// Events still persisted after this flush.
    pub remaining: usize,
}

/// Failure to coordinate with the sender during a flush.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FlushError {
    /// The timeout elapsed before the sender completed the request.
    #[error("flush timed out")]
    TimedOut,
    /// The sender thread has stopped.
    #[error("sender thread has stopped")]
    SenderStopped,
    /// The spool could not be read during the flush.
    #[error("failed to read spool: {0}")]
    Spool(String),
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn spool_evicts_oldest_events_to_stay_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let mut spool = Spool::new(directory.path().into(), 700).unwrap();
        for index in 0..10 {
            let event = Event::new(index.to_string(), now_timestamp(), "x".repeat(100));
            spool.store(&event).unwrap();
        }
        let total: u64 = spool
            .paths()
            .unwrap()
            .iter()
            .map(|path| fs::metadata(path).unwrap().len())
            .sum();
        assert!(total <= 700);
        assert!(spool.len().unwrap() < 10);
    }

    #[test]
    fn missing_spool_directory_counts_as_empty() {
        let directory = tempfile::tempdir().unwrap();
        let never_created = directory.path().join("absent");
        let spool = Spool {
            directory: never_created.clone(),
            max_bytes: 0,
        };
        assert_eq!(spool.paths().unwrap(), Vec::<PathBuf>::new());
        assert_eq!(spool.len().unwrap(), 0);
        assert_eq!(spool.oldest().unwrap(), None);
    }

    #[test]
    fn corrupt_spool_files_are_removed_but_transient_failures_are_not() {
        let directory = tempfile::tempdir().unwrap();
        let spool = Spool {
            directory: directory.path().to_path_buf(),
            max_bytes: 0,
        };
        // A corrupt file is confirmed garbage: dropped so the spool drains.
        let corrupt = directory.path().join("1-corrupt.json");
        fs::write(&corrupt, b"{not json").unwrap();
        assert_eq!(spool.oldest().unwrap(), None);
        assert!(!corrupt.exists());

        // A read failure is transient: surfaced, and the file survives.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let unreadable = directory.path().join("2-unreadable.json");
            fs::write(&unreadable, b"{}").unwrap();
            fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).unwrap();
            let result = spool.oldest();
            fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(result.is_err(), "unreadable file must surface an error");
            assert!(unreadable.exists(), "unreadable file must not be deleted");
        }
    }

    #[test]
    fn panic_event_keeps_message_and_adds_error_details() {
        let event = panic_event_parts("src/main.rs:10:5", "boom");
        assert_eq!(event.message, "panic at src/main.rs:10:5: boom");
        assert_eq!(event.severity, Severity::Fatal);
        let error = event.error.expect("panic events carry error details");
        assert_eq!(error.type_name, "panic");
        assert_eq!(error.value.as_deref(), Some("boom"));
    }

    #[test]
    fn error_event_carries_type_chain_and_frames() {
        #[derive(Debug, thiserror::Error)]
        #[error("top failed: {source}")]
        struct Top {
            #[source]
            source: Inner,
        }

        #[derive(Debug, thiserror::Error)]
        #[error("inner broke")]
        struct Inner;

        let error = Top { source: Inner };
        let event = error_event(&error, Severity::Error);
        assert_eq!(event.message, "top failed: inner broke");
        let details = event.error.expect("error events carry error details");
        assert!(details.type_name.ends_with("Top"));
        assert_eq!(details.value.as_deref(), Some("top failed: inner broke"));
        let chain = event
            .contexts
            .get("error_chain")
            .and_then(serde_json::Value::as_array)
            .expect("cause chain recorded");
        assert_eq!(chain.len(), 1);
        assert_eq!(
            chain[0].get("value").and_then(serde_json::Value::as_str),
            Some("inner broke")
        );
    }

    #[test]
    fn error_event_without_causes_omits_chain_context() {
        #[derive(Debug, thiserror::Error)]
        #[error("standalone")]
        struct Standalone;

        let event = error_event(&Standalone, Severity::Warning);
        assert!(event.contexts.is_empty());
    }
}
