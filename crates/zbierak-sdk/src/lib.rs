//! A runtime-independent client for reporting events to Zbierak.
//!
//! Sending happens on one bounded background thread. Application threads never perform an
//! HTTP request: when the in-memory queue is full, events are written to the bounded disk
//! spool instead. Add [`BreadcrumbLayer`] to a `tracing_subscriber` registry to attach recent
//! tracing events to subsequently captured events.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::fs;
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use reqwest::StatusCode;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::field::{Field, Visit};
use tracing::{Event as TracingEvent, Subscriber};
use tracing_subscriber::Layer;
use uuid::Uuid;
use zbierak_protocol::{Breadcrumb, Event, Severity, ValidationError};

/// A callback that can remove or transform sensitive event data before persistence or sending.
pub type Redactor = Arc<dyn Fn(&mut Event) + Send + Sync + 'static>;

/// Configures and constructs a [`Client`].
pub struct ClientBuilder {
    endpoint: String,
    auth_token: Option<String>,
    queue_capacity: usize,
    breadcrumb_capacity: usize,
    spool_dir: PathBuf,
    spool_max_bytes: u64,
    request_timeout: Duration,
    retry_interval: Duration,
    release: Option<String>,
    environment: Option<String>,
    platform: Option<String>,
    redactor: Option<Redactor>,
}

impl ClientBuilder {
    /// Creates a builder whose endpoint is the complete event ingestion URL.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            auth_token: None,
            queue_capacity: 256,
            breadcrumb_capacity: 100,
            spool_dir: PathBuf::from(".zbierak-spool"),
            spool_max_bytes: 10 * 1024 * 1024,
            request_timeout: Duration::from_secs(10),
            retry_interval: Duration::from_secs(5),
            release: None,
            environment: None,
            platform: Some("rust".into()),
            redactor: None,
        }
    }

    /// Sets the bearer token sent with each request.
    #[must_use]
    pub fn auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    /// Sets the bounded in-memory event queue size. The minimum is one.
    #[must_use]
    pub fn queue_capacity(mut self, capacity: usize) -> Self {
        self.queue_capacity = capacity.max(1);
        self
    }

    /// Sets the maximum number of tracing breadcrumbs retained in memory.
    #[must_use]
    pub fn breadcrumb_capacity(mut self, capacity: usize) -> Self {
        self.breadcrumb_capacity = capacity;
        self
    }

    /// Sets the persistent offline spool directory and maximum total bytes.
    ///
    /// A zero byte limit disables disk spooling.
    #[must_use]
    pub fn spool(mut self, directory: impl Into<PathBuf>, max_bytes: u64) -> Self {
        self.spool_dir = directory.into();
        self.spool_max_bytes = max_bytes;
        self
    }

    /// Sets the timeout for an individual HTTP request.
    #[must_use]
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Sets how often the sender checks the offline spool while idle.
    #[must_use]
    pub fn retry_interval(mut self, interval: Duration) -> Self {
        self.retry_interval = interval.max(Duration::from_millis(10));
        self
    }

    /// Sets the release attached when an event does not specify one.
    #[must_use]
    pub fn release(mut self, release: impl Into<String>) -> Self {
        self.release = Some(release.into());
        self
    }

    /// Sets the environment attached when an event does not specify one.
    #[must_use]
    pub fn environment(mut self, environment: impl Into<String>) -> Self {
        self.environment = Some(environment.into());
        self
    }

    /// Sets the platform attached when an event does not specify one.
    #[must_use]
    pub fn platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }

    /// Installs a callback invoked synchronously before validation and queueing.
    ///
    /// Capture fails with [`CaptureError::RedactorPanicked`] if the callback panics.
    #[must_use]
    pub fn redactor<F>(mut self, redactor: F) -> Self
    where
        F: Fn(&mut Event) + Send + Sync + 'static,
    {
        self.redactor = Some(Arc::new(redactor));
        self
    }

    /// Builds the client and starts its sender thread.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] when the endpoint is empty, the HTTP client
    /// cannot be constructed, or the spool directory/sender thread cannot
    /// be created.
    pub fn build(self) -> Result<Client, BuildError> {
        if self.endpoint.trim().is_empty() {
            return Err(BuildError::EmptyEndpoint);
        }
        let http = reqwest::blocking::Client::builder()
            .timeout(self.request_timeout)
            .build()?;
        let spool = Arc::new(Mutex::new(Spool::new(
            self.spool_dir,
            self.spool_max_bytes,
        )?));
        let (sender, receiver) = mpsc::sync_channel(self.queue_capacity);
        let breadcrumbs = Arc::new(Mutex::new(VecDeque::with_capacity(
            self.breadcrumb_capacity,
        )));
        let worker_spool = Arc::clone(&spool);
        let endpoint = self.endpoint;
        let token = self.auth_token;
        let retry_interval = self.retry_interval;
        let worker = thread::Builder::new()
            .name("zbierak-sender".into())
            .spawn(move || {
                run_sender(
                    receiver,
                    http,
                    endpoint,
                    token,
                    worker_spool,
                    retry_interval,
                );
            })?;

        Ok(Client {
            inner: Arc::new(Inner {
                sender,
                worker: Mutex::new(Some(worker)),
                spool,
                breadcrumbs,
                breadcrumb_capacity: self.breadcrumb_capacity,
                release: self.release,
                environment: self.environment,
                platform: self.platform,
                redactor: self.redactor,
            }),
        })
    }
}

/// A cheap-to-clone event client.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

impl Client {
    /// Starts configuring a client for the complete ingestion URL.
    #[must_use]
    pub fn builder(endpoint: impl Into<String>) -> ClientBuilder {
        ClientBuilder::new(endpoint)
    }

    /// Captures a message with the given severity and returns its stable event ID.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError`] when validation or queueing fails; see
    /// [`Client::capture_event`] for the full contract.
    pub fn capture_message(
        &self,
        message: impl Into<String>,
        severity: Severity,
    ) -> Result<String, CaptureError> {
        let event = Event {
            message: message.into(),
            severity,
            ..Event::default()
        };
        self.capture_event(event)
    }

    /// Captures a caller-built event and returns its stable event ID.
    ///
    /// Empty IDs and timestamps are populated. Existing values are retained, including when
    /// the event is retried from disk.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError::RedactorPanicked`] if the redactor panics,
    /// [`CaptureError::InvalidEvent`] when validation fails, and
    /// [`CaptureError::Spool`] when a full queue cannot spill the event to
    /// disk. A full queue that can spill returns `Ok` — the event is safe
    /// on disk even though it has not been sent yet.
    pub fn capture_event(&self, mut event: Event) -> Result<String, CaptureError> {
        if event.event_id.is_empty() {
            event.event_id = Uuid::new_v4().to_string();
        }
        if event.timestamp.is_empty() {
            event.timestamp = now_timestamp();
        }
        if event.release.is_none() {
            event.release.clone_from(&self.inner.release);
        }
        if event.environment.is_none() {
            event.environment.clone_from(&self.inner.environment);
        }
        if event.platform.is_none() {
            event.platform.clone_from(&self.inner.platform);
        }
        if event.breadcrumbs.is_empty() {
            event.breadcrumbs = lock(&self.inner.breadcrumbs).iter().cloned().collect();
        }
        if self.inner.redactor.as_ref().is_some_and(|redactor| {
            panic::catch_unwind(AssertUnwindSafe(|| redactor(&mut event))).is_err()
        }) {
            return Err(CaptureError::RedactorPanicked);
        }
        event.validate()?;
        let event_id = event.event_id.clone();

        match self.inner.sender.try_send(Command::Event(Box::new(event))) {
            Ok(()) => Ok(event_id),
            Err(mpsc::TrySendError::Full(Command::Event(event))) => {
                lock(&self.inner.spool).store(event.as_ref())?;
                Ok(event_id)
            }
            Err(mpsc::TrySendError::Disconnected(_)) => Err(CaptureError::SenderStopped),
            Err(mpsc::TrySendError::Full(_)) => unreachable!("only event commands use try_send"),
        }
    }

    /// Adds a breadcrumb directly to the bounded in-memory trail.
    pub fn add_breadcrumb(&self, breadcrumb: Breadcrumb) {
        push_breadcrumb(
            &self.inner.breadcrumbs,
            self.inner.breadcrumb_capacity,
            breadcrumb,
        );
    }

    /// Returns a tracing subscriber layer backed by this client's breadcrumb trail.
    #[must_use]
    pub fn breadcrumb_layer(&self) -> BreadcrumbLayer {
        BreadcrumbLayer {
            breadcrumbs: Arc::clone(&self.inner.breadcrumbs),
            capacity: self.inner.breadcrumb_capacity,
        }
    }

    /// Installs a process-wide panic hook that captures panics and then invokes the old hook.
    ///
    /// Install this once after constructing the final client. Rust does not provide a safe way
    /// to uninstall a hook without potentially replacing another library's later hook.
    pub fn install_panic_hook(&self) {
        let previous = panic::take_hook();
        let client = self.clone();
        panic::set_hook(Box::new(move |info| {
            let payload = info
                .payload()
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
                .unwrap_or("non-string panic payload");
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
            let _ =
                client.capture_message(format!("panic at {location}: {payload}"), Severity::Fatal);
            previous(info);
        }));
    }

    /// Waits for queued events and retryable spooled events up to `timeout`.
    ///
    /// # Errors
    ///
    /// Returns [`FlushError::TimedOut`] when the deadline elapses first,
    /// [`FlushError::SenderStopped`] when the sender thread is gone, and
    /// [`FlushError::Spool`] when the spool cannot be read mid-flush.
    pub fn flush(&self, timeout: Duration) -> Result<FlushReport, FlushError> {
        let (reply_sender, reply_receiver) = mpsc::sync_channel(1);
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        let mut command = Command::Flush {
            deadline,
            reply: reply_sender,
        };
        loop {
            match self.inner.sender.try_send(command) {
                Ok(()) => break,
                Err(mpsc::TrySendError::Full(returned)) if Instant::now() < deadline => {
                    command = returned;
                    thread::sleep(Duration::from_millis(1));
                }
                Err(mpsc::TrySendError::Full(_)) => return Err(FlushError::TimedOut),
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    return Err(FlushError::SenderStopped);
                }
            }
        }
        let report = reply_receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => FlushError::TimedOut,
                mpsc::RecvTimeoutError::Disconnected => FlushError::SenderStopped,
            })??;
        Ok(report)
    }
}

struct Inner {
    sender: SyncSender<Command>,
    worker: Mutex<Option<JoinHandle<()>>>,
    spool: Arc<Mutex<Spool>>,
    breadcrumbs: Arc<Mutex<VecDeque<Breadcrumb>>>,
    breadcrumb_capacity: usize,
    release: Option<String>,
    environment: Option<String>,
    platform: Option<String>,
    redactor: Option<Redactor>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        let _ = self.sender.send(Command::Shutdown);
        if let Some(worker) = lock(&self.worker).take() {
            let _ = worker.join();
        }
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

enum Command {
    Event(Box<Event>),
    Flush {
        deadline: Instant,
        reply: SyncSender<Result<FlushReport, FlushError>>,
    },
    Shutdown,
}

// Thread entry point: arguments must be moved onto the spawned thread.
#[allow(clippy::needless_pass_by_value)]
fn run_sender(
    receiver: mpsc::Receiver<Command>,
    http: reqwest::blocking::Client,
    endpoint: String,
    token: Option<String>,
    spool: Arc<Mutex<Spool>>,
    retry_interval: Duration,
) {
    loop {
        match receiver.recv_timeout(retry_interval) {
            Ok(Command::Event(event)) => {
                if matches!(
                    deliver(&http, &endpoint, token.as_deref(), event.as_ref()),
                    Delivery::Retry
                ) {
                    let _ = lock(&spool).store(event.as_ref());
                }
            }
            Ok(Command::Flush { deadline, reply }) => {
                let report = drain_spool(&http, &endpoint, token.as_deref(), &spool, deadline);
                let _ = reply.send(report);
            }
            Ok(Command::Shutdown) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = drain_spool(
                    &http,
                    &endpoint,
                    token.as_deref(),
                    &spool,
                    Instant::now() + retry_interval,
                );
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Delivery {
    Delivered,
    PermanentFailure,
    Retry,
}

fn deliver(
    http: &reqwest::blocking::Client,
    endpoint: &str,
    token: Option<&str>,
    event: &Event,
) -> Delivery {
    let mut request = http.post(endpoint).json(event);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    match request.send() {
        Ok(response) if response.status().is_success() => Delivery::Delivered,
        Ok(response) if is_retryable(response.status()) => Delivery::Retry,
        Ok(_) => Delivery::PermanentFailure,
        Err(_) => Delivery::Retry,
    }
}

fn is_retryable(status: StatusCode) -> bool {
    status.is_server_error()
        || status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
}

fn drain_spool(
    http: &reqwest::blocking::Client,
    endpoint: &str,
    token: Option<&str>,
    spool: &Mutex<Spool>,
    deadline: Instant,
) -> Result<FlushReport, FlushError> {
    // SpoolError carries io::Error (not `Eq`), so it is flattened into the
    // message here to keep FlushError comparable.
    fn spool_error<E: std::fmt::Display>(error: E) -> FlushError {
        FlushError::Spool(error.to_string())
    }
    let mut delivered = 0;
    loop {
        if Instant::now() >= deadline {
            return Ok(FlushReport {
                delivered,
                remaining: lock(spool).len().map_err(spool_error)?,
            });
        }
        let Some((path, event)) = lock(spool).oldest().map_err(spool_error)? else {
            return Ok(FlushReport {
                delivered,
                remaining: 0,
            });
        };
        match deliver(http, endpoint, token, &event) {
            Delivery::Delivered => {
                let _ = Spool::remove(&path);
                delivered += 1;
            }
            Delivery::PermanentFailure => {
                let _ = Spool::remove(&path);
            }
            Delivery::Retry => {
                return Ok(FlushReport {
                    delivered,
                    remaining: lock(spool).len().map_err(spool_error)?,
                });
            }
        }
    }
}

struct Spool {
    directory: PathBuf,
    max_bytes: u64,
}

impl Spool {
    fn new(directory: PathBuf, max_bytes: u64) -> io::Result<Self> {
        if max_bytes > 0 {
            fs::create_dir_all(&directory)?;
        }
        Ok(Self {
            directory,
            max_bytes,
        })
    }

    fn store(&mut self, event: &Event) -> Result<(), SpoolError> {
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
    fn oldest(&self) -> Result<Option<(PathBuf, Event)>, SpoolError> {
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

    fn remove(path: &Path) -> io::Result<()> {
        fs::remove_file(path)
    }

    /// Number of spool files currently on disk.
    fn len(&self) -> io::Result<usize> {
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

fn push_breadcrumb(
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
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn event_id_is_generated_before_queueing() {
        let directory = tempfile::tempdir().unwrap();
        let client = Client::builder("http://127.0.0.1:1/events")
            .spool(directory.path(), 1024 * 1024)
            .request_timeout(Duration::from_millis(20))
            .build()
            .unwrap();
        let id = client.capture_message("failure", Severity::Error).unwrap();
        assert!(Uuid::parse_str(&id).is_ok());
        let _ = client.flush(Duration::from_millis(100));
    }

    #[test]
    fn redactor_runs_before_event_is_accepted() {
        let directory = tempfile::tempdir().unwrap();
        let client = Client::builder("http://127.0.0.1:1/events")
            .spool(directory.path(), 1024 * 1024)
            .redactor(|event| {
                event.tags.remove("secret");
                event.message = event.message.replace("token", "[redacted]");
            })
            .build()
            .unwrap();
        let mut event = Event {
            message: "token leaked".into(),
            ..Event::default()
        };
        event.tags.insert("secret".into(), "value".into());
        assert!(client.capture_event(event).is_ok());
    }

    #[test]
    fn tracing_layer_keeps_a_bounded_trail() {
        let directory = tempfile::tempdir().unwrap();
        let client = Client::builder("http://127.0.0.1:1/events")
            .spool(directory.path(), 1024 * 1024)
            .breadcrumb_capacity(1)
            .build()
            .unwrap();
        let subscriber = tracing_subscriber::registry().with(client.breadcrumb_layer());
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(request_id = 7_u64, "first");
            tracing::warn!("second");
        });
        let breadcrumbs = lock(&client.inner.breadcrumbs);
        assert_eq!(breadcrumbs.len(), 1);
        assert!(breadcrumbs[0].message.contains("second"));
        assert_eq!(breadcrumbs[0].severity, Severity::Warning);
    }

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
}
