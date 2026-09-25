//! Synchronous [`Client`] backed by a dedicated OS sender thread.

use std::collections::VecDeque;
use std::fmt;
use std::panic;
use std::path::PathBuf;
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use zbierak_protocol::{Breadcrumb, Event, Severity};

use crate::{
    BreadcrumbLayer, BuildError, CaptureContext, CaptureError, Delivery, FlushError, FlushReport,
    Spool, error_event, is_retryable, lock, panic_event, push_breadcrumb,
};

/// Configures and constructs a [`Client`].
pub struct ClientBuilder {
    endpoint: String,
    auth_token: Option<String>,
    queue_capacity: usize,
    spool_dir: PathBuf,
    spool_max_bytes: u64,
    request_timeout: Duration,
    retry_interval: Duration,
    context: CaptureContext,
}

impl ClientBuilder {
    /// Creates a builder whose endpoint is the complete event ingestion URL.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            auth_token: None,
            queue_capacity: 256,
            spool_dir: PathBuf::from(".zbierak-spool"),
            spool_max_bytes: 10 * 1024 * 1024,
            request_timeout: Duration::from_secs(10),
            retry_interval: Duration::from_secs(5),
            context: CaptureContext {
                release: None,
                environment: None,
                platform: Some("rust".into()),
                breadcrumbs: Arc::new(Mutex::new(VecDeque::new())),
                breadcrumb_capacity: 100,
                redactor: None,
            },
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
        self.context.breadcrumb_capacity = capacity;
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
        self.context.release = Some(release.into());
        self
    }

    /// Sets the environment attached when an event does not specify one.
    #[must_use]
    pub fn environment(mut self, environment: impl Into<String>) -> Self {
        self.context.environment = Some(environment.into());
        self
    }

    /// Sets the platform attached when an event does not specify one.
    #[must_use]
    pub fn platform(mut self, platform: impl Into<String>) -> Self {
        self.context.platform = Some(platform.into());
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
        self.context.redactor = Some(Arc::new(redactor));
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
        lock(&self.context.breadcrumbs).reserve(self.context.breadcrumb_capacity);
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
                context: self.context,
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
    pub fn capture_event(&self, event: Event) -> Result<String, CaptureError> {
        let event = self.inner.context.prepare(event)?;
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
            &self.inner.context.breadcrumbs,
            self.inner.context.breadcrumb_capacity,
            breadcrumb,
        );
    }

    /// Returns a tracing subscriber layer backed by this client's breadcrumb trail.
    #[must_use]
    pub fn breadcrumb_layer(&self) -> BreadcrumbLayer {
        BreadcrumbLayer {
            breadcrumbs: Arc::clone(&self.inner.context.breadcrumbs),
            capacity: self.inner.context.breadcrumb_capacity,
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
            let _ = client.capture_event(panic_event(info));
            previous(info);
        }));
    }

    /// Captures an error value with its cause chain and the current stack
    /// frames, and returns its stable event ID.
    ///
    /// The error text becomes the event message, the concrete type and stack
    /// fill [`crate::ErrorInfo`], and `source()` causes land in the `error_chain`
    /// context.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError`] under the same conditions as
    /// [`Client::capture_event`].
    pub fn capture_error<E: std::error::Error + 'static>(
        &self,
        error: &E,
        severity: Severity,
    ) -> Result<String, CaptureError> {
        self.capture_event(error_event(error, severity))
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
    context: CaptureContext,
}

impl Drop for Inner {
    fn drop(&mut self) {
        let _ = self.sender.send(Command::Shutdown);
        if let Some(worker) = lock(&self.worker).take() {
            let _ = worker.join();
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

fn drain_spool(
    http: &reqwest::blocking::Client,
    endpoint: &str,
    token: Option<&str>,
    spool: &Mutex<Spool>,
    deadline: Instant,
) -> Result<FlushReport, FlushError> {
    // SpoolError carries io::Error (not `Eq`), so it is flattened into the
    // message here to keep FlushError comparable.
    fn spool_error<E: fmt::Display>(error: E) -> FlushError {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;
    use uuid::Uuid;

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
        let breadcrumbs = lock(&client.inner.context.breadcrumbs);
        assert_eq!(breadcrumbs.len(), 1);
        assert!(breadcrumbs[0].message.contains("second"));
        assert_eq!(breadcrumbs[0].severity, Severity::Warning);
    }
}
