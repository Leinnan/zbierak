//! Asynchronous [`AsyncClient`] backed by a spawned Tokio sender task.

use std::panic;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use zbierak_protocol::{Breadcrumb, Event, Severity};

use crate::{
    BreadcrumbLayer, BuildError, CaptureContext, CaptureError, Delivery, FlushError, FlushReport,
    Spool, error_event, is_retryable, lock, panic_event, push_breadcrumb,
};

/// Configures and constructs an [`AsyncClient`].
pub struct AsyncClientBuilder {
    endpoint: String,
    auth_token: Option<String>,
    queue_capacity: usize,
    spool_dir: std::path::PathBuf,
    spool_max_bytes: u64,
    request_timeout: Duration,
    retry_interval: Duration,
    context: CaptureContext,
}

impl AsyncClientBuilder {
    /// Creates a builder whose endpoint is the complete event ingestion URL.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            auth_token: None,
            queue_capacity: 256,
            spool_dir: std::path::PathBuf::from(".zbierak-spool"),
            spool_max_bytes: 10 * 1024 * 1024,
            request_timeout: Duration::from_secs(10),
            retry_interval: Duration::from_secs(5),
            context: CaptureContext {
                release: None,
                environment: None,
                platform: Some("rust".into()),
                breadcrumbs: Arc::new(Mutex::new(std::collections::VecDeque::new())),
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
    pub fn spool(mut self, directory: impl Into<std::path::PathBuf>, max_bytes: u64) -> Self {
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

    /// Builds the client and spawns its sender task.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] when the endpoint is empty, the HTTP client
    /// cannot be constructed, or the spool directory cannot be created.
    ///
    /// # Panics
    ///
    /// Panics when called outside of a Tokio runtime, because the sender task
    /// must be spawned onto one.
    pub fn build(self) -> Result<AsyncClient, BuildError> {
        if self.endpoint.trim().is_empty() {
            return Err(BuildError::EmptyEndpoint);
        }
        let http = reqwest::Client::builder()
            .timeout(self.request_timeout)
            .build()?;
        let spool = Arc::new(Mutex::new(Spool::new(
            self.spool_dir,
            self.spool_max_bytes,
        )?));
        let (sender, receiver) = mpsc::channel(self.queue_capacity);
        lock(&self.context.breadcrumbs).reserve(self.context.breadcrumb_capacity);
        let worker_spool = Arc::clone(&spool);
        let endpoint = self.endpoint;
        let token = self.auth_token;
        let retry_interval = self.retry_interval;
        let worker = tokio::spawn(run_worker(
            receiver,
            http,
            endpoint,
            token,
            worker_spool,
            retry_interval,
        ));

        Ok(AsyncClient {
            inner: Arc::new(Inner {
                sender,
                worker: Mutex::new(Some(worker)),
                spool,
                shutdown: AtomicBool::new(false),
                context: self.context,
            }),
        })
    }
}

/// A cheap-to-clone event client whose sender runs as a Tokio task.
///
/// Capture methods are synchronous: they validate and enqueue without ever
/// awaiting, so they are safe to call from sync code inside async applications.
/// Only [`flush`](AsyncClient::flush) and [`shutdown`](AsyncClient::shutdown)
/// are asynchronous.
#[derive(Clone)]
pub struct AsyncClient {
    inner: Arc<Inner>,
}

impl AsyncClient {
    /// Starts configuring a client for the complete ingestion URL.
    #[must_use]
    pub fn builder(endpoint: impl Into<String>) -> AsyncClientBuilder {
        AsyncClientBuilder::new(endpoint)
    }

    /// Captures a message with the given severity and returns its stable event ID.
    ///
    /// # Errors
    ///
    /// Returns [`CaptureError`] when validation or queueing fails; see
    /// [`AsyncClient::capture_event`] for the full contract.
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
    /// Returns [`CaptureError::SenderStopped`] once [`AsyncClient::shutdown`]
    /// was called on any clone, [`CaptureError::RedactorPanicked`] if the
    /// redactor panics, [`CaptureError::InvalidEvent`] when validation fails,
    /// and [`CaptureError::Spool`] when a full queue cannot spill the event to
    /// disk. A full queue that can spill returns `Ok` — the event is safe
    /// on disk even though it has not been sent yet.
    pub fn capture_event(&self, event: Event) -> Result<String, CaptureError> {
        if self.inner.shutdown.load(Ordering::Relaxed) {
            return Err(CaptureError::SenderStopped);
        }
        let event = self.inner.context.prepare(event)?;
        let event_id = event.event_id.clone();

        match self.inner.sender.try_send(Command::Event(Box::new(event))) {
            Ok(()) => Ok(event_id),
            Err(mpsc::error::TrySendError::Full(Command::Event(event))) => {
                lock(&self.inner.spool).store(event.as_ref())?;
                Ok(event_id)
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                unreachable!("only event commands use try_send")
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(CaptureError::SenderStopped),
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
    /// [`AsyncClient::capture_event`].
    pub fn capture_error<E: std::error::Error + 'static>(
        &self,
        error: &E,
        severity: Severity,
    ) -> Result<String, CaptureError> {
        self.capture_event(error_event(error, severity))
    }

    /// Waits for queued events and retryable spooled events up to `timeout`.
    ///
    /// The wait includes queuing the flush request itself, so a full queue
    /// cannot extend the call past the deadline.
    ///
    /// # Errors
    ///
    /// Returns [`FlushError::TimedOut`] when the deadline elapses first,
    /// [`FlushError::SenderStopped`] when the sender task is gone, and
    /// [`FlushError::Spool`] when the spool cannot be read mid-flush.
    pub async fn flush(&self, timeout: Duration) -> Result<FlushReport, FlushError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        let tokio_deadline = tokio::time::Instant::from(deadline);
        let (reply, reply_receiver) = oneshot::channel();
        let send = self.inner.sender.send(Command::Flush { deadline, reply });
        match tokio::time::timeout_at(tokio_deadline, send).await {
            Err(_) => Err(FlushError::TimedOut),
            Ok(Err(_)) => Err(FlushError::SenderStopped),
            Ok(Ok(())) => match tokio::time::timeout_at(tokio_deadline, reply_receiver).await {
                Err(_) => Err(FlushError::TimedOut),
                Ok(Err(_)) => Err(FlushError::SenderStopped),
                Ok(Ok(report)) => report,
            },
        }
    }

    /// Stops the client and waits for queued events to be attempted.
    ///
    /// The worker finishes every event queued before the stop request —
    /// failures retryable later are written to the offline spool — and then
    /// exits. The client is marked stopped for every clone: subsequent
    /// captures return [`CaptureError::SenderStopped`].
    ///
    /// Clients dropped without calling this method close their queue the same
    /// way, but the drop cannot wait for the worker, so delivery of the last
    /// queued events is not guaranteed.
    pub async fn shutdown(self) {
        self.inner.shutdown.store(true, Ordering::Relaxed);
        let _ = self.inner.sender.send(Command::Shutdown).await;
        // Take the handle in its own statement so the lock guard is not held
        // across the await below.
        let worker = lock(&self.inner.worker).take();
        if let Some(worker) = worker {
            let _ = worker.await;
        }
    }
}

struct Inner {
    sender: mpsc::Sender<Command>,
    worker: Mutex<Option<JoinHandle<()>>>,
    spool: Arc<Mutex<Spool>>,
    shutdown: AtomicBool,
    context: CaptureContext,
}

enum Command {
    Event(Box<Event>),
    Flush {
        deadline: Instant,
        reply: oneshot::Sender<Result<FlushReport, FlushError>>,
    },
    Shutdown,
}

// Task entry point: arguments must be moved onto the spawned task.
#[allow(clippy::needless_pass_by_value)]
async fn run_worker(
    mut receiver: mpsc::Receiver<Command>,
    http: reqwest::Client,
    endpoint: String,
    token: Option<String>,
    spool: Arc<Mutex<Spool>>,
    retry_interval: Duration,
) {
    loop {
        let command = tokio::time::timeout(retry_interval, receiver.recv()).await;
        match command {
            Ok(Some(Command::Event(event))) => {
                if matches!(
                    deliver(&http, &endpoint, token.as_deref(), event.as_ref()).await,
                    Delivery::Retry
                ) {
                    let _ = lock(&spool).store(event.as_ref());
                }
            }
            Ok(Some(Command::Flush { deadline, reply })) => {
                let report =
                    drain_spool(&http, &endpoint, token.as_deref(), &spool, deadline).await;
                let _ = reply.send(report);
            }
            Ok(Some(Command::Shutdown) | None) => break,
            Err(_elapsed) => {
                let _ = drain_spool(
                    &http,
                    &endpoint,
                    token.as_deref(),
                    &spool,
                    Instant::now() + retry_interval,
                )
                .await;
            }
        }
    }
}

async fn deliver(
    http: &reqwest::Client,
    endpoint: &str,
    token: Option<&str>,
    event: &Event,
) -> Delivery {
    let mut request = http.post(endpoint).json(event);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    match request.send().await {
        Ok(response) if response.status().is_success() => Delivery::Delivered,
        Ok(response) if is_retryable(response.status()) => Delivery::Retry,
        Ok(_) => Delivery::PermanentFailure,
        Err(_) => Delivery::Retry,
    }
}

async fn drain_spool(
    http: &reqwest::Client,
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
        match deliver(http, endpoint, token, &event).await {
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use uuid::Uuid;

    /// Reads one complete HTTP request (headers plus `content-length` body).
    async fn read_request(socket: &mut TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            if request_complete(&request) {
                return request;
            }
            let read = socket.read(&mut chunk).await.expect("socket readable");
            assert!(read > 0, "connection closed before the request completed");
            request.extend_from_slice(&chunk[..read]);
        }
    }

    fn request_complete(request: &[u8]) -> bool {
        let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            return false;
        };
        let headers = String::from_utf8_lossy(&request[..end]);
        matches!(content_length(&headers), Some(length) if request.len() >= end + 4 + length)
    }

    fn content_length(headers: &str) -> Option<usize> {
        for line in headers.lines() {
            if let Some((name, value)) = line.split_once(':')
                && name.trim().eq_ignore_ascii_case("content-length")
            {
                return value.trim().parse().ok();
            }
        }
        None
    }

    /// Answers exactly `expected` POSTs with 200 and returns their bodies.
    async fn serve_requests(listener: TcpListener, expected: usize) -> Vec<String> {
        let mut bodies = Vec::new();
        for _ in 0..expected {
            let (mut socket, _) = listener.accept().await.expect("connection accepted");
            let request = read_request(&mut socket).await;
            let header_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .expect("request headers");
            bodies.push(String::from_utf8_lossy(&request[header_end + 4..]).into_owned());
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await;
        }
        bodies
    }

    #[tokio::test]
    async fn event_id_is_generated_before_queueing() {
        let directory = tempfile::tempdir().unwrap();
        let client = AsyncClient::builder("http://127.0.0.1:1/events")
            .spool(directory.path(), 1024 * 1024)
            .request_timeout(Duration::from_millis(20))
            .build()
            .unwrap();
        let id = client.capture_message("failure", Severity::Error).unwrap();
        assert!(Uuid::parse_str(&id).is_ok());
        client.shutdown().await;
    }

    #[tokio::test]
    async fn redactor_runs_before_event_is_accepted() {
        let directory = tempfile::tempdir().unwrap();
        let client = AsyncClient::builder("http://127.0.0.1:1/events")
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
        client.shutdown().await;
    }

    #[tokio::test]
    async fn queued_events_are_delivered_with_their_ids() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { serve_requests(listener, 2).await });
        let directory = tempfile::tempdir().unwrap();
        let client = AsyncClient::builder(format!("http://{address}/events"))
            .spool(directory.path(), 1024 * 1024)
            .build()
            .unwrap();
        let first = client.capture_message("first", Severity::Error).unwrap();
        let second = client.capture_message("second", Severity::Error).unwrap();
        let report = client.flush(Duration::from_secs(5)).await.unwrap();
        assert_eq!(report, FlushReport::default());
        client.shutdown().await;
        let bodies = server.await.unwrap();
        assert_eq!(bodies.len(), 2);
        assert!(bodies[0].contains(&first));
        assert!(bodies[1].contains(&second));
    }

    #[tokio::test]
    async fn undeliverable_event_is_spooled_and_flush_reports_remaining() {
        let directory = tempfile::tempdir().unwrap();
        let client = AsyncClient::builder("http://127.0.0.1:1/events")
            .spool(directory.path(), 1024 * 1024)
            .request_timeout(Duration::from_millis(50))
            .build()
            .unwrap();
        client.capture_message("offline", Severity::Error).unwrap();
        let report = client.flush(Duration::from_secs(5)).await.unwrap();
        assert_eq!(
            report,
            FlushReport {
                delivered: 0,
                remaining: 1,
            }
        );
        client.shutdown().await;
    }

    #[tokio::test]
    async fn full_queue_spills_to_disk_while_worker_is_stalled() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let holder = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("stalled connection");
            // Hold the connection open without responding to stall the worker.
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(socket);
        });
        let directory = tempfile::tempdir().unwrap();
        let client = AsyncClient::builder(format!("http://{address}/events"))
            .queue_capacity(1)
            .request_timeout(Duration::from_millis(50))
            .retry_interval(Duration::from_secs(3600))
            .spool(directory.path(), 1024 * 1024)
            .build()
            .unwrap();
        client.capture_message("first", Severity::Error).unwrap();
        client.capture_message("second", Severity::Error).unwrap();
        client.capture_message("third", Severity::Error).unwrap();
        assert!(lock(&client.inner.spool).len().unwrap() >= 1);
        client.shutdown().await;
        holder.abort();
    }

    #[tokio::test]
    async fn capture_after_shutdown_reports_sender_stopped() {
        let directory = tempfile::tempdir().unwrap();
        let client = AsyncClient::builder("http://127.0.0.1:1/events")
            .spool(directory.path(), 1024 * 1024)
            .build()
            .unwrap();
        let probe = client.clone();
        client.shutdown().await;
        let result = probe.capture_message("late", Severity::Error);
        assert!(matches!(result, Err(CaptureError::SenderStopped)));
    }
}
