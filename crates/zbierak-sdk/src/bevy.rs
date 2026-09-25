//! Bevy integration for reporting events to Zbierak.
//!
//! The module wires the SDK into a Bevy app in three steps, mirroring how
//! `bevy_log::LogPlugin` expects extensions:
//!
//! 1. Call [`init`] *before* adding any plugins. It stores a
//!    [`RuntimeClient`] process-wide and installs the panic hook.
//! 2. Register [`log_capture_layer`] as the `custom_layer` of
//!    `LogPlugin`. Bevy invokes the function while building its tracing
//!    subscriber, which installs a `tracing_subscriber::Layer` that
//!    forwards Bevy `error!` (and optionally lower-severity) log events
//!    into a channel the drain system reads. Matching events capture the
//!    current call-site stack frames inside the layer, on the emitting
//!    thread ([`ReportConfig::capture_stack_frames`], on by default).
//! 3. Add [`ZbierakPlugin`], which registers the `PreUpdate` system that
//!    drains captured log events, applies rate limiting and duplicate
//!    suppression, and queues them on the client.
//!
//! ```ignore
//! use bevy::log::LogPlugin;
//! use zbierak_sdk::Client;
//!
//! let client = Client::builder("https://errors.example.com/api/v1/projects/game/events")
//!     .auth_token("zbk_REPLACE_WITH_PROJECT_KEY")
//!     .release(env!("CARGO_PKG_VERSION"))
//!     .build()?;
//! zbierak_sdk::bevy::init(client, Default::default())?;
//!
//! App::new()
//!     .add_plugins(
//!         DefaultPlugins.set(LogPlugin {
//!             custom_layer: zbierak_sdk::bevy::log_capture_layer,
//!             ..default()
//!         }),
//!     )
//!     .add_plugins(zbierak_sdk::bevy::ZbierakPlugin);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Log events whose target starts with one of
//! [`ReportConfig::excluded_targets`] (the SDK itself, by default) and
//! messages produced by the SDK panic hook are never reported, so the
//! pipeline cannot report on itself.
//!
//! On `wasm32` the module exposes inert stubs so game code compiles
//! unchanged: [`init`] returns `InitError::UnsupportedTarget` and the
//! layer function never installs anything.

// The Bevy integration needs a client to report through.
#[cfg(not(any(feature = "blocking", feature = "async")))]
compile_error!("the `bevy` feature requires the `blocking` or `async` client feature");

use std::time::Duration;

use tracing::Level;
use zbierak_protocol::Severity;

/// Failure to initialize the process-wide Bevy reporting state.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InitError {
    /// [`init`] was called more than once. The first client wins.
    #[error("Zbierak reporting is already initialized")]
    AlreadyInitialized,
    /// Reporting is unavailable on this target (wasm32 stubs).
    #[cfg(target_arch = "wasm32")]
    #[error("Zbierak reporting is not supported on this target")]
    UnsupportedTarget,
}

/// Tunables for the Bevy log capture pipeline.
///
/// Defaults mirror a low-noise production setup: only `error!` events are
/// forwarded, at most 20 per rolling minute, with identical messages
/// suppressed for a minute, and each captured event carries the call-site
/// stack frames.
#[derive(Clone, Debug)]
pub struct ReportConfig {
    /// Minimum [`Level`] forwarded to Zbierak. tracing orders levels by
    /// verbosity (`ERROR < WARN < INFO < DEBUG < TRACE`), so
    /// [`Level::ERROR`] captures errors only and [`Level::WARN`] captures
    /// warnings and errors.
    capture_level: Level,
    /// Sliding rate window for the global event cap.
    rate_window: Duration,
    /// Maximum events forwarded per rate window; the rest are dropped.
    max_events_per_window: usize,
    /// Skip re-reporting an identical message within this window.
    duplicate_suppression: Duration,
    /// Upper bound on messages tracked for duplicate suppression.
    max_tracked_messages: usize,
    /// Messages are truncated to this size before queueing.
    max_message_bytes: usize,
    /// Log targets with these prefixes are never captured.
    excluded_targets: Vec<String>,
    /// Whether matching log events capture the current stack frames.
    capture_stack_frames: bool,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            capture_level: Level::ERROR,
            rate_window: Duration::from_secs(60),
            max_events_per_window: 20,
            duplicate_suppression: Duration::from_secs(60),
            max_tracked_messages: 1024,
            max_message_bytes: 4096,
            excluded_targets: vec!["zbierak".into()],
            capture_stack_frames: true,
        }
    }
}

impl ReportConfig {
    /// Sets the minimum [`Level`] forwarded to Zbierak.
    #[must_use]
    pub fn capture_level(mut self, level: Level) -> Self {
        self.capture_level = level;
        self
    }

    /// Sets the sliding rate window for the global event cap.
    #[must_use]
    pub fn rate_window(mut self, window: Duration) -> Self {
        self.rate_window = window;
        self
    }

    /// Sets the maximum events forwarded per rate window.
    #[must_use]
    pub fn max_events_per_window(mut self, max: usize) -> Self {
        self.max_events_per_window = max;
        self
    }

    /// Sets how long an identical message is suppressed after reporting.
    #[must_use]
    pub fn duplicate_suppression(mut self, window: Duration) -> Self {
        self.duplicate_suppression = window;
        self
    }

    /// Sets the upper bound on messages tracked for duplicate suppression.
    #[must_use]
    pub fn max_tracked_messages(mut self, max: usize) -> Self {
        self.max_tracked_messages = max;
        self
    }

    /// Sets the size at which messages are truncated before queueing.
    #[must_use]
    pub fn max_message_bytes(mut self, max: usize) -> Self {
        self.max_message_bytes = max;
        self
    }

    /// Replaces the log-target prefixes that are never captured.
    ///
    /// Targets are matched with [`str::starts_with`]; the SDK's own targets
    /// (`zbierak…`) are excluded by default so the reporting pipeline cannot
    /// report on itself.
    #[must_use]
    pub fn excluded_targets(
        mut self,
        prefixes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.excluded_targets = prefixes.into_iter().map(Into::into).collect();
        self
    }

    /// Sets whether matching log events capture the current stack frames.
    ///
    /// Frames are captured inside the tracing layer, on the thread that
    /// emitted the log event, so the first reported frame is the call site
    /// above the `error!`/`warn!` invocation. Capturing runs before rate
    /// limiting, on the emitting thread; disable it if hot error paths must
    /// stay allocation- and symbolication-free.
    ///
    /// When the SDK is built without the `stacktraces` feature this setting
    /// has no effect: capture degrades to an empty frame list.
    #[must_use]
    pub fn capture_stack_frames(mut self, capture: bool) -> Self {
        self.capture_stack_frames = capture;
        self
    }
}

/// Maps a tracing level onto the protocol severities.
fn severity_for(level: Level) -> Severity {
    match level {
        Level::ERROR => Severity::Error,
        Level::WARN => Severity::Warning,
        Level::INFO => Severity::Info,
        Level::TRACE | Level::DEBUG => Severity::Debug,
    }
}

/// Truncates to at most `max_bytes` without splitting a UTF-8 code point.
fn truncate_utf8(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::collections::HashMap;
    use std::sync::OnceLock;
    use std::sync::mpsc::{self, Sender};
    use std::time::Instant;

    use bevy_app::{App, Plugin, PreUpdate};
    use bevy_ecs::system::{Local, NonSend};
    use bevy_log::BoxedLayer;
    use tracing::field::{Field, Visit};
    use tracing::{Event as TracingEvent, Level, Subscriber};
    use tracing_subscriber::Layer;
    use zbierak_protocol::{Breadcrumb, ErrorInfo, Event, StackFrame};

    use super::{InitError, ReportConfig, Severity, severity_for, truncate_utf8};
    #[cfg(feature = "async")]
    use crate::AsyncClient;
    use crate::CaptureError;
    #[cfg(feature = "blocking")]
    use crate::Client;

    /// A cheap-to-clone client handle for either supported runtime.
    #[derive(Clone)]
    pub enum RuntimeClient {
        /// Synchronous client sending on a dedicated OS thread.
        #[cfg(feature = "blocking")]
        Blocking(Client),
        /// Asynchronous client sending on a spawned Tokio task.
        #[cfg(feature = "async")]
        Async(AsyncClient),
    }

    impl RuntimeClient {
        /// Captures a message with the given severity and returns its stable event ID.
        ///
        /// # Errors
        ///
        /// Returns [`CaptureError`] when validation or queueing fails.
        pub fn capture_message(
            &self,
            message: impl Into<String>,
            severity: Severity,
        ) -> Result<String, CaptureError> {
            match self {
                #[cfg(feature = "blocking")]
                Self::Blocking(client) => client.capture_message(message, severity),
                #[cfg(feature = "async")]
                Self::Async(client) => client.capture_message(message, severity),
            }
        }

        /// Captures a caller-built event and returns its stable event ID.
        ///
        /// # Errors
        ///
        /// Returns [`CaptureError`] when validation or queueing fails; see the
        /// underlying client for the full contract.
        pub fn capture_event(&self, event: Event) -> Result<String, CaptureError> {
            match self {
                #[cfg(feature = "blocking")]
                Self::Blocking(client) => client.capture_event(event),
                #[cfg(feature = "async")]
                Self::Async(client) => client.capture_event(event),
            }
        }

        /// Captures an error value with its cause chain and the current stack
        /// frames, and returns its stable event ID.
        ///
        /// # Errors
        ///
        /// Returns [`CaptureError`] when validation or queueing fails; see the
        /// underlying client for the full contract.
        pub fn capture_error<E: std::error::Error + 'static>(
            &self,
            error: &E,
            severity: Severity,
        ) -> Result<String, CaptureError> {
            match self {
                #[cfg(feature = "blocking")]
                Self::Blocking(client) => client.capture_error(error, severity),
                #[cfg(feature = "async")]
                Self::Async(client) => client.capture_error(error, severity),
            }
        }

        /// Adds a breadcrumb directly to the bounded in-memory trail.
        pub fn add_breadcrumb(&self, breadcrumb: Breadcrumb) {
            match self {
                #[cfg(feature = "blocking")]
                Self::Blocking(client) => client.add_breadcrumb(breadcrumb),
                #[cfg(feature = "async")]
                Self::Async(client) => client.add_breadcrumb(breadcrumb),
            }
        }

        /// Installs the process-wide panic hook on the underlying client.
        pub fn install_panic_hook(&self) {
            match self {
                #[cfg(feature = "blocking")]
                Self::Blocking(client) => client.install_panic_hook(),
                #[cfg(feature = "async")]
                Self::Async(client) => client.install_panic_hook(),
            }
        }
    }

    #[cfg(feature = "blocking")]
    impl From<Client> for RuntimeClient {
        fn from(client: Client) -> Self {
            Self::Blocking(client)
        }
    }

    #[cfg(feature = "async")]
    impl From<AsyncClient> for RuntimeClient {
        fn from(client: AsyncClient) -> Self {
            Self::Async(client)
        }
    }

    struct Global {
        client: RuntimeClient,
        config: ReportConfig,
    }

    static GLOBAL: OnceLock<Global> = OnceLock::new();

    /// Initializes process-wide Bevy reporting with the given client and
    /// configuration, installing the panic hook.
    ///
    /// Call once from `main` before adding plugins; the `LogPlugin`
    /// invokes [`log_capture_layer`] while building its subscriber, so the
    /// client must already be registered by then.
    ///
    /// # Errors
    ///
    /// Returns [`InitError::AlreadyInitialized`] if reporting was
    /// initialized before; the first client and configuration win.
    pub fn init(client: impl Into<RuntimeClient>, config: ReportConfig) -> Result<(), InitError> {
        let client = client.into();
        client.install_panic_hook();
        GLOBAL
            .set(Global { client, config })
            .map_err(|_| InitError::AlreadyInitialized)
    }

    /// Returns the process-wide client when reporting is initialized.
    #[must_use]
    pub fn client() -> Option<&'static RuntimeClient> {
        GLOBAL.get().map(|global| &global.client)
    }

    /// Captures a message at the given severity when reporting is initialized.
    pub fn capture_message(message: impl Into<String>, severity: Severity) {
        if let Some(client) = client() {
            let _ = client.capture_message(message, severity);
        }
    }

    /// Returns the process-wide configuration when reporting is initialized.
    fn config() -> Option<&'static ReportConfig> {
        GLOBAL.get().map(|global| &global.config)
    }

    /// `LogPlugin::custom_layer` compatible hook that installs the log
    /// capture layer.
    ///
    /// Bevy calls this while building its tracing subscriber, so reporting
    /// must already be initialized with [`init`]. The layer forwards captured
    /// log events through a channel; [`ZbierakPlugin`] registers the system
    /// that drains it.
    pub fn log_capture_layer(app: &mut App) -> Option<BoxedLayer> {
        let config = config()?;
        let (sender, receiver) = mpsc::channel();
        app.insert_non_send(LogCaptureReceiver(receiver));
        Some(Box::new(LogCaptureLayer {
            sender,
            capture_level: config.capture_level,
            excluded_targets: config.excluded_targets.clone(),
            capture_stack_frames: config.capture_stack_frames,
        }))
    }

    /// Bevy plugin that registers the log drain system.
    ///
    /// Add after `DefaultPlugins`; the drain system no-ops until both
    /// [`init`] and [`log_capture_layer`] ran.
    #[derive(Default)]
    pub struct ZbierakPlugin;

    impl Plugin for ZbierakPlugin {
        fn build(&self, app: &mut App) {
            app.add_systems(PreUpdate, drain_captured_logs);
        }
    }

    /// A captured Bevy log event on its way to the drain system.
    pub(crate) struct CapturedLog {
        pub(crate) message: String,
        pub(crate) target: String,
        pub(crate) level: Level,
        /// Call-site stack frames, empty when capture is disabled or the
        /// `stacktraces` feature is compiled out.
        pub(crate) frames: Vec<StackFrame>,
    }

    /// `custom_layer` layer forwarding matching log events to the drain
    /// system.
    pub(crate) struct LogCaptureLayer {
        pub(crate) sender: Sender<CapturedLog>,
        pub(crate) capture_level: Level,
        pub(crate) excluded_targets: Vec<String>,
        pub(crate) capture_stack_frames: bool,
    }

    impl<S: Subscriber> Layer<S> for LogCaptureLayer {
        fn on_event(
            &self,
            event: &TracingEvent<'_>,
            _context: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let level = *event.metadata().level();
            // tracing orders levels by verbosity, so `WARN <= ERROR` is false.
            if level > self.capture_level {
                return;
            }
            let target = event.metadata().target();
            if self
                .excluded_targets
                .iter()
                .any(|prefix| target.starts_with(prefix.as_str()))
            {
                return;
            }
            let mut message = None;
            event.record(&mut MessageVisitor(&mut message));
            let Some(message) = message else {
                return;
            };
            // Panics are reported by the SDK panic hook as `fatal`; skip the
            // duplicate log entry in case a subscriber stack emits one.
            if message.starts_with("panic at ") {
                return;
            }
            // The layer runs on the emitting thread, so the current stack is
            // the call site of the `error!`/`warn!` invocation.
            let frames = if self.capture_stack_frames {
                crate::stacktrace::capture_frames()
            } else {
                Vec::new()
            };
            self.sender
                .send(CapturedLog {
                    message,
                    target: target.to_owned(),
                    level,
                    frames,
                })
                .ok();
        }
    }

    /// Extracts the `message` field from a tracing event.
    struct MessageVisitor<'a>(&'a mut Option<String>);

    impl Visit for MessageVisitor<'_> {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                *self.0 = Some(format!("{value:?}"));
            }
        }
    }

    /// Non-`Send` side of the capture channel, held by the app.
    struct LogCaptureReceiver(mpsc::Receiver<CapturedLog>);

    /// Sliding rate and duplicate suppression state of the drain system.
    #[derive(Default)]
    pub(crate) struct ThrottleState {
        last_sent: HashMap<String, Instant>,
        window_start: Option<Instant>,
        pub(crate) sent_in_window: usize,
        pub(crate) dropped_in_window: usize,
    }

    /// `PreUpdate` system draining captured log events into the client.
    fn drain_captured_logs(
        receiver: Option<NonSend<LogCaptureReceiver>>,
        mut state: Local<ThrottleState>,
    ) {
        let Some(global) = GLOBAL.get() else {
            return;
        };
        let Some(receiver) = receiver else {
            return;
        };
        process_captured(
            &global.client,
            &global.config,
            &mut state,
            receiver.0.try_iter(),
        );
    }

    /// Core of the drain system: rate limiting, duplicate suppression,
    /// truncation, and queueing. Free-standing for unit testing.
    pub(crate) fn process_captured(
        client: &RuntimeClient,
        config: &ReportConfig,
        state: &mut ThrottleState,
        logs: impl Iterator<Item = CapturedLog>,
    ) {
        for captured in logs {
            let now = Instant::now();
            match state.window_start {
                Some(start) if now.duration_since(start) < config.rate_window => {}
                _ => {
                    if state.dropped_in_window > 0 {
                        tracing::debug!(
                            dropped = state.dropped_in_window,
                            "Zbierak dropped error log events in the last rate window"
                        );
                    }
                    state.window_start = Some(now);
                    state.sent_in_window = 0;
                    state.dropped_in_window = 0;
                }
            }
            if state.sent_in_window >= config.max_events_per_window {
                state.dropped_in_window += 1;
                continue;
            }
            if state
                .last_sent
                .get(&captured.message)
                .is_some_and(|sent| now.duration_since(*sent) < config.duplicate_suppression)
            {
                continue;
            }
            let message = truncate_utf8(&captured.message, config.max_message_bytes).to_owned();
            let mut event = Event {
                message: message.clone(),
                severity: severity_for(captured.level),
                error: Some(ErrorInfo {
                    type_name: "log".into(),
                    value: Some(message),
                    stack_frames: captured.frames,
                }),
                ..Event::default()
            };
            event.tags.insert("target".into(), captured.target);
            match client.capture_event(event) {
                Ok(_) => {
                    state.sent_in_window += 1;
                    if state.last_sent.len() >= config.max_tracked_messages {
                        state.last_sent.clear();
                    }
                    state.last_sent.insert(captured.message, now);
                }
                Err(queue_error) => {
                    tracing::debug!("Zbierak failed to queue log event: {queue_error}");
                }
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use bevy_app::App;
    use bevy_log::BoxedLayer;
    use zbierak_protocol::{Breadcrumb, Event, Severity};

    #[cfg(feature = "async")]
    use crate::AsyncClient;
    #[cfg(feature = "blocking")]
    use crate::Client;
    use crate::{CaptureError, InitError, ReportConfig};

    /// Inert stub: `wasm32` builds cannot construct a client, so game code
    /// cfg-gates client construction and this type is never inhabited.
    #[derive(Clone)]
    pub enum RuntimeClient {}

    impl RuntimeClient {
        /// Stub: never called, the type cannot be constructed.
        ///
        /// # Errors
        ///
        /// Never returns successfully.
        pub fn capture_message(
            &self,
            _message: impl Into<String>,
            _severity: Severity,
        ) -> Result<String, CaptureError> {
            Err(CaptureError::SenderStopped)
        }

        /// Stub: never called, the type cannot be constructed.
        ///
        /// # Errors
        ///
        /// Never returns successfully.
        pub fn capture_event(&self, _event: Event) -> Result<String, CaptureError> {
            Err(CaptureError::SenderStopped)
        }

        /// Stub: never called, the type cannot be constructed.
        ///
        /// # Errors
        ///
        /// Never returns successfully.
        pub fn capture_error<E: std::error::Error + 'static>(
            &self,
            _error: &E,
            _severity: Severity,
        ) -> Result<String, CaptureError> {
            Err(CaptureError::SenderStopped)
        }

        /// Stub: never called, the type cannot be constructed.
        pub fn add_breadcrumb(&self, _breadcrumb: Breadcrumb) {}

        /// Stub: never called, the type cannot be constructed.
        pub fn install_panic_hook(&self) {}
    }

    #[cfg(feature = "blocking")]
    impl From<Client> for RuntimeClient {
        fn from(_client: Client) -> Self {
            unreachable!("RuntimeClient is uninhabited on wasm32")
        }
    }

    #[cfg(feature = "async")]
    impl From<AsyncClient> for RuntimeClient {
        fn from(_client: AsyncClient) -> Self {
            unreachable!("RuntimeClient is uninhabited on wasm32")
        }
    }

    /// Stub: always fails with [`InitError::UnsupportedTarget`].
    ///
    /// # Errors
    ///
    /// Always returns [`InitError::UnsupportedTarget`].
    pub fn init(_client: impl Into<RuntimeClient>, _config: ReportConfig) -> Result<(), InitError> {
        Err(InitError::UnsupportedTarget)
    }

    /// Stub: reporting is never initialized on this target.
    #[must_use]
    pub fn client() -> Option<&'static RuntimeClient> {
        None
    }

    /// Stub: no-op on this target.
    pub fn capture_message(_message: impl Into<String>, _severity: Severity) {}

    /// Stub: never installs a capture layer on this target.
    pub fn log_capture_layer(_app: &mut App) -> Option<BoxedLayer> {
        None
    }

    /// Stub: registers nothing on this target.
    #[derive(Default)]
    pub struct ZbierakPlugin;

    impl bevy_app::Plugin for ZbierakPlugin {
        fn build(&self, _app: &mut App) {}
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use native::{RuntimeClient, ZbierakPlugin, capture_message, client, init, log_capture_layer};

#[cfg(target_arch = "wasm32")]
pub use wasm::{RuntimeClient, ZbierakPlugin, capture_message, client, init, log_capture_layer};

#[cfg(all(test, not(target_arch = "wasm32"), feature = "blocking"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use tracing::Level;
    use tracing_subscriber::layer::SubscriberExt;
    use zbierak_protocol::{Severity, StackFrame};

    use super::{ReportConfig, native, severity_for, truncate_utf8};
    use crate::Client;

    /// Builds a client pointed at an unreachable endpoint; capture only queues.
    fn test_client() -> Client {
        let directory = tempfile::tempdir().unwrap();
        Client::builder("http://127.0.0.1:1/events")
            .spool(directory.path(), 1024 * 1024)
            .request_timeout(Duration::from_millis(20))
            .build()
            .unwrap()
    }

    #[test]
    fn truncate_utf8_respects_char_boundaries() {
        assert_eq!(truncate_utf8("hello", 10), "hello");
        assert_eq!(truncate_utf8("hello", 4), "hell");
        let multi = "a\u{1F600}b";
        assert_eq!(truncate_utf8(multi, 3), "a");
        assert_eq!(truncate_utf8(multi, 5), "a\u{1F600}");
    }

    #[test]
    fn severity_maps_to_protocol_values() {
        assert_eq!(severity_for(Level::ERROR), Severity::Error);
        assert_eq!(severity_for(Level::WARN), Severity::Warning);
        assert_eq!(severity_for(Level::INFO), Severity::Info);
        assert_eq!(severity_for(Level::DEBUG), Severity::Debug);
        assert_eq!(severity_for(Level::TRACE), Severity::Debug);
    }

    #[test]
    fn config_defaults_match_a_low_noise_setup() {
        let config = ReportConfig::default();
        assert_eq!(config.capture_level, Level::ERROR);
        assert_eq!(config.rate_window, Duration::from_secs(60));
        assert_eq!(config.max_events_per_window, 20);
        assert_eq!(config.duplicate_suppression, Duration::from_secs(60));
        assert_eq!(config.max_tracked_messages, 1024);
        assert_eq!(config.max_message_bytes, 4096);
        assert_eq!(config.excluded_targets, vec!["zbierak".to_string()]);
        assert!(config.capture_stack_frames);
    }

    #[test]
    fn rate_limit_drops_events_past_the_window_cap() {
        let client = test_client().into();
        let config = ReportConfig::default().max_events_per_window(2);
        let mut state = native::ThrottleState::default();
        native::process_captured(&client, &config, &mut state, test_logs(5));
        assert_eq!(state.sent_in_window, 2);
        assert_eq!(state.dropped_in_window, 3);
    }

    #[test]
    fn duplicate_messages_are_suppressed_within_the_window() {
        let client = test_client().into();
        let config = ReportConfig::default();
        let mut state = native::ThrottleState::default();
        let logs = std::iter::repeat_with(|| native::CapturedLog {
            message: "same failure".into(),
            target: "game::system".into(),
            level: Level::ERROR,
            frames: Vec::new(),
        })
        .take(3);
        native::process_captured(&client, &config, &mut state, logs);
        assert_eq!(state.sent_in_window, 1);
    }

    #[test]
    fn excluded_targets_are_not_captured_by_the_layer() {
        let config = ReportConfig::default();
        let (sender, receiver) = mpsc::channel();
        let layer = native::LogCaptureLayer {
            sender,
            capture_level: config.capture_level,
            excluded_targets: config.excluded_targets.clone(),
            capture_stack_frames: false,
        };
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(target: "zbierak_sdk::bevy", "self report");
            tracing::error!(target: "game::combat", "real failure");
            tracing::warn!(target: "game::combat", "below threshold");
        });
        let captured: Vec<String> = receiver.try_iter().map(|log| log.message).collect();
        assert_eq!(captured, vec!["real failure".to_string()]);
    }

    #[test]
    fn layer_captures_call_site_stack_frames() {
        let (sender, receiver) = mpsc::channel();
        let layer = native::LogCaptureLayer {
            sender,
            capture_level: Level::ERROR,
            excluded_targets: Vec::new(),
            capture_stack_frames: true,
        };
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(target: "game::combat", "traced failure");
        });
        let captured: Vec<native::CapturedLog> = receiver.try_iter().collect();
        assert_eq!(captured.len(), 1);
        let frames = &captured[0].frames;
        assert!(!frames.is_empty(), "call-site frames must be captured");
        for frame in frames {
            let function = frame.function.as_deref().unwrap_or_default();
            assert!(
                !function.starts_with("tracing"),
                "dispatch machinery must be filtered: {function}"
            );
        }
    }

    #[test]
    fn layer_frame_capture_can_be_disabled() {
        let (sender, receiver) = mpsc::channel();
        let layer = native::LogCaptureLayer {
            sender,
            capture_level: Level::ERROR,
            excluded_targets: Vec::new(),
            capture_stack_frames: false,
        };
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(target: "game::combat", "untraced failure");
        });
        let captured: Vec<native::CapturedLog> = receiver.try_iter().collect();
        assert_eq!(captured.len(), 1);
        assert!(
            captured[0].frames.is_empty(),
            "disabled capture must not collect frames"
        );
    }

    #[test]
    fn process_captured_attaches_frames_to_the_error_info() {
        let directory = tempfile::tempdir().unwrap();
        let client = Client::builder("http://127.0.0.1:1/events")
            .spool(directory.path(), 1024 * 1024)
            .request_timeout(Duration::from_millis(20))
            .build()
            .unwrap();
        let config = ReportConfig::default();
        let mut state = native::ThrottleState::default();
        let logs = std::iter::once(native::CapturedLog {
            message: "spooled with frames".into(),
            target: "game::system".into(),
            level: Level::ERROR,
            frames: vec![StackFrame {
                function: Some("game::system::tick".into()),
                filename: Some("src/game.rs".into()),
                line: Some(42),
                ..StackFrame::default()
            }],
        });
        let runtime_client: native::RuntimeClient = client.clone().into();
        native::process_captured(&runtime_client, &config, &mut state, logs);
        let _ = client.flush(Duration::from_secs(2));
        let spooled = read_spooled_events(directory.path());
        assert_eq!(spooled.len(), 1);
        let error = spooled[0]
            .get("error")
            .expect("log events carry error info")
            .get("stack_frames")
            .and_then(serde_json::Value::as_array)
            .expect("frames attached to the error info");
        assert_eq!(error.len(), 1);
        assert_eq!(
            error[0].get("function").and_then(serde_json::Value::as_str),
            Some("game::system::tick")
        );
    }

    #[test]
    fn capture_level_threshold_forwards_warnings_when_raised() {
        let (sender, receiver) = mpsc::channel();
        let layer = native::LogCaptureLayer {
            sender,
            capture_level: Level::WARN,
            excluded_targets: Vec::new(),
            capture_stack_frames: false,
        };
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(target: "game::combat", "degraded");
        });
        let captured: Vec<native::CapturedLog> = receiver.try_iter().collect();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].level, Level::WARN);
    }

    #[test]
    fn panic_hook_messages_are_not_double_captured() {
        let (sender, receiver) = mpsc::channel();
        let layer = native::LogCaptureLayer {
            sender,
            capture_level: Level::ERROR,
            excluded_targets: Vec::new(),
            capture_stack_frames: false,
        };
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!("panic at src/main.rs:1:1: boom");
            tracing::error!("ordinary failure");
        });
        let captured: Vec<String> = receiver.try_iter().map(|log| log.message).collect();
        assert_eq!(captured, vec!["ordinary failure".to_string()]);
    }

    fn test_logs(count: usize) -> impl Iterator<Item = native::CapturedLog> {
        (0..count).map(|index| native::CapturedLog {
            message: format!("failure {index}"),
            target: "game::system".into(),
            level: Level::ERROR,
            frames: Vec::new(),
        })
    }

    /// Deserializes every spooled event payload in `directory`.
    fn read_spooled_events(directory: &std::path::Path) -> Vec<serde_json::Value> {
        let mut events = Vec::new();
        for entry in std::fs::read_dir(directory).expect("spool dir readable") {
            let path = entry.expect("entry readable").path();
            if path.extension().is_none_or(|extension| extension != "json") {
                continue;
            }
            let bytes = std::fs::read(&path).expect("spool file readable");
            events.push(serde_json::from_slice(&bytes).expect("spooled event parses"));
        }
        events
    }

    #[test]
    fn headless_app_reports_errors_through_the_pipeline() {
        let directory = tempfile::tempdir().unwrap();
        let client = Client::builder("http://127.0.0.1:1/events")
            .spool(directory.path(), 1024 * 1024)
            .request_timeout(Duration::from_millis(20))
            .build()
            .unwrap();
        super::init(client.clone(), ReportConfig::default()).unwrap();

        let mut app = bevy_app::App::new();
        app.add_plugins(bevy_log::LogPlugin {
            custom_layer: super::log_capture_layer,
            ..Default::default()
        })
        .add_plugins(super::ZbierakPlugin);
        tracing::error!(target: "game::combat", "headless pipeline failure");
        app.update();
        // Delivery to the unreachable endpoint fails, so the captured event
        // ends up in the spool; flush forces the worker to finish the queue.
        let report = client.flush(Duration::from_secs(2)).unwrap();
        assert_eq!(report.remaining, 1, "captured log event must be spooled");
        let spooled = read_spooled_events(directory.path());
        assert_eq!(spooled.len(), 1);
        let error = spooled[0].get("error").expect("error info present");
        let frames = error
            .get("stack_frames")
            .and_then(serde_json::Value::as_array)
            .expect("log events capture call-site stack frames by default");
        assert!(!frames.is_empty(), "frames must survive the whole pipeline");
    }
}
