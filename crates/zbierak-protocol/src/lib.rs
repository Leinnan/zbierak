//! Versioned wire models for sending events to Zbierak.
//!
//! The types intentionally use strings for identifiers and timestamps. This keeps the
//! protocol independent of a particular UUID or time crate while retaining a stable JSON
//! representation.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[cfg(feature = "schema")]
use utoipa::ToSchema;

/// The newest event schema understood by this crate.
pub const PROTOCOL_VERSION: u16 = 1;

/// A complete event accepted by the ingestion API.
#[cfg_attr(feature = "schema", derive(ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// Wire schema version.
    #[serde(default = "protocol_version")]
    pub version: u16,
    /// Producer-assigned stable identifier. SDKs should preserve it across retries.
    pub event_id: String,
    /// UTC timestamp in RFC 3339 form.
    pub timestamp: String,
    /// Human-readable event summary.
    pub message: String,
    /// Structured error information, when the event represents an error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorInfo>,
    /// Event severity.
    #[serde(default)]
    pub severity: Severity,
    /// Application release or build identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release: Option<String>,
    /// Deployment environment, such as `production`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    /// Runtime or operating-system platform.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// Stack frames when no more specific error object owns them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stack_frames: Vec<StackFrame>,
    /// Recent application activity ordered from oldest to newest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub breadcrumbs: Vec<Breadcrumb>,
    /// Flat indexed metadata.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tags: BTreeMap<String, String>,
    /// Arbitrary structured diagnostic context.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub contexts: BTreeMap<String, Value>,
    /// User associated with the event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<User>,
    /// Explicit grouping components. When absent, the server chooses a fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<Vec<String>>,
}

impl Event {
    /// Creates an event with practical defaults and caller-provided identity and time.
    pub fn new(
        event_id: impl Into<String>,
        timestamp: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            event_id: event_id.into(),
            timestamp: timestamp.into(),
            message: message.into(),
            ..Self::default()
        }
    }

    /// Validates protocol invariants and ingestion limits.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ValidationError::new(
                "version",
                format!("unsupported protocol version {}", self.version),
            ));
        }
        validate_required("event_id", &self.event_id, 128)?;
        validate_required("timestamp", &self.timestamp, 64)?;
        validate_timestamp("timestamp", &self.timestamp)?;
        validate_required("message", &self.message, 16_384)?;
        if self.tags.len() > 100 {
            return Err(ValidationError::new(
                "tags",
                "must contain at most 100 entries",
            ));
        }
        for (key, value) in &self.tags {
            validate_required("tags.key", key, 128)?;
            validate_optional("tags.value", value, 1_024)?;
        }
        if self.contexts.len() > 50 {
            return Err(ValidationError::new(
                "contexts",
                "must contain at most 50 entries",
            ));
        }
        if self.breadcrumbs.len() > 1_000 {
            return Err(ValidationError::new(
                "breadcrumbs",
                "must contain at most 1000 entries",
            ));
        }
        if let Some(parts) = &self.fingerprint {
            if parts.is_empty() || parts.len() > 10 {
                return Err(ValidationError::new(
                    "fingerprint",
                    "must contain between 1 and 10 components",
                ));
            }
            for part in parts {
                validate_required("fingerprint", part, 1_024)?;
            }
        }
        Ok(())
    }
}

impl Default for Event {
    fn default() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            event_id: String::new(),
            timestamp: String::new(),
            message: String::new(),
            error: None,
            severity: Severity::Error,
            release: None,
            environment: None,
            platform: None,
            stack_frames: Vec::new(),
            breadcrumbs: Vec::new(),
            tags: BTreeMap::new(),
            contexts: BTreeMap::new(),
            user: None,
            fingerprint: None,
        }
    }
}

/// Structured error details.
#[cfg_attr(feature = "schema", derive(ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorInfo {
    /// Language or application error type, such as `std::io::Error`.
    #[serde(rename = "type")]
    pub type_name: String,
    /// Error value or description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Error-specific stack frames.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stack_frames: Vec<StackFrame>,
}

/// Severity used for events and breadcrumbs.
#[cfg_attr(feature = "schema", derive(ToSchema))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Detailed diagnostic information.
    Debug,
    /// Informational activity.
    Info,
    /// A potentially harmful condition.
    Warning,
    /// An operation failed.
    #[default]
    Error,
    /// The process or a major subsystem cannot continue.
    Fatal,
}

/// A single call-site in a stack trace.
#[cfg_attr(feature = "schema", derive(ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackFrame {
    /// Source file name or path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// Fully qualified function name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// One-based source line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// One-based source column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    /// Module, package, or crate name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// Whether this frame belongs to application code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_app: Option<bool>,
}

/// A point-in-time diagnostic trail entry.
#[cfg_attr(feature = "schema", derive(ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Breadcrumb {
    /// UTC timestamp in RFC 3339 form.
    pub timestamp: String,
    /// Human-readable activity description.
    pub message: String,
    /// Breadcrumb severity.
    #[serde(default = "default_breadcrumb_severity")]
    pub severity: Severity,
    /// Logical category, usually a tracing target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Additional structured values.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data: BTreeMap<String, Value>,
}

impl Breadcrumb {
    /// Creates an informational breadcrumb.
    pub fn new(timestamp: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            timestamp: timestamp.into(),
            message: message.into(),
            severity: Severity::Info,
            category: None,
            data: BTreeMap::new(),
        }
    }
}

/// User identity and optional profile data.
#[cfg_attr(feature = "schema", derive(ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct User {
    /// Stable application user identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Email address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Display or login name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Network address, if collection is permitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    /// Additional user attributes.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub data: BTreeMap<String, Value>,
}

/// Successful ingestion response.
#[cfg_attr(feature = "schema", derive(ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestResponse {
    /// Accepted event identifier.
    pub event_id: String,
    /// Whether this was a newly accepted event or an idempotent duplicate.
    pub status: IngestStatus,
}

/// Ingestion disposition.
#[cfg_attr(feature = "schema", derive(ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngestStatus {
    /// The event was accepted for processing.
    Accepted,
    /// The identifier had already been accepted.
    Duplicate,
}

/// Machine-readable API error body.
#[cfg_attr(feature = "schema", derive(ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    /// Stable machine-readable error code.
    pub code: String,
    /// Human-readable error explanation.
    pub message: String,
    /// Field that caused the error, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

/// A failed protocol validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationError {
    field: &'static str,
    message: String,
}

impl ValidationError {
    fn new(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            field,
            message: message.into(),
        }
    }

    /// Returns the invalid field path.
    pub fn field(&self) -> &'static str {
        self.field
    }

    /// Returns the validation explanation without its field prefix.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for ValidationError {}

const fn protocol_version() -> u16 {
    PROTOCOL_VERSION
}

const fn default_breadcrumb_severity() -> Severity {
    Severity::Info
}

fn validate_required(field: &'static str, value: &str, max: usize) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        return Err(ValidationError::new(field, "must not be empty"));
    }
    validate_optional(field, value, max)
}

fn validate_optional(field: &'static str, value: &str, max: usize) -> Result<(), ValidationError> {
    if value.len() > max {
        return Err(ValidationError::new(
            field,
            format!("must be at most {max} bytes"),
        ));
    }
    Ok(())
}

/// Parsed timestamps must be RFC 3339 and land within a sane operational window
/// (year 2000 through 2100) so clock malfunctions cannot poison stored data.
const MIN_TIMESTAMP_YEAR: i32 = 2000;
const MAX_TIMESTAMP_YEAR: i32 = 2100;

pub fn validate_timestamp(field: &'static str, value: &str) -> Result<(), ValidationError> {
    let parsed = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| {
        ValidationError::new(
            field,
            "must be an RFC 3339 timestamp such as 2026-09-24T12:00:00Z",
        )
    })?;
    let year = parsed.year();
    if !(MIN_TIMESTAMP_YEAR..=MAX_TIMESTAMP_YEAR).contains(&year) {
        return Err(ValidationError::new(
            field,
            format!("must fall between years {MIN_TIMESTAMP_YEAR} and {MAX_TIMESTAMP_YEAR}"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_event() -> Event {
        Event::new(
            "018f4c7c-0000-7000-8000-000000000001",
            "2026-09-24T12:00:00Z",
            "database unavailable",
        )
    }

    #[test]
    fn defaults_are_practical_and_valid_after_required_fields() {
        let event = valid_event();
        assert_eq!(event.version, PROTOCOL_VERSION);
        assert_eq!(event.severity, Severity::Error);
        assert!(event.validate().is_ok());
    }

    #[test]
    fn json_round_trip_preserves_structured_payload() {
        let mut event = valid_event();
        event.tags.insert("region".into(), "eu-central".into());
        event.error = Some(ErrorInfo {
            type_name: "io::Error".into(),
            value: Some("connection refused".into()),
            stack_frames: vec![StackFrame {
                filename: Some("src/db.rs".into()),
                line: Some(42),
                ..StackFrame::default()
            }],
        });

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"io::Error\""));
        assert_eq!(serde_json::from_str::<Event>(&json).unwrap(), event);
    }

    #[test]
    fn validation_reports_the_relevant_field() {
        let mut event = valid_event();
        event.fingerprint = Some(Vec::new());
        let error = event.validate().unwrap_err();
        assert_eq!(error.field(), "fingerprint");

        event.fingerprint = None;
        event.message.clear();
        assert_eq!(event.validate().unwrap_err().field(), "message");
    }

    #[test]
    fn older_payloads_receive_additive_defaults() {
        let event: Event = serde_json::from_str(
            r#"{"event_id":"id","timestamp":"2026-09-24T12:00:00Z","message":"oops"}"#,
        )
        .unwrap();
        assert_eq!(event.version, PROTOCOL_VERSION);
        assert_eq!(event.severity, Severity::Error);
        assert!(event.tags.is_empty());
    }

    #[test]
    fn timestamps_accept_rfc3339_variants() {
        for stamp in [
            "2026-09-24T12:00:00Z",
            "2026-09-24T12:00:00+02:00",
            "2026-09-24T12:00:00.123456789-05:30",
            "2026-01-01T00:00:00z",
        ] {
            let mut event = valid_event();
            event.timestamp = stamp.into();
            assert!(event.validate().is_ok(), "rejected valid {stamp}");
        }
    }

    #[test]
    fn timestamps_reject_non_rfc3339_and_implausible_dates() {
        for stamp in [
            "",
            "not a timestamp",
            "2026-09-24 12:00:00",
            "2026-13-40T25:99:99Z",
            "2101-01-01T00:00:00Z",
            "1999-12-31T23:59:59Z",
        ] {
            let mut event = valid_event();
            event.timestamp = stamp.into();
            let error = event.validate().unwrap_err();
            assert_eq!(error.field(), "timestamp", "wrong field for {stamp}");
        }
    }
}
