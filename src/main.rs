//! Zbierak server binary: runs the operator UI and the versioned ingestion
//! API until shut down.
//!
//! Startup failures print the error plus every underlying cause, so a
//! `journalctl -u zbierak` entry is enough to locate a misconfiguration.

use std::error::Error;

#[tokio::main]
async fn main() {
    install_panic_hook();
    zbierak::init_logging();
    if let Err(error) = zbierak::run().await {
        report_fatal(&error);
        std::process::exit(1);
    }
}

/// Prints the error and every underlying cause on its own line.
///
/// `Display` alone shows only the outermost message: a database error that
/// wraps an IO failure, or a migration error that wraps a SQL failure, would
/// otherwise hide the decisive detail (permission denied, readonly file
/// system, and so on). Stderr is used directly because journald captures it
/// even if the tracing subscriber could not be initialized.
fn report_fatal(error: &zbierak::AppError) {
    eprintln!("zbierak failed to start: {error}");
    let mut source = Error::source(error);
    while let Some(cause) = source {
        eprintln!("  caused by: {cause}");
        source = cause.source();
    }
}

/// Replaces the default panic hook with a single clear stderr line.
///
/// Panics inside spawned tasks (for example the outbox worker) do not abort
/// the process; without a hook they would vanish silently. Panics are denied
/// in production code, so this only guards against unexpected breakage.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|panic| {
        let location = panic.location().map_or_else(
            || "unknown location".to_string(),
            |location| {
                format!(
                    "{}:{}:{}",
                    location.file(),
                    location.line(),
                    location.column()
                )
            },
        );
        let message = panic
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| panic.payload().downcast_ref::<String>().map(String::as_str))
            .unwrap_or("opaque panic payload");
        eprintln!("zbierak panicked at {location}: {message}");
    }));
}
