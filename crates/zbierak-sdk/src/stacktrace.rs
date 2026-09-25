//! Stack frame capture built on the `backtrace` crate.
//!
//! All functions degrade to empty results when symbol information is
//! unavailable (stripped release builds), so callers never need to branch.

use backtrace::BacktraceSymbol;
use zbierak_protocol::StackFrame;

/// Maximum number of frames reported for one event.
pub(crate) const MAX_FRAMES: usize = 128;

/// Upper bound for one string field inside a frame, mirroring the protocol's
/// ingestion limit so captured frames always validate instead of silently
/// dropping the whole event.
const MAX_FRAME_FIELD_BYTES: usize = 1_024;

/// Captures the current call stack, oldest first, capped at [`MAX_FRAMES`].
///
/// Frames belonging to the panic machinery and to this SDK are removed so the
/// first reported frame is the application call site. Field values are
/// truncated to [`MAX_FRAME_FIELD_BYTES`] so a single verbose symbol cannot
/// invalidate the event.
pub(crate) fn capture_frames() -> Vec<StackFrame> {
    let backtrace = backtrace::Backtrace::new();
    let mut frames: Vec<StackFrame> = backtrace
        .frames()
        .iter()
        .flat_map(backtrace::BacktraceFrame::symbols)
        .filter_map(symbol_frame)
        .collect();
    // The panic runtime sits above `rust_begin_unwind`; dropping through the
    // last occurrence makes the panicking call site the first frame.
    if let Some(start) = frames
        .iter()
        .rposition(|frame| frame.function.as_deref() == Some("rust_begin_unwind"))
    {
        frames.drain(..=start);
    }
    frames.retain(|frame| !frame.function.as_deref().is_some_and(is_internal_frame));
    frames.truncate(MAX_FRAMES);
    for frame in &mut frames {
        truncate_frame_fields(frame);
    }
    frames
}

/// Trims a frame field to [`MAX_FRAME_FIELD_BYTES`] without splitting a UTF-8
/// code point.
fn truncate_frame_fields(frame: &mut StackFrame) {
    for field in [&mut frame.function, &mut frame.filename, &mut frame.module] {
        if let Some(text) = field.as_mut()
            && text.len() > MAX_FRAME_FIELD_BYTES
        {
            let mut end = MAX_FRAME_FIELD_BYTES;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
        }
    }
}

/// True for frames that belong to the Rust runtime, this SDK, the
/// stack-capture machinery, or the `tracing` dispatch stack rather than
/// application code. Matched on demangled paths to stay independent of
/// optimization-level-dependent inlining.
fn is_internal_frame(function: &str) -> bool {
    // v0-mangled generics demangle with leading `<...>`; look past them so
    // `<backtrace[hash]::capture::Backtrace>::new` is still recognized.
    let function = function.trim_start_matches('<');
    function.starts_with("zbierak_sdk")
        || function.starts_with("std::panicking")
        || function.starts_with("core::panicking")
        // Capture machinery unwound through while collecting IPs. The
        // bracketed form is the v0-mangled `backtrace[hash]::` demangling.
        || function.starts_with("backtrace")
        || function.starts_with("gimli")
        || function.starts_with("addr2line")
        // Scoped to avoid swallowing unrelated crates like `object_store`.
        || function.starts_with("object[")
        || function.starts_with("object::")
        // The macro-to-layer dispatch path above the `error!`/`panic!` call
        // site. The `::` keeps lookalike crates such as `tracing_appender`
        // visible, and the bracketed form covers v0-mangled names like
        // `tracing_core[hash]::dispatcher::get_default`.
        || function.starts_with("tracing::")
        || function.starts_with("tracing[")
        || function.starts_with("tracing_core::")
        || function.starts_with("tracing_core[")
        || function.starts_with("tracing_subscriber::")
        || function.starts_with("tracing_subscriber[")
        || function.starts_with("alloc::boxed::Box<")
}

/// Converts one resolved symbol into a protocol frame.
fn symbol_frame(symbol: &BacktraceSymbol) -> Option<StackFrame> {
    let function = symbol.name().map(|name| name.to_string());
    let filename = symbol
        .filename()
        .and_then(std::path::Path::to_str)
        .map(str::to_owned);
    // Frames with neither a name nor a file carry no browsable information.
    if function.is_none() && filename.is_none() {
        return None;
    }
    Some(StackFrame {
        function,
        in_app: filename.as_deref().map(classify_in_app),
        filename,
        line: symbol.lineno(),
        column: symbol.colno(),
        module: None,
    })
}

/// Classifies a source path as application code (`true`) or toolchain and
/// registry code (`false`). Unresolvable paths return `None` at the caller.
fn classify_in_app(filename: &str) -> bool {
    !(filename.contains("library/std")
        || filename.contains("library/core")
        || filename.contains("library/alloc")
        || filename.contains("library\\std")
        || filename.contains("library\\core")
        || filename.contains("library\\alloc")
        || filename.contains("/rustc/")
        || filename.contains("\\rustc\\")
        || filename.contains("/.cargo/registry/")
        || filename.contains("\\.cargo\\registry\\"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use zbierak_protocol::StackFrame;

    use super::{classify_in_app, is_internal_frame, truncate_frame_fields};

    #[test]
    fn toolchain_and_registry_paths_are_not_in_app() {
        for path in [
            "/rustc/90743e7298aca107d625/lib/std/src/panicking.rs",
            "/Users/dev/.cargo/registry/src/index.crates.io-.../serde-1.0.0/src/de.rs",
            "/rust/library/std/src/panic.rs",
            r"C:\Users\dev\.rustup\toolchains\stable\lib\rustlib\src\rust\library\core\src\panicking.rs",
        ] {
            assert!(
                !classify_in_app(path),
                "system path classified in-app: {path}"
            );
        }
    }

    #[test]
    fn application_paths_are_in_app() {
        for path in [
            "src/main.rs",
            "/home/dev/app/src/server.rs",
            "/Users/dev/project/crates/store/src/lib.rs",
        ] {
            assert!(classify_in_app(path), "app path classified system: {path}");
        }
    }

    #[test]
    fn runtime_and_sdk_frames_are_filtered() {
        for name in [
            "zbierak_sdk::stacktrace::capture_frames",
            "std::panicking::begin_panic_handler",
            "core::panicking::panic_fmt",
            "<alloc::boxed::Box<F,A> as FnOnce<()>>::call_once",
        ] {
            assert!(is_internal_frame(name), "not filtered: {name}");
        }
        assert!(!is_internal_frame("store::checkout::charge"));
    }

    #[test]
    fn symbolizer_machinery_frames_are_filtered() {
        for name in [
            "backtrace[38f1211cc00854]::backtrace::trace::<<Backtrace as Foo>::Bar>::{closure#0}",
            "<backtrace[38f1211cc00854]::capture::Backtrace>::new",
            "backtrace::capture::Backtrace::create",
            "gimli[38f1211cc00854]::read::eval::Evaluation::run",
            "addr2line::context::FrameIter::next",
            "object[38f1211cc00854]::read::elf::file::ElfFile::parse",
            "object::read::macho::MachOFile::parse",
        ] {
            assert!(is_internal_frame(name), "not filtered: {name}");
        }
        // Names that merely share a prefix with the machinery stay visible.
        assert!(!is_internal_frame("backend::app::route"));
        assert!(!is_internal_frame("object_store::tree::walk"));
    }

    #[test]
    fn tracing_dispatch_frames_are_filtered() {
        for name in [
            "tracing::error!",
            "tracing::level_filters::LevelFilter::current",
            "tracing_core::dispatcher::get_default",
            "tracing_core[9347222e4ed66466]::dispatcher::get_default::<(), ()>",
            "tracing_subscriber::layer::SubscriberExt::with",
            "tracing_subscriber[9347222e4ed66466]::registry::Layered::on_event",
            "<tracing_subscriber::registry::Layers>::on_event",
        ] {
            assert!(is_internal_frame(name), "not filtered: {name}");
        }
        // Lookalike crates that share a prefix but not the `::` stay visible.
        assert!(!is_internal_frame("tracing_appender::rolling::worker"));
        assert!(!is_internal_frame(
            "tracing_appender[9347]::rolling::worker"
        ));
        assert!(!is_internal_frame("game::tracing::instrument"));
    }

    #[test]
    fn oversized_frame_fields_are_truncated_to_the_protocol_limit() {
        let mut frame = StackFrame {
            function: Some(format!("game::tick::{}", "x".repeat(2_048))),
            filename: Some(format!("src/{}", "a".repeat(2_000))),
            module: Some("m".repeat(1_025)),
            ..StackFrame::default()
        };
        truncate_frame_fields(&mut frame);
        assert_eq!(frame.function.as_deref().map(str::len), Some(1_024));
        assert_eq!(frame.filename.as_deref().map(str::len), Some(1_024));
        assert_eq!(frame.module.as_deref().map(str::len), Some(1_024));
        // Multi-byte characters are never split.
        let mut frame = StackFrame {
            function: Some("\u{1F600}".repeat(800)),
            ..StackFrame::default()
        };
        truncate_frame_fields(&mut frame);
        let function = frame.function.expect("truncation keeps the value");
        assert!(function.len() <= 1_024);
        assert!(function.is_char_boundary(function.len()));
    }
}
