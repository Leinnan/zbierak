//! Runtime assets embedded into the binary at build time.
//!
//! The operator-UI templates and static files ship inside the executable, so
//! a deployment only needs the binary itself; missing asset directories can
//! no longer prevent startup. The `ZBIERAK_TEMPLATE_DIR` and
//! `ZBIERAK_STATIC_DIR` environment variables remain available as optional
//! filesystem overrides for development and theming.

use include_dir::{Dir, DirEntry, File, include_dir};

/// Operator-UI Tera templates, embedded from `src/templates`.
pub static TEMPLATES: Dir = include_dir!("$CARGO_MANIFEST_DIR/src/templates");

/// Static assets served under `/static`, embedded from `src/static`.
pub static STATIC: Dir = include_dir!("$CARGO_MANIFEST_DIR/src/static");

/// Every `.html` template in [`TEMPLATES`] as `(name, source)` pairs.
///
/// Names match what `Tera::load_from_glob` produced historically: paths
/// relative to the template root, for example `base.html` and
/// `fragments/flash.html`.
pub fn html_templates() -> impl Iterator<Item = (&'static str, &'static str)> {
    let mut templates = Vec::new();
    collect_html_templates(&TEMPLATES, &mut templates);
    templates.into_iter()
}

/// `Dir::files()` only walks the top level, so subdirectories such as
/// `fragments/` are collected manually.
fn collect_html_templates<'d>(directory: &'d Dir<'d>, templates: &mut Vec<(&'d str, &'d str)>) {
    for entry in directory.entries() {
        match entry {
            DirEntry::Dir(subdirectory) => collect_html_templates(subdirectory, templates),
            DirEntry::File(file) => {
                if file.path().extension().is_some_and(|ext| ext == "html")
                    && let (Some(name), Some(source)) = (file.path().to_str(), file.contents_utf8())
                {
                    templates.push((name, source));
                }
            }
        }
    }
}

/// Looks up an embedded static asset by its slash-separated path.
///
/// Returns `None` when no file exists at that path; traversal components are
/// rejected by the caller before reaching this lookup.
#[must_use]
pub fn static_file(path: &str) -> Option<&'static [u8]> {
    STATIC.get_file(path).map(File::contents)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{TEMPLATES, html_templates, static_file};

    #[test]
    fn embedded_templates_cover_every_required_name() {
        for name in [
            "base.html",
            "login.html",
            "bootstrap.html",
            "projects.html",
            "project.html",
            "issue.html",
            "settings.html",
            "users.html",
            "user.html",
            "user_settings.html",
            "error.html",
        ] {
            assert!(
                TEMPLATES.get_file(name).is_some(),
                "required template {name} is not embedded"
            );
        }
    }

    #[test]
    fn html_templates_expose_relative_names() {
        let names: Vec<&str> = html_templates().map(|(name, _)| name).collect();
        assert!(names.contains(&"base.html"));
        assert!(names.contains(&"fragments/flash.html"));
        assert!(names.iter().all(|name| !name.starts_with('/')));
    }

    #[test]
    fn static_lookup_serves_known_assets() {
        assert!(static_file("app.css").is_some());
        assert!(static_file("vendor/tabler/tabler.min.css").is_some());
        assert!(static_file("no/such/asset.css").is_none());
    }
}
