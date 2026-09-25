use std::{
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use url::Url;

use crate::{AppError, AppResult};

/// Where a class of runtime assets (templates, static files) is loaded from.
///
/// Assets are embedded in the binary by default; a filesystem directory is
/// only used when the matching environment variable names an existing one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetSource {
    /// Assets embedded in the binary at build time.
    Embedded,
    /// A filesystem directory overriding the embedded assets.
    Directory(PathBuf),
}

/// Runtime configuration, loaded from the environment by [`Config::from_env`].
#[derive(Debug)]
pub struct Config {
    /// Address the HTTP server binds to (`ZBIERAK_LISTEN_ADDR`).
    pub bind: SocketAddr,
    /// SQLite connection URL (`ZBIERAK_DATABASE_URL`).
    pub database_url: String,
    /// Whether cookies are marked `Secure` (`ZBIERAK_COOKIE_SECURE`).
    pub cookie_secure: bool,
    /// Session lifetime in days (`ZBIERAK_SESSION_DAYS`, 1-365).
    pub session_days: i64,
    /// Where static assets are loaded from (`ZBIERAK_STATIC_DIR`).
    pub static_dir: AssetSource,
    /// Where Tera templates are loaded from (`ZBIERAK_TEMPLATE_DIR`).
    pub template_dir: AssetSource,
    /// Master key encrypting webhook signing secrets at rest.
    pub webhook_key: Option<[u8; 32]>,
    /// Public base URL used to build issue links in notifications
    /// (`ZBIERAK_PUBLIC_URL`).
    pub public_url: Option<Url>,
}

impl AssetSource {
    /// Short human-readable description safe for startup logs.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Embedded => "embedded".into(),
            Self::Directory(path) => format!("directory {}", path.display()),
        }
    }
}

impl Config {
    /// Loads the configuration from environment variables, applying
    /// defaults for anything unset.
    ///
    /// # Errors
    ///
    /// Returns an error when a variable has an unparseable value, the
    /// session lifetime is out of range, the database URL is not a SQLite
    /// URL, or the secret key does not decode to 32 bytes.
    pub fn from_env() -> AppResult<Self> {
        let bind = preferred_env("ZBIERAK_LISTEN_ADDR", "ZBIERAK_BIND")
            .unwrap_or_else(|| "127.0.0.1:3000".into())
            .parse()
            .map_err(|e| AppError::Config(format!("invalid ZBIERAK_LISTEN_ADDR: {e}")))?;
        let database_url = match preferred_env("ZBIERAK_DATABASE_URL", "DATABASE_URL") {
            Some(url) => normalize_database_url(url),
            None => default_database_url(),
        };
        if !database_url.starts_with("sqlite:") {
            return Err(AppError::Config(
                "ZBIERAK_DATABASE_URL must be a SQLite URL".into(),
            ));
        }
        let cookie_secure = parse_bool("ZBIERAK_COOKIE_SECURE", false)?;
        let session_days = env::var("ZBIERAK_SESSION_DAYS")
            .unwrap_or_else(|_| "30".into())
            .parse::<i64>()
            .map_err(|e| AppError::Config(format!("invalid ZBIERAK_SESSION_DAYS: {e}")))?;
        if !(1..=365).contains(&session_days) {
            return Err(AppError::Config(
                "ZBIERAK_SESSION_DAYS must be between 1 and 365".into(),
            ));
        }
        let webhook_key = match env::var("ZBIERAK_SECRET_KEY") {
            Ok(raw) => Some(crate::secrets::parse_key(&raw)?),
            Err(env::VarError::NotPresent) => None,
            Err(error) => {
                return Err(AppError::Config(format!(
                    "invalid ZBIERAK_SECRET_KEY: {error}"
                )));
            }
        };
        let public_url = match env::var("ZBIERAK_PUBLIC_URL") {
            Ok(raw) => parse_public_url(Some(raw))?,
            Err(env::VarError::NotPresent) => None,
            Err(error) => {
                return Err(AppError::Config(format!(
                    "invalid ZBIERAK_PUBLIC_URL: {error}"
                )));
            }
        };
        Ok(Self {
            bind,
            database_url,
            cookie_secure,
            session_days,
            static_dir: resolve_asset_dir("ZBIERAK_STATIC_DIR"),
            template_dir: resolve_asset_dir("ZBIERAK_TEMPLATE_DIR"),
            webhook_key,
            public_url,
        })
    }

    /// One-line, secret-free description of the effective configuration for
    /// startup logs. Never include `webhook_key` material.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "version {}, listen {}, database {}, cookie_secure {}, session_days {}, templates: {}, static: {}, webhook_key: {}, public_url: {}",
            env!("CARGO_PKG_VERSION"),
            self.bind,
            self.database_url,
            self.cookie_secure,
            self.session_days,
            self.template_dir.describe(),
            self.static_dir.describe(),
            if self.webhook_key.is_some() {
                "present"
            } else {
                "absent"
            },
            self.public_url
                .as_ref()
                .map_or_else(|| "unset".to_string(), ToString::to_string)
        )
    }
}

fn preferred_env(primary: &str, legacy: &str) -> Option<String> {
    env::var(primary).ok().or_else(|| env::var(legacy).ok())
}

/// Parses `ZBIERAK_PUBLIC_URL`: an optional absolute `http`/`https` base URL
/// used to link issues in outgoing notifications.
fn parse_public_url(value: Option<String>) -> AppResult<Option<Url>> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let url = Url::parse(&raw)
        .map_err(|error| AppError::Config(format!("invalid ZBIERAK_PUBLIC_URL: {error}")))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(AppError::Config(
            "ZBIERAK_PUBLIC_URL must be an absolute http(s) URL".into(),
        ));
    }
    Ok(Some(url))
}

fn default_database_url() -> String {
    if Path::new("/data").is_dir() {
        "sqlite:///data/zbierak.db?mode=rwc".into()
    } else {
        "sqlite://data/zbierak.db".into()
    }
}

fn normalize_database_url(url: String) -> String {
    normalize_database_url_for(url, Path::new("/data").is_dir())
}

fn normalize_database_url_for(url: String, data_dir_present: bool) -> String {
    // The container .env points SQLite at the /data volume. Source runs on hosts
    // without that directory (for example macOS, whose root filesystem is
    // read-only) must not fail trying to create it, so fall back to ./data.
    match url.strip_prefix("sqlite:///data/") {
        Some(rest) if !data_dir_present => format!("sqlite://data/{rest}"),
        _ => url,
    }
}

/// Resolves an asset source: the configured directory when the variable names
/// an existing one, embedded assets otherwise. A set-but-invalid variable is
/// reported loudly (warning with the ignored path) instead of being silently
/// dropped, but it no longer prevents startup.
fn resolve_asset_dir(variable: &str) -> AssetSource {
    match env::var(variable) {
        Ok(value) => asset_source_for(variable, &value),
        Err(_) => AssetSource::Embedded,
    }
}

fn asset_source_for(variable: &str, value: &str) -> AssetSource {
    if Path::new(value).is_dir() {
        AssetSource::Directory(PathBuf::from(value))
    } else {
        tracing::warn!(
            variable,
            path = %value,
            "environment variable names a missing directory; falling back to embedded assets"
        );
        AssetSource::Embedded
    }
}

fn parse_bool(name: &str, default: bool) -> AppResult<bool> {
    match env::var(name) {
        Ok(value) => match value.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" => Ok(true),
            "0" | "false" | "no" => Ok(false),
            _ => Err(AppError::Config(format!("{name} must be true or false"))),
        },
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(AppError::Config(format!("invalid {name}: {error}"))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    use std::net::SocketAddr;

    use super::{
        AssetSource, Config, asset_source_for, normalize_database_url_for, parse_public_url,
    };

    #[test]
    fn container_data_url_falls_back_without_data_dir() {
        assert_eq!(
            normalize_database_url_for("sqlite:///data/zbierak.db?mode=rwc".into(), false),
            "sqlite://data/zbierak.db?mode=rwc"
        );
    }

    #[test]
    fn container_data_url_is_kept_when_data_dir_exists() {
        assert_eq!(
            normalize_database_url_for("sqlite:///data/zbierak.db?mode=rwc".into(), true),
            "sqlite:///data/zbierak.db?mode=rwc"
        );
    }

    #[test]
    fn unrelated_database_urls_are_unchanged() {
        for url in [
            "sqlite::memory:",
            "sqlite://data/zbierak.db",
            "sqlite:///tmp/zbierak.db",
        ] {
            assert_eq!(normalize_database_url_for(url.into(), false), url);
        }
    }

    #[test]
    fn valid_directory_override_is_used() {
        let directory = tempfile::tempdir().unwrap();
        assert_eq!(
            asset_source_for("ZBIERAK_TEST_DIR", directory.path().to_str().unwrap()),
            AssetSource::Directory(directory.path().to_path_buf())
        );
    }

    #[test]
    fn missing_directory_override_falls_back_to_embedded() {
        assert_eq!(
            asset_source_for("ZBIERAK_TEST_DIR", "/no/such/dir/zbierak"),
            AssetSource::Embedded
        );
    }

    fn sample_config(webhook_key: Option<[u8; 32]>) -> Config {
        Config {
            bind: "127.0.0.1:3000".parse::<SocketAddr>().unwrap(),
            database_url: "sqlite://data/zbierak.db".into(),
            cookie_secure: true,
            session_days: 30,
            static_dir: AssetSource::Embedded,
            template_dir: AssetSource::Embedded,
            webhook_key,
            public_url: None,
        }
    }

    #[test]
    fn summary_names_every_relevant_setting() {
        let summary = sample_config(None).summary();
        for needle in [
            "127.0.0.1:3000",
            "sqlite://data/zbierak.db",
            "cookie_secure true",
            "session_days 30",
            "templates: embedded",
            "static: embedded",
            "webhook_key: absent",
            "public_url: unset",
        ] {
            assert!(
                summary.contains(needle),
                "summary missing {needle}: {summary}"
            );
        }
    }

    #[test]
    fn summary_never_contains_key_material() {
        let mut key = [7_u8; 32];
        key[0] = 0xAB;
        let config = sample_config(Some(key));
        let summary = config.summary();
        assert!(summary.contains("webhook_key: present"));
        assert!(!summary.contains("171"));
        assert!(!summary.contains(&format!("{key:?}")));
    }

    #[test]
    fn asset_source_describe_renders_both_variants() {
        assert_eq!(AssetSource::Embedded.describe(), "embedded");
        assert_eq!(
            AssetSource::Directory(std::path::PathBuf::from("/app/static")).describe(),
            "directory /app/static"
        );
    }

    #[test]
    fn public_url_is_absent_when_unset() {
        assert_eq!(parse_public_url(None).unwrap(), None);
    }

    #[test]
    fn public_url_accepts_absolute_http_urls() {
        for raw in [
            "https://errors.example.com",
            "https://errors.example.com/",
            "http://localhost:3000",
            "https://example.com/zbierak/",
        ] {
            let parsed = parse_public_url(Some(raw.into())).unwrap();
            assert!(parsed.is_some(), "{raw} should parse");
            assert!(
                matches!(parsed.as_ref().unwrap().scheme(), "http" | "https"),
                "{raw} should keep an http(s) scheme"
            );
        }
    }

    #[test]
    fn public_url_rejects_unusable_values() {
        for raw in ["not a url", "ftp://example.com", "mailto:ops@example.com"] {
            assert!(parse_public_url(Some(raw.into())).is_err(), "{raw}");
        }
    }
}
