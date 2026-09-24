use std::{
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use crate::{AppError, AppResult};

#[derive(Debug)]
pub struct Config {
    pub bind: SocketAddr,
    pub database_url: String,
    pub cookie_secure: bool,
    pub session_days: i64,
    pub static_dir: PathBuf,
    pub template_dir: PathBuf,
    /// Master key encrypting webhook signing secrets at rest.
    pub webhook_key: Option<[u8; 32]>,
}

impl Config {
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
        Ok(Self {
            bind,
            database_url,
            cookie_secure,
            session_days,
            static_dir: resolve_asset_dir("ZBIERAK_STATIC_DIR", "static"),
            template_dir: resolve_asset_dir("ZBIERAK_TEMPLATE_DIR", "templates"),
            webhook_key,
        })
    }
}

fn preferred_env(primary: &str, legacy: &str) -> Option<String> {
    env::var(primary).ok().or_else(|| env::var(legacy).ok())
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

fn resolve_asset_dir(variable: &str, name: &str) -> PathBuf {
    if let Ok(value) = env::var(variable) {
        let path = PathBuf::from(value);
        if path.is_dir() {
            return path;
        }
    }
    asset_dir(name)
}

fn asset_dir(name: &str) -> PathBuf {
    let deployed = PathBuf::from(name);
    if deployed.is_dir() {
        deployed
    } else {
        PathBuf::from("src").join(name)
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
mod tests {
    use super::normalize_database_url_for;

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
}
