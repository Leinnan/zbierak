use std::{env, net::SocketAddr, path::PathBuf};

use crate::{AppError, AppResult};

#[derive(Debug)]
pub struct Config {
    pub bind: SocketAddr,
    pub database_url: String,
    pub cookie_secure: bool,
    pub session_days: i64,
    pub static_dir: PathBuf,
    pub template_dir: PathBuf,
}

impl Config {
    pub fn from_env() -> AppResult<Self> {
        let bind = preferred_env("ZBIERAK_LISTEN_ADDR", "ZBIERAK_BIND")
            .unwrap_or_else(|| "127.0.0.1:3000".into())
            .parse()
            .map_err(|e| AppError::Config(format!("invalid ZBIERAK_LISTEN_ADDR: {e}")))?;
        let database_url = preferred_env("ZBIERAK_DATABASE_URL", "DATABASE_URL")
            .unwrap_or_else(|| "sqlite://data/zbierak.db".into());
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
        Ok(Self {
            bind,
            database_url,
            cookie_secure,
            session_days,
            static_dir: env::var("ZBIERAK_STATIC_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| asset_dir("static")),
            template_dir: env::var("ZBIERAK_TEMPLATE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| asset_dir("templates")),
        })
    }
}

fn preferred_env(primary: &str, legacy: &str) -> Option<String> {
    env::var(primary).ok().or_else(|| env::var(legacy).ok())
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
