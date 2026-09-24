use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::FromRow;
use tokio::sync::watch;
use url::Url;

use crate::{AppResult, AppState, net_policy};

#[derive(FromRow)]
struct Delivery {
    id: i64,
    payload_json: String,
    attempts: i64,
    kind: String,
    url: String,
    secret: Option<String>,
    secret_encrypted: i64,
}

pub async fn run(state: AppState, mut shutdown: watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() {
            break;
        }
        match claim(&state).await {
            Ok(Some(delivery)) => deliver(&state, delivery).await,
            Ok(None) => {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(2)) => {},
                    _ = shutdown.changed() => {},
                }
            }
            Err(error) => {
                tracing::error!(%error, "outbox worker failed");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

async fn claim(state: &AppState) -> AppResult<Option<Delivery>> {
    let row = sqlx::query_as::<_, Delivery>(
        "UPDATE outbox SET locked_at=unixepoch(), attempts=attempts+1
         WHERE id=(SELECT id FROM outbox WHERE delivered_at IS NULL AND available_at<=unixepoch()
           AND (locked_at IS NULL OR locked_at<unixepoch()-60) ORDER BY id LIMIT 1)
        RETURNING id, payload_json, attempts,
          (SELECT kind FROM notification_endpoints WHERE id=endpoint_id) AS kind,
          (SELECT url FROM notification_endpoints WHERE id=endpoint_id) AS url,
          (SELECT secret FROM notification_endpoints WHERE id=endpoint_id) AS secret,
          (SELECT secret_encrypted FROM notification_endpoints WHERE id=endpoint_id)
            AS secret_encrypted",
    )
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

async fn deliver(state: &AppState, delivery: Delivery) {
    // Each delivery gets its own client pinned to freshly resolved public
    // addresses, so neither loopback/private networks nor DNS rebinding can
    // redirect a webhook to internal services. Redirects are never followed.
    let client = match pinned_client(state, &delivery.url).await {
        Ok(client) => client,
        Err(error) => {
            fail(state, &delivery, error).await;
            return;
        }
    };
    let mut request = client
        .post(&delivery.url)
        .header("content-type", "application/json");
    if delivery.kind == "webhook"
        && let Some(stored) = &delivery.secret
    {
        let signing_secret = match signing_secret(state, delivery.secret_encrypted, stored) {
            Ok(secret) => secret,
            Err(error) => {
                fail(state, &delivery, error).await;
                return;
            }
        };
        let mut mac = Hmac::<Sha256>::new_from_slice(signing_secret.as_bytes())
            .expect("HMAC accepts any key");
        mac.update(delivery.payload_json.as_bytes());
        request = request.header(
            "x-zbierak-signature",
            format!("sha256={}", STANDARD.encode(mac.finalize().into_bytes())),
        );
    }
    let result = request.body(delivery.payload_json.clone()).send().await;
    match result {
        Ok(response) if response.status().is_success() => {
            if let Err(error) =
                sqlx::query("UPDATE outbox SET delivered_at=unixepoch(), locked_at=NULL WHERE id=?")
                    .bind(delivery.id)
                    .execute(&state.db)
                    .await
            {
                tracing::error!(%error, id=delivery.id, "could not complete outbox delivery");
            }
        }
        Ok(response) => fail(state, &delivery, format!("HTTP {}", response.status())).await,
        Err(error) => fail(state, &delivery, error.to_string()).await,
    }
}
async fn pinned_client(state: &AppState, raw_url: &str) -> Result<reqwest::Client, String> {
    let url = Url::parse(raw_url).map_err(|error| format!("invalid destination URL: {error}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("destination must be HTTP or HTTPS".into());
    }
    let host = url
        .host_str()
        .ok_or_else(|| "destination URL has no host".to_owned())?
        .to_owned();
    let default_port = if url.scheme() == "https" { 443 } else { 80 };
    let addresses = net_policy::resolve_allowed_with(
        &host,
        url.port_or_known_default().unwrap_or(default_port),
        |host, port| state.resolver.resolve(host, port),
    )
    .await
    .map_err(|error| error.to_string())?;
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none());
    for address in addresses {
        builder = builder.resolve(&host, address);
    }
    builder
        .build()
        .map_err(|error| format!("HTTP client build failed: {error}"))
}

/// Resolves the plaintext signing secret, decrypting sealed rows. Legacy
/// plaintext rows keep working with a warning so upgrades stay non-breaking.
fn signing_secret(state: &AppState, secret_encrypted: i64, stored: &str) -> Result<String, String> {
    if secret_encrypted == 0 {
        tracing::warn!(
            "endpoint stores its signing secret in plaintext; re-create it to encrypt at rest"
        );
        return Ok(stored.to_owned());
    }
    let key = state.config.webhook_key.ok_or_else(|| {
        "ZBIERAK_SECRET_KEY is not configured but an encrypted secret exists".to_owned()
    })?;
    crate::secrets::decrypt(&key, stored).map_err(|error| error.to_string())
}

async fn fail(state: &AppState, delivery: &Delivery, error: String) {
    let capped = if error.len() > 1000 {
        &error[..1000]
    } else {
        &error
    };
    let delay = retry_delay(delivery.attempts);
    if let Err(db_error) = sqlx::query(
        "UPDATE outbox SET locked_at=NULL, available_at=unixepoch()+?, last_error=? WHERE id=?",
    )
    .bind(delay)
    .bind(capped)
    .bind(delivery.id)
    .execute(&state.db)
    .await
    {
        tracing::error!(%db_error, id=delivery.id, "could not reschedule outbox delivery");
    }
}

fn retry_delay(attempts: i64) -> i64 {
    if attempts >= 12 {
        86_400
    } else {
        (5_i64 * 2_i64.pow(attempts.max(0) as u32)).min(3600)
    }
}
