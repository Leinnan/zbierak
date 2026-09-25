use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit, Mac};
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
    tracing::debug!("outbox worker started");
    loop {
        if *shutdown.borrow() {
            break;
        }
        match claim(&state).await {
            Ok(Some(delivery)) => deliver(&state, delivery).await,
            Ok(None) => {
                tokio::select! {
                    () = tokio::time::sleep(Duration::from_secs(2)) => {},
                    _ = shutdown.changed() => {},
                }
            }
            Err(error) => {
                tracing::error!(%error, "outbox worker failed");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
    tracing::debug!("outbox worker stopped");
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
            fail(state, delivery.id, delivery.attempts, error).await;
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
                fail(state, delivery.id, delivery.attempts, error).await;
                return;
            }
        };
        // HMAC construction is infallible for any key length; this is the
        // one deliberate, documented panic exception in production code.
        #[allow(clippy::expect_used)]
        let mut mac = Hmac::<Sha256>::new_from_slice(signing_secret.as_bytes())
            .expect("HMAC accepts any key");
        mac.update(delivery.payload_json.as_bytes());
        request = request.header(
            "x-zbierak-signature",
            format!("sha256={}", STANDARD.encode(mac.finalize().into_bytes())),
        );
    }
    // The payload is moved into the request; only the delivery id and retry
    // count are needed if delivery fails.
    let Delivery {
        id,
        attempts,
        payload_json,
        ..
    } = delivery;
    let result = request.body(payload_json).send().await;
    match result {
        Ok(response) if response.status().is_success() => {
            if let Err(error) =
                sqlx::query("UPDATE outbox SET delivered_at=unixepoch(), locked_at=NULL WHERE id=?")
                    .bind(id)
                    .execute(&state.db)
                    .await
            {
                tracing::error!(%error, id, "could not complete outbox delivery");
            }
        }
        Ok(response) => fail(state, id, attempts, format!("HTTP {}", response.status())).await,
        Err(error) => fail(state, id, attempts, error.to_string()).await,
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
    let builder = addresses
        .into_iter()
        .fold(
            reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none()),
            |builder, address| builder.resolve(&host, address),
        )
        .build()
        .map_err(|error| format!("HTTP client build failed: {error}"))?;
    Ok(builder)
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

async fn fail(state: &AppState, delivery_id: i64, attempts: i64, error: String) {
    let capped = truncate_utf8(&error, 1000);
    let delay = retry_delay(attempts);
    if let Err(db_error) = sqlx::query(
        "UPDATE outbox SET locked_at=NULL, available_at=unixepoch()+?, last_error=? WHERE id=?",
    )
    .bind(delay)
    .bind(capped)
    .bind(delivery_id)
    .execute(&state.db)
    .await
    {
        tracing::error!(%db_error, id=delivery_id, "could not reschedule outbox delivery");
    }
}

/// Truncates to at most `max_bytes` without panicking on a multibyte
/// character: the cut always lands on a valid UTF-8 boundary.
fn truncate_utf8(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn retry_delay(attempts: i64) -> i64 {
    if attempts >= 12 {
        86_400
    } else {
        // The guard above bounds attempts below 12, so the conversion is
        // total for every input that reaches the shift.
        let shift = u32::try_from(attempts.clamp(0, 11)).unwrap_or(0);
        (5_i64 * 2_i64.pow(shift)).min(3600)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    use super::{retry_delay, truncate_utf8};

    #[test]
    fn truncation_stays_on_utf8_boundaries() {
        assert_eq!(truncate_utf8("short", 10), "short");
        let owned = "x".repeat(1000);
        let cut = truncate_utf8(&owned, 1000);
        assert_eq!(cut.len(), 1000);
        assert_eq!(cut, owned);
        let over = "x".repeat(1001);
        let cut = truncate_utf8(&over, 1000);
        assert_eq!(cut.len(), 1000);

        // Multibyte characters crossing the byte-1000 boundary are dropped
        // whole instead of panicking.
        let multibyte = "e\u{301}".repeat(600); // 2 bytes each
        let cut = truncate_utf8(multibyte.as_str(), 1000);
        assert!(cut.len() <= 1000);
        assert!(multibyte.starts_with(cut));
        assert!(cut.chars().all(|c| c == 'e' || c == '\u{301}'));
        let emoji = "\u{1F600}".repeat(600); // 4 bytes each
        let cut = truncate_utf8(emoji.as_str(), 1000);
        assert_eq!(cut.len() % 4, 0);
        assert!(emoji.starts_with(cut));
    }

    #[test]
    fn retry_delays_grow_and_cap() {
        assert_eq!(retry_delay(0), 5);
        assert_eq!(retry_delay(1), 10);
        assert_eq!(retry_delay(9), 2560);
        assert_eq!(retry_delay(10), 3600, "delays cap at one hour");
        assert_eq!(retry_delay(12), 86_400);
        assert_eq!(retry_delay(50), 86_400);
        assert_eq!(retry_delay(-3), 5, "negative attempts are clamped");
    }
}
