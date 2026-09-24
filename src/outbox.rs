use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use reqwest::StatusCode;
use sha2::Sha256;
use sqlx::FromRow;
use tokio::sync::watch;

use crate::{AppResult, AppState};

#[derive(FromRow)]
struct Delivery {
    id: i64,
    payload_json: String,
    attempts: i64,
    kind: String,
    url: String,
    secret: Option<String>,
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
           (SELECT secret FROM notification_endpoints WHERE id=endpoint_id) AS secret",
    )
    .fetch_optional(&state.db)
    .await?;
    Ok(row)
}

async fn deliver(state: &AppState, delivery: Delivery) {
    let mut request = state
        .http
        .post(&delivery.url)
        .header("content-type", "application/json");
    if delivery.kind == "webhook"
        && let Some(secret) = &delivery.secret
    {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key");
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

#[allow(dead_code)]
fn _status_is_retryable(status: StatusCode) -> bool {
    status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS
}
