use serde_json::Value;
use sqlx::SqlitePool;

use crate::AppResult;

/// Appends an operator- or security-relevant action to the audit log.
///
/// Audit entries are best-effort diagnostics for privileged actions; they are
/// never user-facing. Failures bubble up as database errors so callers do not
/// silently skip bookkeeping.
pub async fn record(
    db: &SqlitePool,
    user_id: Option<i64>,
    action: &str,
    target_type: Option<&str>,
    target_id: Option<String>,
    details: Value,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO audit_log (user_id, action, target_type, target_id, details_json)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(details.to_string())
    .execute(db)
    .await?;
    Ok(())
}
