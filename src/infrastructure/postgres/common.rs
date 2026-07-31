use super::db_error;
use crate::application::AuthError;
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub async fn insert_audit(
    tx: &mut Transaction<'_, Postgres>,
    event_type: &str,
    user_id: Option<Uuid>,
    session_id: Option<Uuid>,
    metadata: Value,
) -> Result<(), AuthError> {
    sqlx::query(
        "INSERT INTO auth_audit_events(event_type, user_id, session_id, metadata) VALUES ($1, $2, $3, $4)",
    )
    .bind(event_type)
    .bind(user_id)
    .bind(session_id)
    .bind(metadata)
    .execute(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(())
}

pub async fn revoke_all_tx(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    reason: &str,
) -> Result<(), AuthError> {
    sqlx::query(
        r"
UPDATE user_sessions
SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = COALESCE(revoke_reason, $2)
WHERE user_id = $1 AND revoked_at IS NULL
",
    )
    .bind(user_id)
    .bind(reason)
    .execute(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(())
}

pub async fn update_password_tx(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    password_hash: &str,
) -> Result<(), AuthError> {
    sqlx::query(
        r"
UPDATE users
SET password_hash = $2, password_changed_at = now(), failed_login_count = 0, locked_until = NULL
WHERE id = $1 AND deleted_at IS NULL
",
    )
    .bind(user_id)
    .bind(password_hash)
    .execute(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(())
}
