use super::{
    PgAuthRepository,
    common::{insert_audit, revoke_all_tx, update_password_tx},
    db_error,
};
use crate::{
    application::{AuthError, RecoveryStore, UserStore},
    domain::UserRecord,
};
use async_trait::async_trait;
use serde_json::Value;
use std::time::Duration;
use uuid::Uuid;

#[async_trait]
impl RecoveryStore for PgAuthRepository {
    async fn consume_verification_token(&self, token_hash: &[u8]) -> Result<Uuid, AuthError> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let user_id = sqlx::query_scalar::<_, Uuid>(
            r"
UPDATE email_verification_tokens
SET consumed_at = now()
WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now()
RETURNING user_id
",
        )
        .bind(token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?
        .ok_or(AuthError::InvalidVerificationToken)?;
        activate_user(&mut tx, user_id).await?;
        insert_audit(&mut tx, "email_verified", Some(user_id), None, Value::Null).await?;
        tx.commit().await.map_err(db_error)?;
        Ok(user_id)
    }

    async fn create_password_reset(
        &self,
        email: &str,
        token_hash: &[u8],
        ttl: Duration,
    ) -> Result<Option<UserRecord>, AuthError> {
        let Some(user) = self.find_user_by_email(email).await? else {
            return Ok(None);
        };
        sqlx::query(
            r"
INSERT INTO password_reset_tokens(user_id, token_hash, expires_at)
VALUES ($1, $2, now() + ($3::double precision * interval '1 second'))
",
        )
        .bind(user.id)
        .bind(token_hash)
        .bind(ttl.as_secs_f64())
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(Some(user))
    }

    async fn consume_password_reset(
        &self,
        token_hash: &[u8],
        password_hash: &str,
    ) -> Result<Uuid, AuthError> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let user_id = consume_reset_token(&mut tx, token_hash).await?;
        update_password_tx(&mut tx, user_id, password_hash).await?;
        revoke_all_tx(&mut tx, user_id, "password_reset").await?;
        insert_audit(&mut tx, "password_reset", Some(user_id), None, Value::Null).await?;
        tx.commit().await.map_err(db_error)?;
        Ok(user_id)
    }
}

async fn activate_user(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> Result<(), AuthError> {
    sqlx::query(
        r"
UPDATE users
SET status = 'active', email_verified_at = COALESCE(email_verified_at, now())
WHERE id = $1 AND deleted_at IS NULL
",
    )
    .bind(user_id)
    .execute(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(())
}

async fn consume_reset_token(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    token_hash: &[u8],
) -> Result<Uuid, AuthError> {
    sqlx::query_scalar::<_, Uuid>(
        r"
UPDATE password_reset_tokens
SET consumed_at = now()
WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now()
RETURNING user_id
",
    )
    .bind(token_hash)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?
    .ok_or(AuthError::InvalidResetToken)
}
