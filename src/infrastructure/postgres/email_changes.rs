use super::{
    PgAuthRepository, db_error,
    rows::{USER_SELECT, UserRow},
    unique_violation,
};
use crate::{
    application::{AuthError, EmailChangeStore, UserStore},
    domain::UserRecord,
};
use async_trait::async_trait;
use std::time::Duration;
use uuid::Uuid;

#[async_trait]
impl EmailChangeStore for PgAuthRepository {
    async fn create_email_change(
        &self,
        user_id: Uuid,
        new_email: &str,
        token_hash: &[u8],
        ttl: Duration,
    ) -> Result<(), AuthError> {
        if self.find_user_by_email(new_email).await?.is_some() {
            return Err(AuthError::EmailAlreadyExists);
        }
        sqlx::query(
            r"INSERT INTO email_change_tokens(user_id, new_email, token_hash, expires_at)
VALUES ($1, $2, $3, now() + ($4::double precision * interval '1 second'))",
        )
        .bind(user_id)
        .bind(new_email)
        .bind(token_hash)
        .bind(ttl.as_secs_f64())
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn consume_email_change(&self, token_hash: &[u8]) -> Result<UserRecord, AuthError> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let token = consume_token(&mut tx, token_hash).await?;
        let sql = format!(
            r"UPDATE users
SET normalized_email = $2, email_verified_at = now(), version = version + 1
WHERE id = $1 AND deleted_at IS NULL
RETURNING {}",
            USER_SELECT
                .trim_start_matches("\nSELECT ")
                .trim_end_matches("\nFROM users\n")
        );
        let result = sqlx::query_as::<_, UserRow>(&sql)
            .bind(token.user_id)
            .bind(token.new_email)
            .fetch_one(&mut *tx)
            .await;
        let row = match result {
            Ok(row) => row,
            Err(error) if unique_violation(&error) => return Err(AuthError::EmailAlreadyExists),
            Err(error) => return Err(db_error(error)),
        };
        tx.commit().await.map_err(db_error)?;
        Ok(row.into())
    }
}

struct EmailChangeToken {
    user_id: Uuid,
    new_email: String,
}

async fn consume_token(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    token_hash: &[u8],
) -> Result<EmailChangeToken, AuthError> {
    let value = sqlx::query_as::<_, (Uuid, String)>(
        r"UPDATE email_change_tokens
SET consumed_at = now()
WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now()
RETURNING user_id, new_email::text",
    )
    .bind(token_hash)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?
    .ok_or(AuthError::InvalidEmailChangeToken)?;
    Ok(EmailChangeToken {
        user_id: value.0,
        new_email: value.1,
    })
}
