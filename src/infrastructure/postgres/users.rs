use super::{
    PgAuthRepository,
    common::{insert_audit, revoke_all_tx, update_password_tx},
    db_error,
    rows::{USER_SELECT, UserRow},
    unique_violation,
};
use crate::{
    application::{AuthError, NewUserAccount, UserStore},
    domain::UserRecord,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::time::Duration;
use uuid::Uuid;

#[async_trait]
impl UserStore for PgAuthRepository {
    async fn create_user(&self, account: NewUserAccount) -> Result<UserRecord, AuthError> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let user_id = insert_user(&mut tx, &account).await?;
        sqlx::query(
            r"
INSERT INTO email_verification_tokens(user_id, token_hash, expires_at)
VALUES ($1, $2, now() + ($3::double precision * interval '1 second'))
",
        )
        .bind(user_id)
        .bind(&account.verification_hash)
        .bind(account.verification_ttl.as_secs_f64())
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        insert_audit(&mut tx, "user_registered", Some(user_id), None, Value::Null).await?;
        tx.commit().await.map_err(db_error)?;
        self.get_user(user_id).await?.ok_or(AuthError::UserNotFound)
    }

    async fn get_user(&self, user_id: Uuid) -> Result<Option<UserRecord>, AuthError> {
        let sql = format!("{USER_SELECT} WHERE id = $1 AND deleted_at IS NULL");
        sqlx::query_as::<_, UserRow>(&sql)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map(|value| value.map(UserRecord::from))
            .map_err(db_error)
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<UserRecord>, AuthError> {
        let sql =
            format!("{USER_SELECT} WHERE normalized_email = $1::citext AND deleted_at IS NULL");
        sqlx::query_as::<_, UserRow>(&sql)
            .bind(email)
            .fetch_optional(&self.pool)
            .await
            .map(|value| value.map(UserRecord::from))
            .map_err(db_error)
    }

    async fn record_failed_login(
        &self,
        user_id: Uuid,
        threshold: i32,
        lockout_duration: Duration,
    ) -> Result<Option<DateTime<Utc>>, AuthError> {
        sqlx::query_scalar(
            r"
UPDATE users
SET failed_login_count = failed_login_count + 1,
    locked_until = CASE
        WHEN failed_login_count + 1 >= $2
        THEN now() + ($3::double precision * interval '1 second')
        ELSE locked_until
    END
WHERE id = $1
RETURNING locked_until
",
        )
        .bind(user_id)
        .bind(threshold.max(1))
        .bind(lockout_duration.as_secs_f64())
        .fetch_one(&self.pool)
        .await
        .map_err(db_error)
    }

    async fn record_login_success(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query(
            r"
UPDATE users
SET failed_login_count = 0, locked_until = NULL, last_login_at = now()
WHERE id = $1
",
        )
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn update_password(&self, user_id: Uuid, password_hash: &str) -> Result<(), AuthError> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        update_password_tx(&mut tx, user_id, password_hash).await?;
        revoke_all_tx(&mut tx, user_id, "password_changed").await?;
        insert_audit(
            &mut tx,
            "password_changed",
            Some(user_id),
            None,
            Value::Null,
        )
        .await?;
        tx.commit().await.map_err(db_error)
    }
}

async fn insert_user(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account: &NewUserAccount,
) -> Result<Uuid, AuthError> {
    let result = sqlx::query_scalar::<_, Uuid>(
        r"
INSERT INTO users(normalized_email, display_name, password_hash, locale, timezone)
VALUES ($1, $2, $3, $4, $5)
RETURNING id
",
    )
    .bind(&account.email)
    .bind(&account.display_name)
    .bind(&account.password_hash)
    .bind(&account.locale)
    .bind(&account.timezone)
    .fetch_one(&mut **tx)
    .await;
    match result {
        Ok(value) => Ok(value),
        Err(error) if unique_violation(&error) => Err(AuthError::EmailAlreadyExists),
        Err(error) => Err(db_error(error)),
    }
}
