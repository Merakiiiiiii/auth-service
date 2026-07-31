use super::{
    PgAuthRepository,
    common::insert_audit,
    db_error,
    rows::{SESSION_SELECT, SessionRow},
    session_queries::{
        SessionInsert, context_from_session, get_session_pool, get_session_tx, get_user_tx,
        insert_session_pool, insert_session_tx, lock_refresh_session, revoke_rotated_session,
    },
};
use crate::{
    application::{AuthError, LoginContext, SessionStore},
    domain::{SessionRecord, UserRecord},
};
use async_trait::async_trait;
use serde_json::Value;
use std::time::Duration;
use uuid::Uuid;

#[async_trait]
impl SessionStore for PgAuthRepository {
    async fn create_session(
        &self,
        user_id: Uuid,
        refresh_hash: &[u8],
        context: &LoginContext,
        refresh_ttl: Duration,
    ) -> Result<SessionRecord, AuthError> {
        let session_id = Uuid::new_v4();
        let insert = SessionInsert {
            session_id,
            family_id: Uuid::new_v4(),
            user_id,
            refresh_hash: refresh_hash.to_vec(),
            context: context.clone(),
            ttl: refresh_ttl,
        };
        insert_session_pool(&self.pool, &insert).await?;
        get_session_pool(&self.pool, session_id)
            .await?
            .ok_or(AuthError::SessionNotFound)
    }

    async fn rotate_session(
        &self,
        old_refresh_hash: &[u8],
        new_refresh_hash: &[u8],
        refresh_ttl: Duration,
    ) -> Result<(SessionRecord, UserRecord), AuthError> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let old = lock_refresh_session(&mut tx, old_refresh_hash).await?;
        revoke_rotated_session(&mut tx, old.id).await?;
        let new_id = Uuid::new_v4();
        let context = context_from_session(&old);
        let insert = SessionInsert {
            session_id: new_id,
            family_id: old.token_family_id,
            user_id: old.user_id,
            refresh_hash: new_refresh_hash.to_vec(),
            context,
            ttl: refresh_ttl,
        };
        insert_session_tx(&mut tx, &insert).await?;
        let session = get_session_tx(&mut tx, new_id)
            .await?
            .ok_or(AuthError::SessionNotFound)?;
        let user = get_user_tx(&mut tx, old.user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        insert_audit(
            &mut tx,
            "session_refreshed",
            Some(user.id),
            Some(new_id),
            Value::Null,
        )
        .await?;
        tx.commit().await.map_err(db_error)?;
        Ok((session, user))
    }

    async fn revoke_refresh_token(&self, refresh_hash: &[u8]) -> Result<(), AuthError> {
        sqlx::query(
            r"
UPDATE user_sessions
SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = COALESCE(revoke_reason, 'logout')
WHERE refresh_token_hash = $1
",
        )
        .bind(refresh_hash)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn revoke_all_sessions(&self, user_id: Uuid, reason: &str) -> Result<(), AuthError> {
        sqlx::query(
            r"
UPDATE user_sessions
SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = COALESCE(revoke_reason, $2)
WHERE user_id = $1 AND revoked_at IS NULL
",
        )
        .bind(user_id)
        .bind(reason)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn session_is_active(&self, session_id: Uuid) -> Result<bool, AuthError> {
        sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM user_sessions WHERE id = $1 AND revoked_at IS NULL AND expires_at > now())",
        )
        .bind(session_id)
        .fetch_one(&self.pool)
        .await
        .map_err(db_error)
    }

    async fn get_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
    ) -> Result<Option<SessionRecord>, AuthError> {
        let sql = format!("{SESSION_SELECT} WHERE id = $1 AND user_id = $2");
        sqlx::query_as::<_, SessionRow>(&sql)
            .bind(session_id)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map(|row| row.map(SessionRecord::from))
            .map_err(db_error)
    }

    async fn list_sessions(&self, user_id: Uuid) -> Result<Vec<SessionRecord>, AuthError> {
        let sql = format!("{SESSION_SELECT} WHERE user_id = $1 ORDER BY created_at DESC");
        sqlx::query_as::<_, SessionRow>(&sql)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map(|rows| rows.into_iter().map(SessionRecord::from).collect())
            .map_err(db_error)
    }

    async fn update_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        device_name: &str,
        expected_version: i64,
    ) -> Result<SessionRecord, AuthError> {
        let sql = format!(
            "UPDATE user_sessions SET device_name = $3, version = version + 1 \
             WHERE id = $1 AND user_id = $2 AND version = $4 RETURNING {}",
            SESSION_SELECT
                .trim_start_matches("\nSELECT ")
                .trim_end_matches("\nFROM user_sessions\n")
        );
        sqlx::query_as::<_, SessionRow>(&sql)
            .bind(session_id)
            .bind(user_id)
            .bind(device_name)
            .bind(expected_version.max(1))
            .fetch_optional(&self.pool)
            .await
            .map_err(db_error)?
            .map(SessionRecord::from)
            .ok_or(AuthError::VersionConflict)
    }

    async fn revoke_session(&self, user_id: Uuid, session_id: Uuid) -> Result<bool, AuthError> {
        let result = sqlx::query(
            r"
UPDATE user_sessions
SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = COALESCE(revoke_reason, 'user_revoked')
WHERE id = $1 AND user_id = $2
",
        )
        .bind(session_id)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }
}
