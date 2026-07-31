use super::{
    PgAuthRepository,
    common::{insert_audit, revoke_all_tx},
    db_error,
};
use crate::application::{AccountLifecycleStore, AuthError};
use async_trait::async_trait;
use serde_json::Value;
use uuid::Uuid;

#[async_trait]
impl AccountLifecycleStore for PgAuthRepository {
    async fn soft_delete_user(
        &self,
        user_id: Uuid,
        expected_version: i64,
    ) -> Result<u64, AuthError> {
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let version = sqlx::query_scalar::<_, i64>(
            r"UPDATE users
SET status = 'deleted', deleted_at = now(), version = version + 1
WHERE id = $1 AND version = $2 AND deleted_at IS NULL
RETURNING version",
        )
        .bind(user_id)
        .bind(expected_version.max(1))
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?
        .ok_or(AuthError::VersionConflict)?;
        revoke_all_tx(&mut tx, user_id, "account_deleted").await?;
        insert_audit(&mut tx, "account_deleted", Some(user_id), None, Value::Null).await?;
        tx.commit().await.map_err(db_error)?;
        u64::try_from(version).map_err(|_| AuthError::Internal)
    }
}
