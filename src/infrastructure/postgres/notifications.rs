use super::{PgAuthRepository, db_error};
use crate::application::{AuthError, NotificationMessage, NotificationStore};
use async_trait::async_trait;
use serde_json::json;

#[async_trait]
impl NotificationStore for PgAuthRepository {
    async fn enqueue_notification(&self, message: NotificationMessage) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO auth_notification_outbox(kind, recipient, payload) VALUES ($1, $2, $3)",
        )
        .bind(message.kind.as_str())
        .bind(message.recipient)
        .bind(json!({"user_id": message.user_id, "token": message.token}))
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }
}
