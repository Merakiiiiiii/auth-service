use crate::application::{AuthError, NotificationMessage};
use async_trait::async_trait;

#[async_trait]
pub trait NotificationStore: Send + Sync {
    async fn enqueue_notification(&self, message: NotificationMessage) -> Result<(), AuthError>;
}
