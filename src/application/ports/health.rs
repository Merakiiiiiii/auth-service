use crate::application::AuthError;
use async_trait::async_trait;

#[async_trait]
pub trait HealthProbe: Send + Sync {
    async fn ping(&self) -> Result<(), AuthError>;
}
