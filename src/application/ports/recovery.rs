use crate::{application::AuthError, domain::UserRecord};
use async_trait::async_trait;
use std::time::Duration;
use uuid::Uuid;

#[async_trait]
pub trait RecoveryStore: Send + Sync {
    async fn consume_verification_token(&self, token_hash: &[u8]) -> Result<Uuid, AuthError>;

    async fn create_password_reset(
        &self,
        email: &str,
        token_hash: &[u8],
        ttl: Duration,
    ) -> Result<Option<UserRecord>, AuthError>;

    async fn consume_password_reset(
        &self,
        token_hash: &[u8],
        password_hash: &str,
    ) -> Result<Uuid, AuthError>;
}
