use crate::{
    application::{AccessClaims, AuthError, IssuedAccessToken},
    domain::{SigningKey, UserRecord},
};
use async_trait::async_trait;
use std::time::Duration;
use uuid::Uuid;

#[async_trait]
pub trait PasswordPort: Send + Sync {
    async fn hash(&self, plaintext: String) -> Result<String, AuthError>;
    async fn verify(&self, plaintext: String, encoded: String) -> Result<bool, AuthError>;
}

pub trait AccessTokenPort: Send + Sync {
    fn issue(
        &self,
        user: &UserRecord,
        session_id: Uuid,
        ttl: Duration,
    ) -> Result<IssuedAccessToken, AuthError>;

    fn validate(&self, raw: &str) -> Result<AccessClaims, AuthError>;
    fn signing_keys(&self) -> Vec<SigningKey>;
}

pub trait SecretPort: Send + Sync {
    fn generate(&self) -> String;
    fn digest(&self, raw: &str) -> Vec<u8>;
}
