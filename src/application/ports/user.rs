use crate::{
    application::{AuthError, NewUserAccount, UserProfilePatch},
    domain::UserRecord,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::time::Duration;
use uuid::Uuid;

#[async_trait]
pub trait UserStore: Send + Sync {
    async fn create_user(&self, account: NewUserAccount) -> Result<UserRecord, AuthError>;
    async fn get_user(&self, user_id: Uuid) -> Result<Option<UserRecord>, AuthError>;
    async fn find_user_by_email(&self, email: &str) -> Result<Option<UserRecord>, AuthError>;

    async fn record_failed_login(
        &self,
        user_id: Uuid,
        threshold: i32,
        lockout_duration: Duration,
    ) -> Result<Option<DateTime<Utc>>, AuthError>;

    async fn record_login_success(&self, user_id: Uuid) -> Result<(), AuthError>;
    async fn update_password(&self, user_id: Uuid, password_hash: &str) -> Result<(), AuthError>;
}

#[async_trait]
pub trait ProfileStore: Send + Sync {
    async fn update_profile(
        &self,
        user_id: Uuid,
        patch: UserProfilePatch,
    ) -> Result<UserRecord, AuthError>;
}

#[async_trait]
pub trait EmailChangeStore: Send + Sync {
    async fn create_email_change(
        &self,
        user_id: Uuid,
        new_email: &str,
        token_hash: &[u8],
        ttl: Duration,
    ) -> Result<(), AuthError>;

    async fn consume_email_change(&self, token_hash: &[u8]) -> Result<UserRecord, AuthError>;
}

#[async_trait]
pub trait AccountLifecycleStore: Send + Sync {
    async fn soft_delete_user(
        &self,
        user_id: Uuid,
        expected_version: i64,
    ) -> Result<u64, AuthError>;
}
