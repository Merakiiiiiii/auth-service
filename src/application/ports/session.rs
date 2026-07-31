use crate::{
    application::{AuthError, LoginContext},
    domain::{SessionRecord, UserRecord},
};
use async_trait::async_trait;
use std::time::Duration;
use uuid::Uuid;

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn create_session(
        &self,
        user_id: Uuid,
        refresh_hash: &[u8],
        context: &LoginContext,
        refresh_ttl: Duration,
    ) -> Result<SessionRecord, AuthError>;

    async fn rotate_session(
        &self,
        old_refresh_hash: &[u8],
        new_refresh_hash: &[u8],
        refresh_ttl: Duration,
    ) -> Result<(SessionRecord, UserRecord), AuthError>;

    async fn revoke_refresh_token(&self, refresh_hash: &[u8]) -> Result<(), AuthError>;
    async fn revoke_all_sessions(&self, user_id: Uuid, reason: &str) -> Result<(), AuthError>;
    async fn session_is_active(&self, session_id: Uuid) -> Result<bool, AuthError>;
    async fn get_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
    ) -> Result<Option<SessionRecord>, AuthError>;
    async fn list_sessions(&self, user_id: Uuid) -> Result<Vec<SessionRecord>, AuthError>;
    async fn update_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        device_name: &str,
        expected_version: i64,
    ) -> Result<SessionRecord, AuthError>;
    async fn revoke_session(&self, user_id: Uuid, session_id: Uuid) -> Result<bool, AuthError>;
}
