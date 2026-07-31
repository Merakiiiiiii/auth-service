use crate::{
    application::{AuthApplication, AuthError, SessionPatch},
    domain::SessionRecord,
};
use uuid::Uuid;

impl AuthApplication {
    pub async fn logout_all(&self, user_id: Uuid) -> Result<(), AuthError> {
        self.repository
            .revoke_all_sessions(user_id, "logout_all")
            .await
    }

    pub async fn get_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
    ) -> Result<SessionRecord, AuthError> {
        self.repository
            .get_session(user_id, session_id)
            .await?
            .ok_or(AuthError::SessionNotFound)
    }

    pub async fn list_sessions(&self, user_id: Uuid) -> Result<Vec<SessionRecord>, AuthError> {
        self.repository.list_sessions(user_id).await
    }

    pub async fn update_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        patch: SessionPatch,
    ) -> Result<SessionRecord, AuthError> {
        let device_name = patch.device_name.trim();
        if device_name.is_empty() || device_name.chars().count() > 160 {
            return Err(AuthError::InvalidDisplayName);
        }
        self.repository
            .update_session(user_id, session_id, device_name, patch.expected_version)
            .await
    }

    pub async fn revoke_session(&self, user_id: Uuid, session_id: Uuid) -> Result<(), AuthError> {
        if !self.repository.revoke_session(user_id, session_id).await? {
            return Err(AuthError::SessionNotFound);
        }
        Ok(())
    }

    pub fn signing_keys(&self) -> Vec<crate::domain::SigningKey> {
        self.access_tokens.signing_keys()
    }
}
