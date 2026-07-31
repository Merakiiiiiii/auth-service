use crate::{
    application::{
        AuthApplication, AuthError, NotificationKind, NotificationMessage, UserProfilePatch,
        normalize_avatar_url, normalize_bio, normalize_display_name, normalize_email,
        normalize_locale, normalize_timezone,
    },
    domain::UserRecord,
};
use uuid::Uuid;

impl AuthApplication {
    pub async fn get_user(&self, user_id: Uuid) -> Result<UserRecord, AuthError> {
        self.repository
            .get_user(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)
    }

    pub async fn update_user(
        &self,
        user_id: Uuid,
        patch: UserProfilePatch,
    ) -> Result<UserRecord, AuthError> {
        let patch = validate_patch(patch)?;
        self.repository.update_profile(user_id, patch).await
    }

    pub async fn request_email_change(
        &self,
        user_id: Uuid,
        new_email: String,
        current_password: String,
    ) -> Result<(), AuthError> {
        let user = self.get_user(user_id).await?;
        if !self
            .passwords
            .verify(current_password, user.password_hash)
            .await?
        {
            return Err(AuthError::InvalidCredentials);
        }
        let new_email = normalize_email(&new_email)?;
        let token = self.secrets.generate();
        self.repository
            .create_email_change(
                user_id,
                &new_email,
                &self.secrets.digest(&token),
                self.policy.email_change_ttl,
            )
            .await?;
        self.enqueue_email_change(user_id, new_email, token).await
    }

    pub async fn confirm_email_change(&self, token: String) -> Result<UserRecord, AuthError> {
        if token.trim().is_empty() {
            return Err(AuthError::InvalidEmailChangeToken);
        }
        self.repository
            .consume_email_change(&self.secrets.digest(&token))
            .await
    }

    pub async fn delete_user(
        &self,
        user_id: Uuid,
        current_password: String,
        expected_version: i64,
    ) -> Result<u64, AuthError> {
        let user = self.get_user(user_id).await?;
        if !self
            .passwords
            .verify(current_password, user.password_hash)
            .await?
        {
            return Err(AuthError::InvalidCredentials);
        }
        self.repository
            .soft_delete_user(user_id, expected_version)
            .await
    }

    async fn enqueue_email_change(
        &self,
        user_id: Uuid,
        recipient: String,
        token: String,
    ) -> Result<(), AuthError> {
        self.repository
            .enqueue_notification(NotificationMessage {
                kind: NotificationKind::EmailChange,
                recipient,
                user_id,
                token: token.clone(),
            })
            .await?;
        if self.policy.log_sensitive_tokens {
            tracing::info!(%user_id, email_change_token = %token, "development email change token");
        }
        Ok(())
    }
}

fn validate_patch(mut patch: UserProfilePatch) -> Result<UserProfilePatch, AuthError> {
    patch.display_name = patch
        .display_name
        .map(|value| normalize_display_name(&value))
        .transpose()?;
    patch.avatar_url = patch
        .avatar_url
        .map(|value| normalize_avatar_url(&value))
        .transpose()?;
    patch.bio = patch.bio.map(|value| normalize_bio(&value)).transpose()?;
    patch.locale = patch
        .locale
        .map(|value| normalize_locale(&value))
        .transpose()?;
    patch.timezone = patch
        .timezone
        .map(|value| normalize_timezone(&value))
        .transpose()?;
    Ok(patch)
}
