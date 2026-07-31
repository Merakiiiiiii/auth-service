use crate::application::{
    AuthApplication, AuthError, NotificationKind, NotificationMessage, normalize_email,
    validate_password,
};
use uuid::Uuid;

impl AuthApplication {
    pub async fn forgot_password(&self, email: String) -> Result<(), AuthError> {
        let Ok(email) = normalize_email(&email) else {
            return Ok(());
        };
        let raw_token = self.secrets.generate();
        let user = self
            .repository
            .create_password_reset(
                &email,
                &self.secrets.digest(&raw_token),
                self.policy.reset_ttl,
            )
            .await?;
        if let Some(user) = user {
            self.enqueue_password_reset(user.id, email, raw_token)
                .await?;
        }
        Ok(())
    }

    pub async fn reset_password(
        &self,
        raw_token: String,
        new_password: String,
    ) -> Result<(), AuthError> {
        validate_password(&new_password)?;
        let password_hash = self.passwords.hash(new_password).await?;
        self.repository
            .consume_password_reset(&self.secrets.digest(&raw_token), &password_hash)
            .await?;
        Ok(())
    }

    pub async fn change_password(
        &self,
        user_id: Uuid,
        current_password: String,
        new_password: String,
    ) -> Result<(), AuthError> {
        validate_password(&new_password)?;
        let user = self
            .repository
            .get_user(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;
        if !self
            .passwords
            .verify(current_password, user.password_hash)
            .await?
        {
            return Err(AuthError::InvalidCredentials);
        }
        let new_hash = self.passwords.hash(new_password).await?;
        self.repository.update_password(user_id, &new_hash).await
    }

    async fn enqueue_password_reset(
        &self,
        user_id: Uuid,
        recipient: String,
        token: String,
    ) -> Result<(), AuthError> {
        self.repository
            .enqueue_notification(NotificationMessage {
                kind: NotificationKind::PasswordReset,
                recipient,
                user_id,
                token: token.clone(),
            })
            .await?;
        if self.policy.log_sensitive_tokens {
            tracing::info!(%user_id, reset_token = %token, "development password reset token");
        }
        Ok(())
    }
}
