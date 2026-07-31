use crate::{
    application::{
        AuthApplication, AuthError, NewUserAccount, NotificationKind, NotificationMessage,
        RegistrationInput, normalize_display_name, normalize_email, normalize_locale,
        normalize_timezone, validate_password,
    },
    domain::UserRecord,
};

impl AuthApplication {
    pub async fn register(&self, input: RegistrationInput) -> Result<UserRecord, AuthError> {
        let email = normalize_email(&input.email)?;
        validate_password(&input.password)?;
        let display_name = normalize_display_name(&input.display_name)?;
        let locale = normalize_locale(&input.locale)?;
        let timezone = normalize_timezone(&input.timezone)?;
        let password_hash = self.passwords.hash(input.password).await?;
        let raw_token = self.secrets.generate();
        let account = NewUserAccount {
            email: email.clone(),
            display_name,
            password_hash,
            locale,
            timezone,
            verification_hash: self.secrets.digest(&raw_token),
            verification_ttl: self.policy.verification_ttl,
        };
        let user = self.repository.create_user(account).await?;
        self.enqueue_verification(&user, email, raw_token).await?;
        Ok(user)
    }

    pub async fn verify_email(&self, raw_token: String) -> Result<(), AuthError> {
        if raw_token.trim().is_empty() {
            return Err(AuthError::InvalidVerificationToken);
        }
        self.repository
            .consume_verification_token(&self.secrets.digest(&raw_token))
            .await?;
        Ok(())
    }

    async fn enqueue_verification(
        &self,
        user: &UserRecord,
        recipient: String,
        token: String,
    ) -> Result<(), AuthError> {
        self.repository
            .enqueue_notification(NotificationMessage {
                kind: NotificationKind::EmailVerification,
                recipient,
                user_id: user.id,
                token: token.clone(),
            })
            .await?;
        if self.policy.log_sensitive_tokens {
            tracing::info!(user_id = %user.id, verification_token = %token, "development verification token");
        }
        Ok(())
    }
}
