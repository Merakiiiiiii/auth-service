use crate::{
    application::{AuthApplication, AuthError, LoginContext, TokenResult},
    domain::UserRecord,
};
use chrono::Utc;
use uuid::Uuid;

impl AuthApplication {
    pub(crate) fn ensure_login_allowed(user: &UserRecord) -> Result<(), AuthError> {
        if user.locked_until.is_some_and(|until| until > Utc::now()) {
            return Err(AuthError::AccountLocked);
        }
        if user.status != "active" {
            return Err(AuthError::EmailNotVerified);
        }
        Ok(())
    }

    pub(crate) async fn reject_failed_login<T>(&self, user_id: Uuid) -> Result<T, AuthError> {
        let locked_until = self
            .repository
            .record_failed_login(
                user_id,
                self.policy.lockout_threshold,
                self.policy.lockout_duration,
            )
            .await?;
        if locked_until.is_some_and(|until| until > Utc::now()) {
            Err(AuthError::AccountLocked)
        } else {
            Err(AuthError::InvalidCredentials)
        }
    }

    pub(crate) async fn issue_session(
        &self,
        user: &UserRecord,
        context: &LoginContext,
    ) -> Result<TokenResult, AuthError> {
        let refresh_token = self.secrets.generate();
        let session = self
            .repository
            .create_session(
                user.id,
                &self.secrets.digest(&refresh_token),
                context,
                self.policy.refresh_ttl,
            )
            .await?;
        self.token_result(user, session.id, refresh_token)
    }

    pub(crate) fn token_result(
        &self,
        user: &UserRecord,
        session_id: Uuid,
        refresh_token: String,
    ) -> Result<TokenResult, AuthError> {
        let access = self
            .access_tokens
            .issue(user, session_id, self.policy.access_ttl)?;
        Ok(TokenResult {
            access_token: access.raw,
            refresh_token,
            access_expires_in: access.expires_in,
            refresh_expires_in: self.policy.refresh_ttl.as_secs(),
            session_id,
        })
    }
}
