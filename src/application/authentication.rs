use crate::application::{
    AccessClaims, AuthApplication, AuthError, LoginContext, TokenResult, normalize_email,
};

impl AuthApplication {
    pub async fn login(
        &self,
        email: String,
        password: String,
        context: LoginContext,
    ) -> Result<TokenResult, AuthError> {
        let email = normalize_email(&email)?;
        let user = self
            .repository
            .find_user_by_email(&email)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;
        Self::ensure_login_allowed(&user)?;
        if !self
            .passwords
            .verify(password, user.password_hash.clone())
            .await?
        {
            return self.reject_failed_login(user.id).await;
        }
        self.repository.record_login_success(user.id).await?;
        self.issue_session(&user, &context).await
    }

    pub async fn refresh_session(&self, raw_refresh: String) -> Result<TokenResult, AuthError> {
        if raw_refresh.trim().is_empty() {
            return Err(AuthError::InvalidRefreshToken);
        }
        let next_refresh = self.secrets.generate();
        let (session, user) = self
            .repository
            .rotate_session(
                &self.secrets.digest(&raw_refresh),
                &self.secrets.digest(&next_refresh),
                self.policy.refresh_ttl,
            )
            .await?;
        if user.status != "active" {
            return Err(AuthError::InvalidRefreshToken);
        }
        self.token_result(&user, session.id, next_refresh)
    }

    pub async fn logout(&self, raw_refresh: String) -> Result<(), AuthError> {
        if !raw_refresh.trim().is_empty() {
            self.repository
                .revoke_refresh_token(&self.secrets.digest(&raw_refresh))
                .await?;
        }
        Ok(())
    }

    pub async fn validate_access_token(&self, raw: String) -> Result<AccessClaims, AuthError> {
        let claims = self.access_tokens.validate(&raw)?;
        if !self.repository.session_is_active(claims.session_id).await? {
            return Err(AuthError::SessionRevoked);
        }
        let user = self
            .repository
            .get_user(claims.user_id)
            .await?
            .ok_or(AuthError::InvalidToken)?;
        if user.status != "active" {
            return Err(AuthError::InvalidToken);
        }
        Ok(claims)
    }
}
