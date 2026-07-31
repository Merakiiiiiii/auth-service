use crate::application::{AccessTokenPort, AuthPolicy, AuthRepository, PasswordPort, SecretPort};
use std::sync::Arc;

#[derive(Clone)]
pub struct AuthApplication {
    pub(crate) repository: Arc<dyn AuthRepository>,
    pub(crate) passwords: Arc<dyn PasswordPort>,
    pub(crate) access_tokens: Arc<dyn AccessTokenPort>,
    pub(crate) secrets: Arc<dyn SecretPort>,
    pub(crate) policy: AuthPolicy,
}

impl AuthApplication {
    pub fn new(
        repository: Arc<dyn AuthRepository>,
        passwords: Arc<dyn PasswordPort>,
        access_tokens: Arc<dyn AccessTokenPort>,
        secrets: Arc<dyn SecretPort>,
        policy: AuthPolicy,
    ) -> Self {
        Self {
            repository,
            passwords,
            access_tokens,
            secrets,
            policy,
        }
    }
}
