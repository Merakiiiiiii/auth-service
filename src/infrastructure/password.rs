use crate::application::{AuthError, PasswordPort};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use async_trait::async_trait;
use rand_core::OsRng;

#[derive(Clone, Default)]
pub struct ArgonPasswordAdapter;

#[async_trait]
impl PasswordPort for ArgonPasswordAdapter {
    async fn hash(&self, plaintext: String) -> Result<String, AuthError> {
        tokio::task::spawn_blocking(move || {
            let salt = SaltString::generate(&mut OsRng);
            Argon2::default()
                .hash_password(plaintext.as_bytes(), &salt)
                .map(|value| value.to_string())
                .map_err(|_| AuthError::Internal)
        })
        .await
        .map_err(|_| AuthError::Internal)?
    }

    async fn verify(&self, plaintext: String, encoded: String) -> Result<bool, AuthError> {
        tokio::task::spawn_blocking(move || {
            let hash = PasswordHash::new(&encoded).map_err(|_| AuthError::Internal)?;
            Ok(Argon2::default()
                .verify_password(plaintext.as_bytes(), &hash)
                .is_ok())
        })
        .await
        .map_err(|_| AuthError::Internal)?
    }
}
