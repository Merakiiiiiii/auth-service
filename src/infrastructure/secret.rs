use crate::application::SecretPort;
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone, Default)]
pub struct Sha256SecretAdapter;

impl SecretPort for Sha256SecretAdapter {
    fn generate(&self) -> String {
        format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
    }

    fn digest(&self, raw: &str) -> Vec<u8> {
        Sha256::digest(raw.as_bytes()).to_vec()
    }
}
