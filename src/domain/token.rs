#[derive(Clone, Debug)]
pub struct SigningKey {
    pub kid: String,
    pub algorithm: String,
    pub public_key_pem: String,
}
