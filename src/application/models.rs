use std::time::Duration;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct RegistrationInput {
    pub email: String,
    pub password: String,
    pub display_name: String,
    pub locale: String,
    pub timezone: String,
}

#[derive(Clone, Debug)]
pub struct NewUserAccount {
    pub email: String,
    pub display_name: String,
    pub password_hash: String,
    pub locale: String,
    pub timezone: String,
    pub verification_hash: Vec<u8>,
    pub verification_ttl: Duration,
}

#[derive(Clone, Debug, Default)]
pub struct LoginContext {
    pub device_name: String,
    pub user_agent: String,
    pub ip_address: String,
}

#[derive(Clone, Debug, Default)]
pub struct UserProfilePatch {
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub bio: Option<String>,
    pub locale: Option<String>,
    pub timezone: Option<String>,
    pub expected_version: i64,
}

#[derive(Clone, Debug)]
pub struct SessionPatch {
    pub device_name: String,
    pub expected_version: i64,
}

#[derive(Clone, Debug)]
pub struct TokenResult {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_in: u64,
    pub refresh_expires_in: u64,
    pub session_id: Uuid,
}

#[derive(Clone, Debug)]
pub struct IssuedAccessToken {
    pub raw: String,
    pub expires_in: u64,
}

#[derive(Clone, Debug)]
pub struct AccessClaims {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub roles: Vec<String>,
    pub expires_at: i64,
}

#[derive(Clone, Debug)]
pub enum NotificationKind {
    EmailVerification,
    PasswordReset,
    EmailChange,
}

impl NotificationKind {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::EmailVerification => "email_verification",
            Self::PasswordReset => "password_reset",
            Self::EmailChange => "email_change",
        }
    }
}

#[derive(Clone, Debug)]
pub struct NotificationMessage {
    pub kind: NotificationKind,
    pub recipient: String,
    pub user_id: Uuid,
    pub token: String,
}
