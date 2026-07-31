use std::time::Duration;

#[derive(Clone, Debug)]
pub struct AuthPolicy {
    pub access_ttl: Duration,
    pub refresh_ttl: Duration,
    pub verification_ttl: Duration,
    pub reset_ttl: Duration,
    pub email_change_ttl: Duration,
    pub lockout_threshold: i32,
    pub lockout_duration: Duration,
    pub log_sensitive_tokens: bool,
}
