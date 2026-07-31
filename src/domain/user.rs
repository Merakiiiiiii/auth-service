use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct UserRecord {
    pub id: Uuid,
    pub normalized_email: String,
    pub display_name: String,
    pub password_hash: String,
    pub status: String,
    pub roles: Vec<String>,
    pub avatar_url: Option<String>,
    pub bio: Option<String>,
    pub locale: String,
    pub timezone: String,
    pub locked_until: Option<DateTime<Utc>>,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub version: i64,
}
