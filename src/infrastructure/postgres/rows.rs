use crate::domain::{SessionRecord, UserRecord};
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

pub const USER_SELECT: &str = r"
SELECT id,
       normalized_email::text AS normalized_email,
       display_name,
       password_hash,
       status::text AS status,
       roles,
       avatar_url,
       bio,
       locale,
       timezone,
       locked_until,
       email_verified_at,
       last_login_at,
       created_at,
       updated_at,
       version
FROM users
";

pub const SESSION_SELECT: &str = r"
SELECT id,
       user_id,
       token_family_id,
       device_name,
       user_agent,
       host(ip_address) AS ip_address,
       expires_at,
       last_used_at,
       revoked_at,
       created_at,
       version
FROM user_sessions
";

#[derive(FromRow)]
pub struct UserRow {
    id: Uuid,
    normalized_email: String,
    display_name: String,
    password_hash: String,
    status: String,
    roles: Vec<String>,
    avatar_url: Option<String>,
    bio: Option<String>,
    locale: String,
    timezone: String,
    locked_until: Option<DateTime<Utc>>,
    email_verified_at: Option<DateTime<Utc>>,
    last_login_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    version: i64,
}

impl From<UserRow> for UserRecord {
    fn from(value: UserRow) -> Self {
        Self {
            id: value.id,
            normalized_email: value.normalized_email,
            display_name: value.display_name,
            password_hash: value.password_hash,
            status: value.status,
            roles: value.roles,
            avatar_url: value.avatar_url,
            bio: value.bio,
            locale: value.locale,
            timezone: value.timezone,
            locked_until: value.locked_until,
            email_verified_at: value.email_verified_at,
            last_login_at: value.last_login_at,
            created_at: value.created_at,
            updated_at: value.updated_at,
            version: value.version,
        }
    }
}

#[derive(FromRow)]
pub struct SessionRow {
    id: Uuid,
    user_id: Uuid,
    token_family_id: Uuid,
    device_name: Option<String>,
    user_agent: Option<String>,
    ip_address: Option<String>,
    expires_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    version: i64,
}

impl From<SessionRow> for SessionRecord {
    fn from(value: SessionRow) -> Self {
        Self {
            id: value.id,
            user_id: value.user_id,
            token_family_id: value.token_family_id,
            device_name: value.device_name,
            user_agent: value.user_agent,
            ip_address: value.ip_address,
            expires_at: value.expires_at,
            last_used_at: value.last_used_at,
            revoked_at: value.revoked_at,
            created_at: value.created_at,
            version: value.version,
        }
    }
}
