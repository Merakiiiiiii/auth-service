use crate::{
    application::{AccessClaims, AuthError, TokenResult},
    domain::{SessionRecord, SigningKey, UserRecord},
};
use platform_proto::{
    ActorContext, OperationResult, SessionInfo, TokenPair, UserProfile, ValidateAccessTokenResponse,
};
use tonic::Status;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub struct ActorIds {
    pub user_id: Uuid,
    pub session_id: Option<Uuid>,
}

pub fn operation(resource_id: impl Into<String>, version: u64) -> OperationResult {
    OperationResult {
        success: true,
        resource_id: resource_id.into(),
        version,
    }
}

pub fn token_pair(value: TokenResult) -> TokenPair {
    TokenPair {
        access_token: value.access_token,
        refresh_token: value.refresh_token,
        access_expires_in: value.access_expires_in,
        refresh_expires_in: value.refresh_expires_in,
        session_id: value.session_id.to_string(),
    }
}

pub fn actor_ids(actor: Option<ActorContext>) -> Result<ActorIds, Status> {
    let actor = actor.ok_or_else(|| Status::unauthenticated("AUTH_INVALID_TOKEN"))?;
    let user_id = Uuid::parse_str(&actor.user_id)
        .map_err(|_| Status::unauthenticated("AUTH_INVALID_TOKEN"))?;
    let session_id = if actor.session_id.is_empty() {
        None
    } else {
        Some(
            Uuid::parse_str(&actor.session_id)
                .map_err(|_| Status::unauthenticated("AUTH_INVALID_TOKEN"))?,
        )
    };
    Ok(ActorIds {
        user_id,
        session_id,
    })
}

pub fn user_profile(user: UserRecord) -> UserProfile {
    UserProfile {
        id: user.id.to_string(),
        email: user.normalized_email,
        display_name: user.display_name,
        status: user.status,
        roles: user.roles,
        created_at: Some(timestamp(user.created_at)),
        avatar_url: user.avatar_url.unwrap_or_default(),
        bio: user.bio.unwrap_or_default(),
        locale: user.locale,
        timezone: user.timezone,
        updated_at: Some(timestamp(user.updated_at)),
        email_verified_at: user.email_verified_at.map(timestamp),
        last_login_at: user.last_login_at.map(timestamp),
        version: unsigned_version(user.version),
    }
}

pub fn session_info(session: SessionRecord, current_session: Option<Uuid>) -> SessionInfo {
    SessionInfo {
        id: session.id.to_string(),
        device_name: session.device_name.unwrap_or_default(),
        user_agent: session.user_agent.unwrap_or_default(),
        ip_address: session.ip_address.unwrap_or_default(),
        created_at: Some(timestamp(session.created_at)),
        expires_at: Some(timestamp(session.expires_at)),
        revoked_at: session.revoked_at.map(timestamp),
        last_used_at: session.last_used_at.map(timestamp),
        current: current_session == Some(session.id),
        version: unsigned_version(session.version),
    }
}

pub fn validated_token(claims: AccessClaims) -> ValidateAccessTokenResponse {
    ValidateAccessTokenResponse {
        valid: true,
        actor: Some(ActorContext {
            user_id: claims.user_id.to_string(),
            session_id: claims.session_id.to_string(),
            roles: claims.roles,
        }),
        expires_at: Some(prost_types::Timestamp {
            seconds: claims.expires_at,
            nanos: 0,
        }),
    }
}

pub fn signing_key(value: SigningKey) -> platform_proto::SigningKey {
    platform_proto::SigningKey {
        kid: value.kid,
        algorithm: value.algorithm,
        public_key_pem: value.public_key_pem,
    }
}

pub fn expected_version(value: u64) -> Result<i64, Status> {
    if value == 0 {
        return Ok(1);
    }
    i64::try_from(value).map_err(|_| Status::invalid_argument("AUTH_INVALID_VERSION"))
}

pub fn parse_id(value: &str, code: &'static str) -> Result<Uuid, Status> {
    Uuid::parse_str(value).map_err(|_| Status::invalid_argument(code))
}

pub fn status(error: AuthError) -> Status {
    super::error::status(error)
}

const fn timestamp(value: chrono::DateTime<chrono::Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: value.timestamp(),
        nanos: value.timestamp_subsec_nanos().cast_signed(),
    }
}

fn unsigned_version(value: i64) -> u64 {
    u64::try_from(value).unwrap_or_default()
}
