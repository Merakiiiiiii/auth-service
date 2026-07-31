use crate::{
    application::{AccessClaims, AccessTokenPort, AuthError, IssuedAccessToken},
    config::Config,
    domain::{SigningKey, UserRecord},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf, time::Duration};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct JwtClaims {
    sub: String,
    sid: String,
    roles: Vec<String>,
    iss: String,
    aud: String,
    iat: usize,
    exp: usize,
}

#[derive(Clone)]
pub struct Ed25519TokenAdapter {
    encoding: EncodingKey,
    decoding: DecodingKey,
    key_id: String,
    public_key_pem: String,
    issuer: String,
    audience: String,
}

impl Ed25519TokenAdapter {
    pub fn from_config(config: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        let private_key = load_key(
            config.jwt_private_key_path.as_ref(),
            config.jwt_private_key_b64.as_deref(),
            "AUTH_JWT_PRIVATE_KEY_PATH/AUTH_JWT_PRIVATE_KEY_B64",
        )?;
        let public_key = load_key(
            config.jwt_public_key_path.as_ref(),
            config.jwt_public_key_b64.as_deref(),
            "AUTH_JWT_PUBLIC_KEY_PATH/AUTH_JWT_PUBLIC_KEY_B64",
        )?;
        Ok(Self {
            encoding: EncodingKey::from_ed_pem(&private_key)?,
            decoding: DecodingKey::from_ed_pem(&public_key)?,
            key_id: config.jwt_key_id.clone(),
            public_key_pem: String::from_utf8(public_key)?,
            issuer: config.jwt_issuer.clone(),
            audience: config.jwt_audience.clone(),
        })
    }

    fn validation(&self) -> Validation {
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.validate_exp = true;
        validation
    }
}

impl AccessTokenPort for Ed25519TokenAdapter {
    fn issue(
        &self,
        user: &UserRecord,
        session_id: Uuid,
        ttl: Duration,
    ) -> Result<IssuedAccessToken, AuthError> {
        let now = usize::try_from(chrono::Utc::now().timestamp().max(0))
            .map_err(|_| AuthError::Internal)?;
        let ttl_seconds = usize::try_from(ttl.as_secs()).map_err(|_| AuthError::Internal)?;
        let claims = JwtClaims {
            sub: user.id.to_string(),
            sid: session_id.to_string(),
            roles: user.roles.clone(),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            iat: now,
            exp: now.saturating_add(ttl_seconds),
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.key_id.clone());
        let raw = encode(&header, &claims, &self.encoding).map_err(|_| AuthError::Internal)?;
        Ok(IssuedAccessToken {
            raw,
            expires_in: ttl.as_secs(),
        })
    }

    fn validate(&self, raw: &str) -> Result<AccessClaims, AuthError> {
        let header = jsonwebtoken::decode_header(raw).map_err(|_| AuthError::InvalidToken)?;
        if header.alg != Algorithm::EdDSA || header.kid.as_deref() != Some(self.key_id.as_str()) {
            return Err(AuthError::InvalidToken);
        }
        let claims = decode::<JwtClaims>(raw, &self.decoding, &self.validation())
            .map_err(|_| AuthError::InvalidToken)?
            .claims;
        Ok(AccessClaims {
            user_id: Uuid::parse_str(&claims.sub).map_err(|_| AuthError::InvalidToken)?,
            session_id: Uuid::parse_str(&claims.sid).map_err(|_| AuthError::InvalidToken)?,
            roles: claims.roles,
            expires_at: i64::try_from(claims.exp).map_err(|_| AuthError::InvalidToken)?,
        })
    }

    fn signing_keys(&self) -> Vec<SigningKey> {
        vec![SigningKey {
            kid: self.key_id.clone(),
            algorithm: "EdDSA".into(),
            public_key_pem: self.public_key_pem.clone(),
        }]
    }
}

fn load_key(
    path: Option<&PathBuf>,
    encoded: Option<&str>,
    name: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if let Some(path) = path {
        return Ok(fs::read(path)?);
    }
    if let Some(encoded) = encoded {
        return Ok(STANDARD.decode(encoded.trim())?);
    }
    Err(format!("missing {name}").into())
}
