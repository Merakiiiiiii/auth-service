use std::{env, net::SocketAddr, path::PathBuf, time::Duration};

#[derive(Clone, Debug)]
pub struct Config {
    pub grpc_address: SocketAddr,
    pub http_address: SocketAddr,
    pub database_url: String,
    pub database_max_connections: u32,
    pub database_connect_timeout: Duration,
    pub database_acquire_timeout: Duration,
    pub internal_grpc_token: String,
    pub access_ttl: Duration,
    pub refresh_ttl: Duration,
    pub verification_ttl: Duration,
    pub reset_ttl: Duration,
    pub email_change_ttl: Duration,
    pub lockout_threshold: i32,
    pub lockout_duration: Duration,
    pub jwt_key_id: String,
    pub jwt_private_key_path: Option<PathBuf>,
    pub jwt_public_key_path: Option<PathBuf>,
    pub jwt_private_key_b64: Option<String>,
    pub jwt_public_key_b64: Option<String>,
    pub jwt_issuer: String,
    pub jwt_audience: String,
    pub log_sensitive_tokens: bool,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let grpc_address = address("GRPC_HOST", "GRPC_PORT", "0.0.0.0", "50051")?;
        let http_address = address("HTTP_HOST", "HTTP_PORT", "0.0.0.0", "8081")?;
        let internal_grpc_token = required("INTERNAL_GRPC_TOKEN")?;
        if internal_grpc_token.trim().len() < 32 {
            return Err("INTERNAL_GRPC_TOKEN must contain at least 32 characters".into());
        }

        Ok(Self {
            grpc_address,
            http_address,
            database_url: required("DATABASE_URL")?,
            database_max_connections: number("DATABASE_MAX_CONNECTIONS", 5),
            database_connect_timeout: Duration::from_secs(number(
                "DATABASE_CONNECT_TIMEOUT_SECONDS",
                5,
            )),
            database_acquire_timeout: Duration::from_secs(number(
                "DATABASE_ACQUIRE_TIMEOUT_SECONDS",
                5,
            )),
            internal_grpc_token,
            access_ttl: Duration::from_secs(number("ACCESS_TOKEN_TTL_SECONDS", 900)),
            refresh_ttl: Duration::from_secs(number("REFRESH_TOKEN_TTL_SECONDS", 2_592_000)),
            verification_ttl: Duration::from_secs(number("EMAIL_VERIFICATION_TTL_SECONDS", 86_400)),
            reset_ttl: Duration::from_secs(number("PASSWORD_RESET_TTL_SECONDS", 3_600)),
            email_change_ttl: Duration::from_secs(number("EMAIL_CHANGE_TTL_SECONDS", 86_400)),
            lockout_threshold: number("LOGIN_LOCKOUT_THRESHOLD", 5),
            lockout_duration: Duration::from_secs(number("LOGIN_LOCKOUT_DURATION_SECONDS", 900)),
            jwt_key_id: env::var("AUTH_JWT_KEY_ID").unwrap_or_else(|_| "auth-v1".into()),
            jwt_private_key_path: env::var_os("AUTH_JWT_PRIVATE_KEY_PATH").map(PathBuf::from),
            jwt_public_key_path: env::var_os("AUTH_JWT_PUBLIC_KEY_PATH").map(PathBuf::from),
            jwt_private_key_b64: env::var("AUTH_JWT_PRIVATE_KEY_B64").ok(),
            jwt_public_key_b64: env::var("AUTH_JWT_PUBLIC_KEY_B64").ok(),
            jwt_issuer: env::var("AUTH_JWT_ISSUER").unwrap_or_else(|_| "auth-service".into()),
            jwt_audience: env::var("AUTH_JWT_AUDIENCE").unwrap_or_else(|_| "public-api".into()),
            log_sensitive_tokens: boolean("AUTH_LOG_SENSITIVE_TOKENS", false),
        })
    }
}

fn address(
    host_name: &str,
    port_name: &str,
    default_host: &str,
    default_port: &str,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let host = env::var(host_name).unwrap_or_else(|_| default_host.into());
    let port = env::var(port_name).unwrap_or_else(|_| default_port.into());
    Ok(format!("{host}:{port}").parse()?)
}

fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value =
        env::var(name).map_err(|_| format!("missing required environment variable {name}"))?;
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty").into());
    }
    Ok(value)
}

fn number<T>(name: &str, default: T) -> T
where
    T: std::str::FromStr + Copy,
{
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn boolean(name: &str, default: bool) -> bool {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
