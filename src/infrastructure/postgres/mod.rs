mod common;
mod email_changes;
mod lifecycle;
mod notifications;
mod profiles;
mod recovery;
mod rows;
mod schema;
mod session_queries;
mod sessions;
mod users;

use crate::{application::AuthError, config::Config};
use sqlx::{PgPool, postgres::PgPoolOptions};

#[derive(Clone)]
pub struct PgAuthRepository {
    pub(super) pool: PgPool,
}

impl PgAuthRepository {
    pub async fn connect(config: &Config) -> Result<Self, AuthError> {
        let connect = PgPoolOptions::new()
            .max_connections(config.database_max_connections)
            .acquire_timeout(config.database_acquire_timeout)
            .connect(&config.database_url);
        let pool = tokio::time::timeout(config.database_connect_timeout, connect)
            .await
            .map_err(|_| AuthError::RepositoryUnavailable)?
            .map_err(db_error)?;
        Ok(Self { pool })
    }
}

pub(super) fn db_error(error: sqlx::Error) -> AuthError {
    let detail = error.to_string();
    drop(error);
    tracing::error!(error = %detail, "auth repository operation failed");
    AuthError::RepositoryUnavailable
}

pub(super) fn unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|value| value.code().is_some_and(|code| code == "23505"))
}
