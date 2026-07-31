use super::{
    db_error,
    rows::{SESSION_SELECT, SessionRow, USER_SELECT, UserRow},
};
use crate::{
    application::{AuthError, LoginContext},
    domain::{SessionRecord, UserRecord},
};
use sqlx::{Postgres, Transaction};
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone)]
pub(super) struct SessionInsert {
    pub session_id: Uuid,
    pub family_id: Uuid,
    pub user_id: Uuid,
    pub refresh_hash: Vec<u8>,
    pub context: LoginContext,
    pub ttl: Duration,
}

pub(super) fn context_from_session(session: &SessionRecord) -> LoginContext {
    LoginContext {
        device_name: session
            .device_name
            .clone()
            .unwrap_or_else(|| "unknown".into()),
        user_agent: session.user_agent.clone().unwrap_or_default(),
        ip_address: session.ip_address.clone().unwrap_or_default(),
    }
}

pub(super) async fn lock_refresh_session(
    tx: &mut Transaction<'_, Postgres>,
    refresh_hash: &[u8],
) -> Result<SessionRecord, AuthError> {
    let sql = format!(
        "{SESSION_SELECT} WHERE refresh_token_hash = $1 AND revoked_at IS NULL AND expires_at > now() FOR UPDATE"
    );
    sqlx::query_as::<_, SessionRow>(&sql)
        .bind(refresh_hash)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_error)?
        .map(SessionRecord::from)
        .ok_or(AuthError::InvalidRefreshToken)
}

pub(super) async fn revoke_rotated_session(
    tx: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
) -> Result<(), AuthError> {
    sqlx::query(
        "UPDATE user_sessions SET revoked_at = now(), revoke_reason = 'refresh_rotated' WHERE id = $1",
    )
    .bind(session_id)
    .execute(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(())
}

pub(super) async fn get_session_pool(
    pool: &sqlx::PgPool,
    session_id: Uuid,
) -> Result<Option<SessionRecord>, AuthError> {
    let sql = format!("{SESSION_SELECT} WHERE id = $1");
    sqlx::query_as::<_, SessionRow>(&sql)
        .bind(session_id)
        .fetch_optional(pool)
        .await
        .map(|row| row.map(SessionRecord::from))
        .map_err(db_error)
}

pub(super) async fn get_session_tx(
    tx: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
) -> Result<Option<SessionRecord>, AuthError> {
    let sql = format!("{SESSION_SELECT} WHERE id = $1");
    sqlx::query_as::<_, SessionRow>(&sql)
        .bind(session_id)
        .fetch_optional(&mut **tx)
        .await
        .map(|row| row.map(SessionRecord::from))
        .map_err(db_error)
}

pub(super) async fn get_user_tx(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> Result<Option<UserRecord>, AuthError> {
    let sql = format!("{USER_SELECT} WHERE id = $1 AND deleted_at IS NULL");
    sqlx::query_as::<_, UserRow>(&sql)
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await
        .map(|row| row.map(UserRecord::from))
        .map_err(db_error)
}

pub(super) async fn insert_session_pool(
    pool: &sqlx::PgPool,
    insert: &SessionInsert,
) -> Result<(), AuthError> {
    execute_session_insert(pool, insert).await
}

pub(super) async fn insert_session_tx(
    tx: &mut Transaction<'_, Postgres>,
    insert: &SessionInsert,
) -> Result<(), AuthError> {
    execute_session_insert(&mut **tx, insert).await
}

async fn execute_session_insert<'e, E>(executor: E, insert: &SessionInsert) -> Result<(), AuthError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query(
        r"
INSERT INTO user_sessions(
    id, user_id, token_family_id, refresh_token_hash,
    device_name, user_agent, ip_address, expires_at
)
VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, '')::inet,
        now() + ($8::double precision * interval '1 second'))
",
    )
    .bind(insert.session_id)
    .bind(insert.user_id)
    .bind(insert.family_id)
    .bind(&insert.refresh_hash)
    .bind(&insert.context.device_name)
    .bind(&insert.context.user_agent)
    .bind(&insert.context.ip_address)
    .bind(insert.ttl.as_secs_f64())
    .execute(executor)
    .await
    .map_err(db_error)?;
    Ok(())
}
