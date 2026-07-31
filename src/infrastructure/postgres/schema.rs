use super::{PgAuthRepository, db_error};
use crate::application::{AuthError, HealthProbe};
use async_trait::async_trait;

impl PgAuthRepository {
    pub async fn ensure_schema(&self) -> Result<(), AuthError> {
        self.ensure_version_table().await?;
        self.ensure_base_schema().await?;
        self.ensure_runtime_schema().await?;
        self.ensure_profile_schema().await
    }

    async fn ensure_version_table(&self) -> Result<(), AuthError> {
        sqlx::query(
            r"CREATE TABLE IF NOT EXISTS auth_service_schema_migrations (
    version bigint PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
)",
        )
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn ensure_base_schema(&self) -> Result<(), AuthError> {
        let exists: Option<String> = sqlx::query_scalar("SELECT to_regclass('public.users')::text")
            .fetch_one(&self.pool)
            .await
            .map_err(db_error)?;
        if exists.is_none() {
            sqlx::raw_sql(include_str!("../../../migrations/0001_auth_schema.sql"))
                .execute(&self.pool)
                .await
                .map_err(db_error)?;
        }
        mark_applied(&self.pool, 1).await
    }

    async fn ensure_runtime_schema(&self) -> Result<(), AuthError> {
        apply_once(
            &self.pool,
            2,
            include_str!("../../../migrations/0002_auth_runtime.sql"),
        )
        .await
    }

    async fn ensure_profile_schema(&self) -> Result<(), AuthError> {
        apply_once(
            &self.pool,
            3,
            include_str!("../../../migrations/0003_profile_crud.sql"),
        )
        .await
    }
}

async fn apply_once(pool: &sqlx::PgPool, version: i64, sql: &str) -> Result<(), AuthError> {
    let applied: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM auth_service_schema_migrations WHERE version = $1)",
    )
    .bind(version)
    .fetch_one(pool)
    .await
    .map_err(db_error)?;
    if applied {
        return Ok(());
    }
    let mut tx = pool.begin().await.map_err(db_error)?;
    sqlx::raw_sql(sql)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    sqlx::query("INSERT INTO auth_service_schema_migrations(version) VALUES ($1)")
        .bind(version)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    tx.commit().await.map_err(db_error)
}

async fn mark_applied(pool: &sqlx::PgPool, version: i64) -> Result<(), AuthError> {
    sqlx::query(
        "INSERT INTO auth_service_schema_migrations(version) VALUES ($1) ON CONFLICT DO NOTHING",
    )
    .bind(version)
    .execute(pool)
    .await
    .map_err(db_error)?;
    Ok(())
}

#[async_trait]
impl HealthProbe for PgAuthRepository {
    async fn ping(&self) -> Result<(), AuthError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(db_error)?;
        Ok(())
    }
}
