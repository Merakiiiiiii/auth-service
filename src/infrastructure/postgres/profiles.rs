use super::{
    PgAuthRepository, db_error,
    rows::{USER_SELECT, UserRow},
};
use crate::{
    application::{AuthError, ProfileStore, UserProfilePatch},
    domain::UserRecord,
};
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
impl ProfileStore for PgAuthRepository {
    async fn update_profile(
        &self,
        user_id: Uuid,
        patch: UserProfilePatch,
    ) -> Result<UserRecord, AuthError> {
        let expected = normalized_version(patch.expected_version);
        let sql = format!(
            r"UPDATE users
SET display_name = COALESCE($3, display_name),
    avatar_url = CASE WHEN $4::text IS NULL THEN avatar_url ELSE NULLIF($4, '') END,
    bio = CASE WHEN $5::text IS NULL THEN bio ELSE NULLIF($5, '') END,
    locale = COALESCE($6, locale),
    timezone = COALESCE($7, timezone),
    version = version + 1
WHERE id = $1 AND version = $2 AND deleted_at IS NULL
RETURNING {}",
            USER_SELECT
                .trim_start_matches("\nSELECT ")
                .trim_end_matches("\nFROM users\n")
        );
        let row = sqlx::query_as::<_, UserRow>(&sql)
            .bind(user_id)
            .bind(expected)
            .bind(patch.display_name)
            .bind(patch.avatar_url)
            .bind(patch.bio)
            .bind(patch.locale)
            .bind(patch.timezone)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_error)?;
        row.map(UserRecord::from)
            .ok_or_else(|| version_or_missing(patch.expected_version))
    }
}

fn normalized_version(version: i64) -> i64 {
    version.max(1)
}

const fn version_or_missing(version: i64) -> AuthError {
    if version > 0 {
        AuthError::VersionConflict
    } else {
        AuthError::UserNotFound
    }
}
