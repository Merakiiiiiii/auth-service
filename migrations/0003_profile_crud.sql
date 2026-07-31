ALTER TABLE users
    ADD COLUMN IF NOT EXISTS avatar_url text,
    ADD COLUMN IF NOT EXISTS bio varchar(500),
    ADD COLUMN IF NOT EXISTS locale varchar(35) NOT NULL DEFAULT 'en',
    ADD COLUMN IF NOT EXISTS timezone varchar(64) NOT NULL DEFAULT 'UTC',
    ADD COLUMN IF NOT EXISTS version bigint NOT NULL DEFAULT 1;

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_version_positive,
    ADD CONSTRAINT users_version_positive CHECK (version > 0);

ALTER TABLE user_sessions
    ADD COLUMN IF NOT EXISTS version bigint NOT NULL DEFAULT 1;

ALTER TABLE user_sessions
    DROP CONSTRAINT IF EXISTS user_sessions_version_positive,
    ADD CONSTRAINT user_sessions_version_positive CHECK (version > 0);

CREATE TABLE IF NOT EXISTS email_change_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    new_email citext NOT NULL,
    token_hash bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS idx_email_change_token_lookup
    ON email_change_tokens (token_hash, expires_at)
    WHERE consumed_at IS NULL;
