ALTER TABLE users
    ADD COLUMN IF NOT EXISTS last_login_at timestamptz,
    ADD COLUMN IF NOT EXISTS password_changed_at timestamptz;

CREATE INDEX IF NOT EXISTS idx_users_lockout
    ON users (locked_until)
    WHERE locked_until IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_sessions_refresh_lookup
    ON user_sessions (refresh_token_hash)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_verification_token_lookup
    ON email_verification_tokens (token_hash)
    WHERE consumed_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_password_reset_lookup
    ON password_reset_tokens (token_hash)
    WHERE consumed_at IS NULL;

CREATE TABLE IF NOT EXISTS auth_notification_outbox (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind varchar(80) NOT NULL,
    recipient citext NOT NULL,
    payload jsonb NOT NULL,
    status varchar(32) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'sending', 'sent', 'failed')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    sent_at timestamptz
);

CREATE INDEX IF NOT EXISTS idx_auth_notification_outbox_due
    ON auth_notification_outbox (next_attempt_at, created_at)
    WHERE status IN ('pending', 'failed');
