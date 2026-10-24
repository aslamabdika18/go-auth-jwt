CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_sessions_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
);

ALTER TABLE refresh_tokens
    ADD COLUMN session_id TEXT;

-- Pertahankan relasi token lama selama migrasi.
INSERT INTO sessions (id, user_id, expires_at)
SELECT
    'legacy-' || id::TEXT,
    user_id,
    expires_at
FROM refresh_tokens;

UPDATE refresh_tokens
SET session_id = 'legacy-' || id::TEXT;

ALTER TABLE refresh_tokens
    ALTER COLUMN session_id SET NOT NULL;

ALTER TABLE refresh_tokens
    ADD CONSTRAINT fk_refresh_tokens_session
    FOREIGN KEY (session_id)
    REFERENCES sessions(id)
    ON DELETE CASCADE;

CREATE INDEX idx_sessions_user_id
    ON sessions(user_id);

CREATE INDEX idx_refresh_tokens_session_id
    ON refresh_tokens(session_id);