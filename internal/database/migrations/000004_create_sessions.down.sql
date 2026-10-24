ALTER TABLE refresh_tokens
    DROP CONSTRAINT fk_refresh_tokens_session;

DROP INDEX IF EXISTS idx_refresh_tokens_session_id;
DROP INDEX IF EXISTS idx_sessions_user_id;

ALTER TABLE refresh_tokens
    DROP COLUMN session_id;

DROP TABLE sessions;