-- Hardening migration.
--
-- Closes the structural gaps found in the initial schema: unscoped recovery
-- tokens, absent session/revocation model, files with no owner, an idempotency
-- store that only existed in process memory, and an "immutable" audit table
-- that nothing actually protected.

-- ---------------------------------------------------------------------------
-- 1. Users: soft delete + credential-stuffing lockout
-- ---------------------------------------------------------------------------
ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INT NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;

-- The original UNIQUE(email) blocks re-registration after a soft delete, so
-- scope uniqueness to live rows only.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key;
CREATE UNIQUE INDEX IF NOT EXISTS uq_users_email_live
    ON users (email) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_live ON users (created_at DESC) WHERE deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- 2. Verifications: purpose-scoped, hashed, single-use
--    Previously every token type shared one untyped `value` column, so an
--    email-verification token was accepted by the password-reset endpoint.
--    Tokens are ephemeral, so the table is rebuilt rather than migrated.
-- ---------------------------------------------------------------------------
DROP TABLE IF EXISTS verifications;
CREATE TABLE verifications (
    id          UUID PRIMARY KEY,
    identifier  VARCHAR(255) NOT NULL,
    purpose     VARCHAR(32)  NOT NULL,
    token_hash  CHAR(64)     NOT NULL,
    expires_at  TIMESTAMPTZ  NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_verifications_purpose
        CHECK (purpose IN ('email_verify', 'password_reset'))
);
CREATE UNIQUE INDEX uq_verifications_hash ON verifications (token_hash);
CREATE INDEX idx_verifications_lookup ON verifications (identifier, purpose, expires_at DESC);

-- ---------------------------------------------------------------------------
-- 3. Sessions: the revocation point the JWT-only design never had
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
    id                 UUID PRIMARY KEY,
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash CHAR(64) NOT NULL,
    -- The immediately-preceding token, retained so that presenting an already
    -- rotated token is distinguishable from presenting a random invalid one.
    -- That distinction is the whole basis of refresh-token reuse detection.
    previous_token_hash CHAR(64),
    expires_at         TIMESTAMPTZ NOT NULL,
    revoked_at         TIMESTAMPTZ,
    rotated_at         TIMESTAMPTZ,
    ip_address         VARCHAR(45),
    user_agent         TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_sessions_refresh_hash ON sessions (refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_previous_hash
    ON sessions (previous_token_hash) WHERE previous_token_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_user_live
    ON sessions (user_id, expires_at DESC) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- 4. OAuth authorization requests: server-side state + PKCE verifier.
--    The callback previously discarded the `state` parameter entirely.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS oauth_auth_requests (
    state_hash    CHAR(64) PRIMARY KEY,
    provider      VARCHAR(32) NOT NULL,
    pkce_verifier TEXT NOT NULL,
    redirect_to   TEXT,
    expires_at    TIMESTAMPTZ NOT NULL,
    consumed_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_oauth_auth_requests_expiry ON oauth_auth_requests (expires_at);

-- ---------------------------------------------------------------------------
-- 5. Files: uploads were previously untracked, so the filename was the entire
--    access-control model. Ownership and visibility now live here.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS files (
    id            UUID PRIMARY KEY,
    owner_id      UUID REFERENCES users(id) ON DELETE CASCADE,
    bucket        VARCHAR(64) NOT NULL DEFAULT 'default',
    storage_key   VARCHAR(255) NOT NULL,
    original_name VARCHAR(255) NOT NULL,
    mime_type     VARCHAR(127) NOT NULL,
    size_bytes    BIGINT NOT NULL,
    checksum_sha256 CHAR(64),
    visibility    VARCHAR(16) NOT NULL DEFAULT 'private',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at    TIMESTAMPTZ,
    CONSTRAINT ck_files_visibility CHECK (visibility IN ('private', 'public'))
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_files_storage_key ON files (storage_key);
CREATE INDEX IF NOT EXISTS idx_files_owner ON files (owner_id, created_at DESC) WHERE deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- 6. Idempotency: shared across replicas, bounded by a TTL, and able to hold an
--    in-flight lock. The in-memory HashMap it replaces was unbounded, per
--    process, and keyed on nothing but the caller-supplied header.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS idempotency_keys (
    scope_hash    CHAR(64) PRIMARY KEY,
    status_code   INT,
    content_type  VARCHAR(127),
    response_body BYTEA,
    completed_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at    TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_idempotency_expiry ON idempotency_keys (expires_at);

-- ---------------------------------------------------------------------------
-- 7. Audit log: enforce the append-only property that was previously only
--    claimed in documentation.
-- ---------------------------------------------------------------------------
-- The ON DELETE SET NULL foreign key would issue an UPDATE against audit_logs
-- whenever a user row is removed, which the immutability trigger below must
-- reject. An audit trail should outlive its subject, so the reference is
-- dropped and user_id retained as an unenforced historical value.
ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS audit_logs_user_id_fkey;

CREATE OR REPLACE FUNCTION audit_logs_reject_mutation() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only; % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_logs_immutable ON audit_logs;
CREATE TRIGGER trg_audit_logs_immutable
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_reject_mutation();

-- Keyset pagination support for the append-only feeds.
CREATE INDEX IF NOT EXISTS idx_audit_logs_keyset ON audit_logs (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_keyset ON notifications (user_id, created_at DESC, id DESC);
