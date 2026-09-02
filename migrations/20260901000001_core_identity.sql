-- ============================================================================
-- 1. Core Identity, Sessions, Verifications, and Idempotency
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users
CREATE TABLE IF NOT EXISTS users (
    id                     UUID PRIMARY KEY,
    name                   VARCHAR(255) NOT NULL,
    email                  VARCHAR(255) NOT NULL,
    email_verified         BOOLEAN NOT NULL DEFAULT false,
    image                  TEXT,
    password_hash          TEXT,
    role                   VARCHAR(50) NOT NULL DEFAULT 'user',
    banned                 BOOLEAN NOT NULL DEFAULT false,
    ban_reason             TEXT,
    ban_expires            TIMESTAMPTZ,
    failed_login_attempts  INT NOT NULL DEFAULT 0,
    locked_until           TIMESTAMPTZ,
    deleted_at             TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_users_email_live ON users (email) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_live ON users (created_at DESC) WHERE deleted_at IS NULL;

-- Better Auth Compatible Accounts Table
CREATE TABLE IF NOT EXISTS accounts (
    id                     UUID PRIMARY KEY,
    user_id                UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_id             VARCHAR(255) NOT NULL,
    provider_id            VARCHAR(32) NOT NULL,
    access_token           TEXT,
    refresh_token          TEXT,
    access_token_expires_at TIMESTAMPTZ,
    refresh_token_expires_at TIMESTAMPTZ,
    scope                  TEXT,
    password               TEXT,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_accounts_provider_account UNIQUE (provider_id, account_id)
);

CREATE INDEX IF NOT EXISTS idx_accounts_user_id ON accounts(user_id);

-- Sessions (Rotating refresh family + instant revocation)
CREATE TABLE IF NOT EXISTS sessions (
    id                  UUID PRIMARY KEY,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash  CHAR(64) NOT NULL,
    previous_token_hash CHAR(64),
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    rotated_at          TIMESTAMPTZ,
    ip_address          VARCHAR(45),
    user_agent          TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_sessions_refresh_hash ON sessions (refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_previous_hash ON sessions (previous_token_hash) WHERE previous_token_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_user_live ON sessions (user_id, expires_at DESC) WHERE revoked_at IS NULL;

-- Verifications (Purpose-scoped, atomic single-use)
CREATE TABLE IF NOT EXISTS verifications (
    id          UUID PRIMARY KEY,
    identifier  VARCHAR(255) NOT NULL,
    purpose     VARCHAR(32) NOT NULL,
    token_hash  CHAR(64) NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_verifications_purpose CHECK (purpose IN ('email_verify', 'password_reset'))
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_verifications_hash ON verifications (token_hash);
CREATE INDEX IF NOT EXISTS idx_verifications_lookup ON verifications (identifier, purpose, expires_at DESC);

-- OAuth Authorization Requests (PKCE state verifier)
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

-- Idempotency Keys
CREATE TABLE IF NOT EXISTS idempotency_keys (
    key_hash       CHAR(64) PRIMARY KEY,
    user_id        UUID REFERENCES users(id) ON DELETE CASCADE,
    recovery_point VARCHAR(64) NOT NULL DEFAULT 'started',
    response_code  INT,
    response_body  TEXT,
    expires_at     TIMESTAMPTZ NOT NULL,
    locked_at      TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_idempotency_keys_expiry ON idempotency_keys (expires_at);
