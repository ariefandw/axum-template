-- ============================================================================
-- 3. Storage, In-App Notifications, and Append-Only Audit Trail
-- ============================================================================

-- Notifications Feed
CREATE TABLE IF NOT EXISTS notifications (
    id         UUID PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app_id     UUID REFERENCES apps(id) ON DELETE SET NULL,
    org_id     UUID REFERENCES organizations(id) ON DELETE SET NULL,
    title      VARCHAR(255) NOT NULL,
    body       TEXT NOT NULL,
    read       BOOLEAN NOT NULL DEFAULT false,
    data       JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_notifications_feed ON notifications (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_org ON notifications (user_id, org_id, created_at DESC) WHERE org_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_notifications_app ON notifications (app_id) WHERE app_id IS NOT NULL;

-- File Storage (Owned, MIME-sniffed, Presigned Upload Lifecycle)
CREATE TABLE IF NOT EXISTS files (
    id                  UUID PRIMARY KEY,
    owner_id            UUID REFERENCES users(id) ON DELETE CASCADE,
    app_id              UUID REFERENCES apps(id) ON DELETE SET NULL,
    org_id              UUID REFERENCES organizations(id) ON DELETE SET NULL,
    bucket              VARCHAR(64) NOT NULL DEFAULT 'default',
    storage_key         VARCHAR(255) NOT NULL,
    original_name       VARCHAR(255) NOT NULL,
    mime_type           VARCHAR(127) NOT NULL,
    size_bytes          BIGINT NOT NULL,
    checksum_sha256     CHAR(64),
    visibility          VARCHAR(16) NOT NULL DEFAULT 'private',
    status              VARCHAR(16) NOT NULL DEFAULT 'ready',
    upload_expires_at   TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at          TIMESTAMPTZ,
    CONSTRAINT ck_files_visibility CHECK (visibility IN ('private', 'public')),
    CONSTRAINT ck_files_status CHECK (status IN ('pending', 'ready', 'failed'))
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_files_storage_key ON files (storage_key);
CREATE INDEX IF NOT EXISTS idx_files_owner ON files (owner_id, created_at DESC) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_files_app_id ON files (app_id) WHERE app_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_files_org ON files (org_id, created_at DESC) WHERE org_id IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_files_reapable_pending ON files (status, upload_expires_at) WHERE status = 'pending';

-- Audit Logs (Append-Only with Database Trigger Protection)
CREATE TABLE IF NOT EXISTS audit_logs (
    id          UUID PRIMARY KEY,
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    action      VARCHAR(64) NOT NULL,
    resource    VARCHAR(64) NOT NULL,
    resource_id VARCHAR(64),
    ip_address  VARCHAR(45),
    user_agent  TEXT,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs (resource, resource_id, created_at DESC);

-- Immutable Audit Trigger
CREATE OR REPLACE FUNCTION audit_logs_immutable()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only: updates and deletes are prohibited';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_logs_immutable ON audit_logs;
CREATE TRIGGER trg_audit_logs_immutable
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_immutable();
