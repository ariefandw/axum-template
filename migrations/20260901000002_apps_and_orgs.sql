-- ============================================================================
-- 2. Multi-Tenant Apps, Organizations, and M2M Scoped API Keys
-- ============================================================================

-- Platform Applications
CREATE TABLE IF NOT EXISTS apps (
    id          UUID PRIMARY KEY,
    owner_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        VARCHAR(255) NOT NULL,
    slug        VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_apps_owner_id ON apps(owner_id);

-- Organizations (B2B Tenants scoped under an App)
CREATE TABLE IF NOT EXISTS organizations (
    id         UUID PRIMARY KEY,
    app_id     UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    name       VARCHAR(255) NOT NULL,
    slug       VARCHAR(100) NOT NULL,
    logo_url   VARCHAR(512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_organizations_app_slug UNIQUE (app_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_organizations_app_id ON organizations(app_id);

-- Organization Memberships (RBAC: owner, admin, member)
CREATE TABLE IF NOT EXISTS org_members (
    id         UUID PRIMARY KEY,
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       VARCHAR(50) NOT NULL DEFAULT 'member',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_org_members_org_user UNIQUE (org_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_org_members_user_id ON org_members(user_id);
CREATE INDEX IF NOT EXISTS idx_org_members_org_id ON org_members(org_id);

-- Machine-to-Machine API Keys
CREATE TABLE IF NOT EXISTS api_keys (
    id           UUID PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id       UUID REFERENCES organizations(id) ON DELETE SET NULL,
    name         VARCHAR(100) NOT NULL,
    key_start    VARCHAR(32) NOT NULL,
    key_hash     CHAR(64) NOT NULL,
    scopes       JSONB NOT NULL DEFAULT '["*"]'::jsonb,
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_api_keys_hash ON api_keys (key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys (user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys (org_id) WHERE org_id IS NOT NULL;
