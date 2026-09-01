-- =========================================================================
-- Migration: Add Apps, Organizations, and Multi-Tenant RBAC Memberships
-- =========================================================================

-- 1. Apps Table (Platform Applications)
CREATE TABLE IF NOT EXISTS apps (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 2. Organizations Table (B2B Tenants scoped under an App)
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY,
    app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL,
    logo_url VARCHAR(512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_organizations_app_slug UNIQUE (app_id, slug)
);

-- 3. Organization Memberships (User roles inside an Org)
CREATE TABLE IF NOT EXISTS org_members (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL DEFAULT 'member', -- 'owner', 'admin', 'member'
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_org_members_org_user UNIQUE (org_id, user_id)
);

-- 4. Scope Notifications by App (Optional link)
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS app_id UUID REFERENCES apps(id) ON DELETE SET NULL;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE SET NULL;

-- 5. Scope Files by App / Org (Optional link)
ALTER TABLE files ADD COLUMN IF NOT EXISTS app_id UUID REFERENCES apps(id) ON DELETE SET NULL;
ALTER TABLE files ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE SET NULL;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_apps_owner_id ON apps(owner_id);
CREATE INDEX IF NOT EXISTS idx_organizations_app_id ON organizations(app_id);
CREATE INDEX IF NOT EXISTS idx_org_members_user_id ON org_members(user_id);
CREATE INDEX IF NOT EXISTS idx_org_members_org_id ON org_members(org_id);
