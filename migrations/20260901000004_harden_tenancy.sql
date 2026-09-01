-- =========================================================================
-- Migration: Add OrgRole CHECK constraint & Slug validity
-- =========================================================================

-- 1. Enforce strict OrgRole CHECK constraint ('owner', 'admin', 'member')
ALTER TABLE org_members DROP CONSTRAINT IF EXISTS chk_org_members_role;
ALTER TABLE org_members ADD CONSTRAINT chk_org_members_role 
    CHECK (role IN ('owner', 'admin', 'member'));

-- 2. Add audit action indexes
CREATE INDEX IF NOT EXISTS idx_apps_slug ON apps(slug);
CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug);
