-- =========================================================================
-- Migration: Cascade app_id to Webhooks and enforce strict multi-app tenancy
-- =========================================================================

ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS app_id UUID REFERENCES apps(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_webhooks_app ON webhooks (app_id) WHERE app_id IS NOT NULL;

-- Index files by app_id for fast scoped lookups
CREATE INDEX IF NOT EXISTS idx_files_app_id ON files (app_id) WHERE app_id IS NOT NULL;
