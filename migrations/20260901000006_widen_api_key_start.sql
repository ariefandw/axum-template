-- =========================================================================
-- Migration: Widen key_start column on api_keys table
-- =========================================================================

ALTER TABLE api_keys ALTER COLUMN key_start TYPE VARCHAR(32);
