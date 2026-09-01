-- =========================================================================
-- Migration: give presigned uploads a real lifecycle
-- =========================================================================
--
-- A presigned upload writes bytes straight to object storage, so the API never
-- sees them. Without a row reserved up front and confirmed afterwards, the
-- object is orphaned: unowned, unreachable through the API, and impossible to
-- authorize or delete. `status` closes that gap.
--
--   pending  a key has been reserved and a URL issued; bytes may not exist yet
--   ready    the object was confirmed present in storage and is readable
--
-- Direct multipart uploads are 'ready' immediately, since the API has already
-- seen and validated every byte.

ALTER TABLE files ADD COLUMN IF NOT EXISTS status VARCHAR(16) NOT NULL DEFAULT 'ready';

ALTER TABLE files DROP CONSTRAINT IF EXISTS ck_files_status;
ALTER TABLE files ADD CONSTRAINT ck_files_status CHECK (status IN ('pending', 'ready'));

-- Reaping abandoned uploads walks this index rather than the whole table.
CREATE INDEX IF NOT EXISTS idx_files_pending
    ON files (created_at) WHERE status = 'pending' AND deleted_at IS NULL;
