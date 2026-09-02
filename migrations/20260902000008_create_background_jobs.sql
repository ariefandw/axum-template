-- Background Jobs Queue (SKIP LOCKED)
--
-- Single-binary, zero-Redis background worker engine.
-- Uses standard PostgreSQL transactional locking to guarantee that multiple replicas
-- can pull jobs concurrently without race conditions or double-execution.

CREATE TABLE background_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    queue VARCHAR(64) NOT NULL DEFAULT 'default',
    job_type VARCHAR(128) NOT NULL,
    payload JSONB NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    attempts INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 5,
    last_error TEXT,
    run_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_at TIMESTAMPTZ,
    locked_by VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for high-throughput concurrency:
-- Fast lookup of next available job to lock using SKIP LOCKED
CREATE INDEX idx_background_jobs_polling ON background_jobs (queue, run_at)
WHERE status = 'queued';

CREATE INDEX idx_background_jobs_cleanup ON background_jobs (status, updated_at)
WHERE status IN ('completed', 'cancelled', 'failed');
