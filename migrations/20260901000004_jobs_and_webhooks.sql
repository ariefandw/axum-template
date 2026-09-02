-- ============================================================================
-- 4. Background Job Queue (SKIP LOCKED) and Transactional Outbox Webhooks
-- ============================================================================

-- Background Jobs Queue
CREATE TABLE IF NOT EXISTS background_jobs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    queue        VARCHAR(64) NOT NULL DEFAULT 'default',
    job_type     VARCHAR(128) NOT NULL,
    payload      JSONB NOT NULL,
    status       VARCHAR(32) NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    attempts     INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 5,
    last_error   TEXT,
    run_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_at    TIMESTAMPTZ,
    locked_by    VARCHAR(128),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_background_jobs_polling ON background_jobs (queue, run_at) WHERE status = 'queued';
CREATE INDEX IF NOT EXISTS idx_background_jobs_cleanup ON background_jobs (status, updated_at) WHERE status IN ('completed', 'cancelled', 'failed');

-- Webhook Endpoints
CREATE TABLE IF NOT EXISTS webhooks (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id     UUID REFERENCES apps(id) ON DELETE CASCADE,
    owner_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id     UUID REFERENCES organizations(id) ON DELETE CASCADE,
    target_url TEXT NOT NULL,
    secret     TEXT NOT NULL,
    events     TEXT[] NOT NULL DEFAULT '{"*"}',
    is_active  BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhooks_owner ON webhooks (owner_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_app ON webhooks (app_id) WHERE app_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_webhooks_org ON webhooks (org_id) WHERE org_id IS NOT NULL;

-- Webhook Delivery Outbox Logs
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id    UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event_type    VARCHAR(128) NOT NULL,
    payload       JSONB NOT NULL,
    status        VARCHAR(32) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivered', 'failed')),
    status_code   INT,
    response_body TEXT,
    attempts      INT NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook ON webhook_deliveries (webhook_id, created_at DESC);
