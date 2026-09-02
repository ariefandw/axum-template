-- Webhooks & Webhook Deliveries (Outbox Dispatcher)
--
-- Provides subscriber endpoint registration and immutable delivery logs.
-- Uses HMAC-SHA256 signatures for payload verification.

CREATE TABLE webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    target_url TEXT NOT NULL,
    secret TEXT NOT NULL,
    events TEXT[] NOT NULL DEFAULT '{"*"}',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhooks_owner ON webhooks (owner_id);
CREATE INDEX idx_webhooks_org ON webhooks (org_id) WHERE org_id IS NOT NULL;

CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event_type VARCHAR(128) NOT NULL,
    payload JSONB NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivered', 'failed')),
    status_code INT,
    response_body TEXT,
    attempts INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhook_deliveries_webhook ON webhook_deliveries (webhook_id, created_at DESC);
