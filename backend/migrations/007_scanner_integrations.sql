-- +goose Up
CREATE TABLE IF NOT EXISTS scanner_integrations (
    id BIGSERIAL PRIMARY KEY,
    application_id BIGINT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    scanner_type_id BIGINT NOT NULL REFERENCES scanner_types(id) ON DELETE RESTRICT,
    name VARCHAR(100) NOT NULL,
    category VARCHAR(40) NOT NULL,
    configuration JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(20) NOT NULL DEFAULT 'awaiting_report',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    token_prefix VARCHAR(20) NOT NULL,
    last_seen_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_scanner_integrations_application_id ON scanner_integrations(application_id);
CREATE INDEX IF NOT EXISTS idx_scanner_integrations_scanner_type_id ON scanner_integrations(scanner_type_id);
CREATE INDEX IF NOT EXISTS idx_scanner_integrations_deleted_at ON scanner_integrations(deleted_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_integration_application_scanner_active
    ON scanner_integrations(application_id, scanner_type_id)
    WHERE deleted_at IS NULL;

ALTER TABLE scans ADD COLUMN IF NOT EXISTS integration_id BIGINT;
ALTER TABLE scans ADD CONSTRAINT fk_scans_integration
    FOREIGN KEY (integration_id) REFERENCES scanner_integrations(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_scans_integration_id ON scans(integration_id);

-- +goose Down
DROP INDEX IF EXISTS idx_scans_integration_id;
ALTER TABLE scans DROP CONSTRAINT IF EXISTS fk_scans_integration;
ALTER TABLE scans DROP COLUMN IF EXISTS integration_id;
DROP TABLE IF EXISTS scanner_integrations;
