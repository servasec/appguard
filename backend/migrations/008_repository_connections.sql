-- +goose Up
CREATE TABLE IF NOT EXISTS repository_oauth_states (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(20) NOT NULL,
    state_hash VARCHAR(64) NOT NULL UNIQUE,
    return_to VARCHAR(300) NOT NULL DEFAULT '',
    installation_id BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_repository_oauth_states_expires_at ON repository_oauth_states(expires_at);
CREATE INDEX IF NOT EXISTS idx_repository_oauth_states_user_id ON repository_oauth_states(user_id);

CREATE TABLE IF NOT EXISTS repository_connections (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(20) NOT NULL,
    provider_account_id VARCHAR(100) NOT NULL,
    account_name VARCHAR(200) NOT NULL,
    installation_id BIGINT,
    provider_base_url VARCHAR(300) NOT NULL DEFAULT '',
    encrypted_access_token VARCHAR(2000) NOT NULL DEFAULT '',
    access_token_iv VARCHAR(44) NOT NULL DEFAULT '',
    encrypted_refresh_token VARCHAR(2000) NOT NULL DEFAULT '',
    refresh_token_iv VARCHAR(44) NOT NULL DEFAULT '',
    token_expires_at TIMESTAMPTZ,
    status VARCHAR(20) NOT NULL DEFAULT 'connected',
    last_webhook_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_repository_connections_user_id ON repository_connections(user_id);
CREATE INDEX IF NOT EXISTS idx_repository_connections_provider_installation ON repository_connections(provider, installation_id);
CREATE INDEX IF NOT EXISTS idx_repository_connections_deleted_at ON repository_connections(deleted_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_repository_connection_account_active
    ON repository_connections(user_id, provider, provider_account_id) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS application_repository_links (
    id BIGSERIAL PRIMARY KEY,
    application_id BIGINT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    connection_id BIGINT NOT NULL REFERENCES repository_connections(id) ON DELETE CASCADE,
    provider VARCHAR(20) NOT NULL,
    external_repository_id VARCHAR(100) NOT NULL,
    repository_path VARCHAR(300) NOT NULL,
    repository_url VARCHAR(500) NOT NULL,
    webhook_secret_hash VARCHAR(64) NOT NULL DEFAULT '',
    webhook_status VARCHAR(20) NOT NULL DEFAULT 'awaiting_delivery',
    last_webhook_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_application_repository_links_connection_id ON application_repository_links(connection_id);
CREATE INDEX IF NOT EXISTS idx_application_repository_links_deleted_at ON application_repository_links(deleted_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_repo_link_app_active
    ON application_repository_links(application_id) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_repo_link_external_active
    ON application_repository_links(provider, external_repository_id) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS repository_webhook_deliveries (
    id BIGSERIAL PRIMARY KEY,
    provider VARCHAR(20) NOT NULL,
    delivery_id VARCHAR(120) NOT NULL,
    event VARCHAR(60) NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT idx_repo_webhook_delivery UNIQUE(provider, delivery_id)
);

-- +goose Down
DROP TABLE IF EXISTS repository_webhook_deliveries;
DROP TABLE IF EXISTS application_repository_links;
DROP TABLE IF EXISTS repository_connections;
DROP TABLE IF EXISTS repository_oauth_states;
