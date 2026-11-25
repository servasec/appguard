-- +goose Up
DROP INDEX IF EXISTS idx_repository_connection_account_active;

-- GitHub App installs are per user or organization, so one AppGuard user can
-- own several installations of the same configured GitHub App.
CREATE UNIQUE INDEX IF NOT EXISTS idx_github_installation_user_active
    ON repository_connections(user_id, installation_id)
    WHERE provider = 'github' AND installation_id IS NOT NULL AND deleted_at IS NULL;

-- GitLab remains one connection per GitLab account and AppGuard user.
CREATE UNIQUE INDEX IF NOT EXISTS idx_gitlab_account_user_active
    ON repository_connections(user_id, provider_account_id)
    WHERE provider = 'gitlab' AND deleted_at IS NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_github_installation_user_active;
DROP INDEX IF EXISTS idx_gitlab_account_user_active;

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM repository_connections
        WHERE deleted_at IS NULL
        GROUP BY user_id, provider, provider_account_id
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION 'cannot roll back multiple GitHub installations while duplicate account connections exist';
    END IF;
END $$;
-- +goose StatementEnd

CREATE UNIQUE INDEX IF NOT EXISTS idx_repository_connection_account_active
    ON repository_connections(user_id, provider, provider_account_id) WHERE deleted_at IS NULL;
