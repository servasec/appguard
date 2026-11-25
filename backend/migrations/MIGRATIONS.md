# Migrations

Each migration is a versioned SQL file applied by [Goose](https://github.com/pressly/goose)
in sequential order when the backend starts.

## Mapping

| Migration | App version | Description |
|-----------|-------------|-------------|
| 001       | v1.0.0      | Initial schema, all tables and indexes |
| 002       | n/a        | Fix unique application-version index |
| 003       | n/a        | Track onboarding completion |
| 004       | n/a        | Add foreign keys |
| 005       | n/a        | Add soft delete support |
| 006       | n/a        | Issue tracker connections |
| 007       | n/a           | Per-application scanner integrations and scan association |
| 008       | n/a           | GitHub/GitLab repository connections, application mappings, and webhook delivery deduplication |
| 009       | n/a           | Allow multiple GitHub App installations per AppGuard user |

## Adding a new migration

```bash
make migrate-create NAME=describe_change
```

Edit the generated file, then rebuild and restart:

```bash
make dev       # development
make community # production
```

The migration runs automatically on startup.
