# Backup and restore

Treat the database and `.env` as one recovery set. The database dump contains customer data; `.env`
contains the encryption key required to read encrypted integration credentials. Store both encrypted,
restrict access, and keep a copy outside the host.

## Create a backup

Run from the AppGuard deployment directory:

```sh
umask 077
stamp=$(date +%Y%m%d-%H%M%S)
docker compose -f docker-compose.prod.yml exec -T db \
  sh -lc 'pg_dump -Fc -U "$POSTGRES_USER" "$POSTGRES_DB"' \
  > "appguard-${stamp}.dump"
cp .env "appguard-${stamp}.env"
chmod 600 "appguard-${stamp}.dump" "appguard-${stamp}.env"
```

Copy both files to encrypted off-host storage. Verify that the dump is non-empty and that the
matching `.env` contains the same encryption key and domain configuration as the running instance.

## Restore to a recovery instance

Use an isolated AppGuard deployment with the same release and a fresh database. Restore the matching
`.env` first, then load the database dump:

```sh
docker compose -f docker-compose.prod.yml stop frontend backend
docker compose -f docker-compose.prod.yml exec -T db \
  sh -lc 'pg_restore --clean --if-exists --no-owner -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  < appguard-YYYYMMDD-HHMMSS.dump
docker compose -f docker-compose.prod.yml up -d
```

Confirm `/health`, sign in, and verify that encrypted integration settings can be read. Do not
overwrite a live database with a restore until the recovery copy has been checked in isolation.

## Upgrade behavior

`scripts/upgrade.sh` now stops if the database is unavailable or its pre-upgrade dump fails. Use
`--no-backup` only when a separate, verified recovery copy exists and the risk is accepted. The
script's automatic dump is a rollback aid, not an off-host backup strategy.
