#!/usr/bin/env bash
set -euo pipefail

set -a
if [ -f /src/.env ]; then
  source <(tr -d '\r' < /src/.env)
fi
set +a

: "${DATABASE_URL:?DATABASE_URL must be set}"

# wait for db to be ready
until psql "$DATABASE_URL" -c "SELECT 1" >/dev/null 2>&1; do
  echo "Waiting for database..."
  sleep 1
done

./src/db/migrate.sh
exec ./build/server
