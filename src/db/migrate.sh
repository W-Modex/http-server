#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-$HOME/.config/modex-http/secrets.env}"

set -a
[ -f "$ENV_FILE" ] && source "$ENV_FILE"
set +a

: "${DATABASE_URL:?DATABASE_URL must be set}"

MIGRATIONS_DIR="${MIGRATIONS_DIR:-./src/db/migrations}"

psql "$DATABASE_URL" -v ON_ERROR_STOP=1 <<'EOF'
CREATE TABLE IF NOT EXISTS schema_migrations (
  version TEXT PRIMARY KEY
);
EOF

for file in "$MIGRATIONS_DIR"/*.sql; do
  [ -e "$file" ] || { echo "No migrations found in $MIGRATIONS_DIR"; break; }

  version="$(basename "$file")"

  if ! psql "$DATABASE_URL" -tAc \
    "SELECT 1 FROM schema_migrations WHERE version = '$version'" | grep -q 1; then
    echo "Applying $version"
    psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$file"
    psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c \
      "INSERT INTO schema_migrations(version) VALUES ('$version')"
  else
    echo "Skipping $version"
  fi
done