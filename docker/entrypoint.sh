#!/usr/bin/env bash
set -euo pipefail

set -a
[ -f /app/.env ] && source /app/.env
set +a

: "${DATABASE_URL:?DATABASE_URL must be set}"

CERT_DIR="/app/certs"
CERT_KEY="$CERT_DIR/dev-key.pem"
CERT_CERT="$CERT_DIR/dev-cert.pem"

mkdir -p "$CERT_DIR"

if [ ! -f "$CERT_KEY" ] || [ ! -f "$CERT_CERT" ]; then
  echo "Generating self-signed HTTPS certificate..."
  openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
    -keyout "$CERT_KEY" \
    -out "$CERT_CERT" \
    -subj "/CN=localhost"
  echo "Certificate generated."
fi

until psql "$DATABASE_URL" -c "SELECT 1" >/dev/null 2>&1; do
  echo "Waiting for database..."
  sleep 1
done

/app/src/db/migrate.sh

exec /app/build/server