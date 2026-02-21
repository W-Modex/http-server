#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-$HOME/.config/modex-http/secrets.env}"

set -a
[ -f .env ] && source .env
[ -f "$ENV_FILE" ] && source "$ENV_FILE"
set +a

./src/db/migrate.sh
exec ./build/server