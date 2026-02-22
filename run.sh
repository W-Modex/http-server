#!/usr/bin/env bash
set -euo pipefail

set -a
[ -f ./.env ] && source ./.env
set +a

./src/db/migrate.sh
exec ./build/server