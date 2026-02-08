#!/usr/bin/env bash
set -euo pipefail
set -a
. ~/.config/modex-http/secrets.env
set +a
exec ./build/server
