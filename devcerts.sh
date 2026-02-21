#!/usr/bin/env bash
set -euo pipefail

mkdir -p certs

openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout certs/dev-key.pem \
  -out certs/dev-cert.pem \
  -subj "/CN=localhost"

echo "Generated certs in ./certs (for local dev)" 