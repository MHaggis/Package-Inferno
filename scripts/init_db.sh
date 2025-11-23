#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "Initializing database schema..."
docker compose up -d db
sleep 3
docker compose run --rm init-db || true
