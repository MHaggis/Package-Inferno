#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] PackageInferno pipeline start"
: > ./out/fetch_queue.ndjson || true

docker compose run --rm enumerator
docker compose run --rm fetcher
docker compose run --rm analyzer

echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] PackageInferno pipeline done"
