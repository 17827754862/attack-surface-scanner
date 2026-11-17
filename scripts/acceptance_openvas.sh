#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

docker compose -f docker-compose.yml -f docker-compose.full.yml \
  --profile full --profile dvwa --profile mock up -d
python scripts/verify_openvas.py
