#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

docker compose --profile dvwa --profile mock up -d --build
docker compose --profile test run --rm tests
python scripts/acceptance.py
