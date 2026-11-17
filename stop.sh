#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

VAS_STOPPER=""
if [ -f .env ]; then
  VAS_STOPPER="$(sed -n 's/^VAS_STOPPER=//p' .env | tail -n 1)"
fi

if [ -n "${VAS_STOPPER:-}" ]; then
  sh -c "$VAS_STOPPER"
elif [ -f .vas-launcher.pid ]; then
  kill "$(cat .vas-launcher.pid)" >/dev/null 2>&1 || true
fi
rm -f .vas-launcher.pid

docker compose -f docker-compose.yml -f docker-compose.full.yml --profile dvwa --profile mock --profile full down
