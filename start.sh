#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: Docker is not installed or not on PATH." >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "Error: Docker Compose v2 is required." >&2
  exit 1
fi

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example. Change passwords before exposing this host."
fi

API_PORT="$(sed -n 's/^API_PORT=//p' .env | tail -n 1)"
FRONTEND_PORT="$(sed -n 's/^FRONTEND_PORT=//p' .env | tail -n 1)"
DVWA_PORT="$(sed -n 's/^DVWA_PORT=//p' .env | tail -n 1)"
MOCK_HTTP_PORT="$(sed -n 's/^MOCK_HTTP_PORT=//p' .env | tail -n 1)"
OPENVAS_ENABLED="$(sed -n 's/^OPENVAS_ENABLED=//p' .env | tail -n 1)"
VAS_LAUNCHER="$(sed -n 's/^VAS_LAUNCHER=//p' .env | tail -n 1)"
API_PORT="${API_PORT:-8000}"
FRONTEND_PORT="${FRONTEND_PORT:-3000}"
DVWA_PORT="${DVWA_PORT:-8081}"
MOCK_HTTP_PORT="${MOCK_HTTP_PORT:-18000}"
OPENVAS_ENABLED="${OPENVAS_ENABLED:-false}"

if [ "$OPENVAS_ENABLED" = "true" ]; then
  echo "OpenVAS is enabled; starting the full scanner profile."
  docker compose -f docker-compose.yml -f docker-compose.full.yml --profile full --profile dvwa --profile mock up -d --build
else
  docker compose --profile dvwa --profile mock up -d --build
fi

echo "Waiting for API health at http://127.0.0.1:${API_PORT}/health ..."
deadline=$(( $(date +%s) + 180 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if curl -fsS "http://127.0.0.1:${API_PORT}/health" >/dev/null 2>&1; then
    echo "Frontend: http://127.0.0.1:${FRONTEND_PORT}"
    echo "API docs: http://127.0.0.1:${API_PORT}/docs"
    echo "DVWA:     http://127.0.0.1:${DVWA_PORT} (admin/password)"
    echo "Mock:     http://127.0.0.1:${MOCK_HTTP_PORT} (container target http://mock:8000)"
    if [ "$OPENVAS_ENABLED" = "true" ]; then
      echo "OpenVAS:  internal GMP service openvas:9390"
    fi
    echo "Login with ADMIN_USERNAME/ADMIN_PASSWORD from .env."
    echo "First DVWA visit may require Create/Reset Database."
    if [ -n "${VAS_LAUNCHER:-}" ]; then
      echo "Starting VAS launcher: ${VAS_LAUNCHER}"
      case "$VAS_LAUNCHER" in
        http://*|https://*)
          if command -v xdg-open >/dev/null 2>&1; then
            nohup xdg-open "$VAS_LAUNCHER" >/dev/null 2>&1 &
          elif command -v open >/dev/null 2>&1; then
            nohup open "$VAS_LAUNCHER" >/dev/null 2>&1 &
          fi
          ;;
        *)
          nohup sh -c "$VAS_LAUNCHER" >/dev/null 2>&1 &
          echo $! > .vas-launcher.pid
          ;;
      esac
    fi
    exit 0
  fi
  sleep 3
done

echo "API did not become healthy in 180 seconds." >&2
docker compose ps >&2
echo "Run: docker compose logs --tail=200 backend worker" >&2
exit 1
