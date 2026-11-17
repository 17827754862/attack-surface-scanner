#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

BUNDLE_DIR="${1:-offline-bundle}"

if [ ! -f "$BUNDLE_DIR/SHA256SUMS" ]; then
  echo "Missing $BUNDLE_DIR/SHA256SUMS" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64) ;;
  *)
    echo "This bundle currently supports AMD64 only; host is $(uname -m)." >&2
    exit 1
    ;;
esac

(
  cd "$BUNDLE_DIR"
  sha256sum -c SHA256SUMS
)
docker load -i "$BUNDLE_DIR/images.tar"
if [ -f "$BUNDLE_DIR/openvas.tar" ]; then
  docker load -i "$BUNDLE_DIR/openvas.tar"
fi

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example; change default credentials."
fi

docker compose --profile dvwa --profile mock up -d --no-build
echo "Frontend: http://127.0.0.1:3000"
