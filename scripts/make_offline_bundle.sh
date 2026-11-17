#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

BUNDLE_DIR="${1:-offline-bundle}"
INCLUDE_OPENVAS="${2:-false}"
mkdir -p "$BUNDLE_DIR"

docker compose --profile dvwa --profile mock build
images="$(
  docker compose --profile dvwa --profile mock config --images \
    | grep -vE '(^|/)immauss/openvas:' \
    | sort -u
)"

printf '%s\n' "$images" > "$BUNDLE_DIR/images.txt"
docker save -o "$BUNDLE_DIR/images.tar" $images
if [ "$INCLUDE_OPENVAS" = "true" ]; then
  docker image inspect immauss/openvas:26.07.27.01 >/dev/null 2>&1
  docker save -o "$BUNDLE_DIR/openvas.tar" immauss/openvas:26.07.27.01
else
  rm -f "$BUNDLE_DIR/openvas.tar"
fi
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$BUNDLE_DIR/VERSION"
printf 'architecture=amd64\nopenvas_included=%s\nfeatures=memory,ai-analysis,bilingual-ui,risk-groups,auth-profiles,no-deadline,active-validation,oast\n' "$INCLUDE_OPENVAS" >> "$BUNDLE_DIR/VERSION"

(
  cd "$BUNDLE_DIR"
  if [ "$INCLUDE_OPENVAS" = "true" ]; then
    sha256sum images.tar images.txt openvas.tar VERSION > SHA256SUMS
  else
    sha256sum images.tar images.txt VERSION > SHA256SUMS
  fi
)

echo "Offline bundle created: $BUNDLE_DIR"
