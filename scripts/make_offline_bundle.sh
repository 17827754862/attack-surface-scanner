#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

BUNDLE_DIR="${1:-offline-bundle}"
mkdir -p "$BUNDLE_DIR"

docker compose --profile dvwa --profile mock build
images="$(
  docker compose --profile dvwa --profile mock config --images \
    | grep -vE '(^|/)immauss/openvas:' \
    | sort -u
)"

printf '%s\n' "$images" > "$BUNDLE_DIR/images.txt"
docker save -o "$BUNDLE_DIR/images.tar" $images
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$BUNDLE_DIR/VERSION"
printf 'architecture=amd64\nopenvas_included=false\nfeatures=memory,ai-analysis,bilingual-ui,risk-groups,auth-profiles,no-deadline,active-validation,oast\n' >> "$BUNDLE_DIR/VERSION"

(
  cd "$BUNDLE_DIR"
  sha256sum images.tar images.txt VERSION > SHA256SUMS
)

echo "Offline bundle created: $BUNDLE_DIR"
