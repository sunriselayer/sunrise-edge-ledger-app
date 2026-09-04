#!/usr/bin/env bash
set -euo pipefail

# Build Ledger device artifacts in the digest-pinned reviewed official image.

readonly TARGET="${1:-all}"
readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly BUILDER_IMAGE="ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder@sha256:fdd23072692f779b92bd805e544264c1385b8f6a8546872db7b9735995d9583e"

if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required for the pinned Ledger device build" >&2
    exit 1
fi

build_target() {
    local target="$1"
    local artifact_dir="$REPO_ROOT/target/$target/release"
    local binary="$artifact_dir/sunrise-edge-ledger-app"
    local hex="$binary.hex"
    local apdu="$binary.apdu"

    docker run --rm \
        --volume "$REPO_ROOT:/app" \
        --workdir /app \
        "$BUILDER_IMAGE" \
        cargo ledger build "$target"

    for artifact in "$binary" "$hex" "$apdu"; do
        if [[ ! -s "$artifact" ]]; then
            echo "missing or empty Ledger artifact: $artifact" >&2
            exit 1
        fi
    done
    sha256sum "$binary" "$hex" "$apdu"
}

case "$TARGET" in
    all)
        for target in nanosplus nanox stax flex apex_p; do
            build_target "$target"
        done
        ;;
    nanosplus|nanox|stax|flex|apex_p)
        build_target "$TARGET"
        ;;
    *)
        echo "unsupported Ledger target: $TARGET" >&2
        exit 2
        ;;
esac
