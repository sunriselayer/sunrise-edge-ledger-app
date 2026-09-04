#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
dev_tools_image='ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools@sha256:414ebf2c4e62d3d20c319284f1715c4b1d975016c45b09b7fc8d6aaa5765eee4'

docker run --rm \
  --env PYTHONDONTWRITEBYTECODE=1 \
  --volume "${repo_root}:/app" \
  --workdir /app \
  "${dev_tools_image}" \
  sh -lc '
    python3 -m venv /tmp/sunrise-ragger
    /tmp/sunrise-ragger/bin/pip install --quiet \
      --disable-pip-version-check \
      --no-cache-dir \
      --require-hashes \
      --requirement tests/speculos/requirements.txt
    /tmp/sunrise-ragger/bin/pytest \
      tests/speculos \
      --tb=short \
      --verbose \
      -p no:cacheprovider \
      --device nanosp
  '
