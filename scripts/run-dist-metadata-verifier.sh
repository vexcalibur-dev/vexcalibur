#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
uv_bin="${UV:-uv}"

cd "$repo_root"
exec "$uv_bin" run \
  --isolated \
  --frozen \
  --only-group dist-verify \
  python -I scripts/verify-dist-metadata.py "$@"
