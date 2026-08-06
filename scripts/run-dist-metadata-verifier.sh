#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
uv_bin="${UV:-uv}"

cd "$repo_root"
exec "$uv_bin" run \
  --isolated \
  --frozen \
  --only-group dist-verify \
  python -I -c '
import runpy
import sys
from pathlib import Path

repo_root = Path.cwd().resolve()
sys.path.insert(0, str(repo_root / "scripts"))
runpy.run_path(
    str(repo_root / "scripts" / "verify-dist-metadata.py"),
    run_name="__main__",
)
' "$@"
