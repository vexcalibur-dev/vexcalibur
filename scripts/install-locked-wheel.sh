#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  printf 'usage: %s VENV_DIR WHEEL REQUIREMENTS_FILE\n' "$0" >&2
  exit 2
fi

uv_bin="${UV:-uv}"
python_bin="${PYTHON:-python3}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
venv_dir="$1"
wheel="$2"
requirements_file="$3"

if [[ ! -f "$wheel" ]]; then
  printf 'Vexcalibur wheel was not found: %s\n' "$wheel" >&2
  exit 2
fi
if ! command -v "$python_bin" >/dev/null 2>&1; then
  printf 'Python interpreter was not found: %s\n' "$python_bin" >&2
  exit 2
fi

cd "$repo_root"

"$uv_bin" export \
  --quiet \
  --frozen \
  --no-dev \
  --no-emit-project \
  --no-annotate \
  --output-file "$requirements_file"

wheel_uri="$(
  "$python_bin" -c \
    'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve(strict=True).as_uri())' \
    "$wheel"
)"
wheel_hash="$(sha256sum -- "$wheel" | awk '{print $1}')"
printf '\nvexcalibur @ %s \\\n' "$wheel_uri" >>"$requirements_file"
printf '    --hash=sha256:%s\n' "$wheel_hash" >>"$requirements_file"

"$uv_bin" venv "$venv_dir"
"$uv_bin" pip sync \
  --require-hashes \
  --python "$venv_dir/bin/python" \
  "$requirements_file"
