#!/usr/bin/env bash
set -euo pipefail

uv_bin="${UV:-uv}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/vexcalibur-installed.XXXXXX")"

cleanup() {
  rm -rf "$work_dir"
}
trap cleanup EXIT

cd "$repo_root"

export UV_CACHE_DIR="${UV_CACHE_DIR:-$work_dir/uv-cache}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$work_dir/cache}"
export PIP_DISABLE_PIP_VERSION_CHECK=1
unset VIRTUAL_ENV CONDA_PREFIX CONDA_DEFAULT_ENV CONDA_SHLVL

wheel="${VEXCALIBUR_WHEEL:-}"
if [[ -z "$wheel" ]]; then
  dist_dir="$work_dir/dist"
  "$uv_bin" build --clear --no-create-gitignore --no-sources --out-dir "$dist_dir"
  mapfile -t wheels < <(find "$dist_dir" -maxdepth 1 -type f -name "*.whl" | sort)
  if [[ ${#wheels[@]} -ne 1 ]]; then
    printf 'expected exactly one wheel in %s, found %s\n' "$dist_dir" "${#wheels[@]}" >&2
    exit 2
  fi
  wheel="${wheels[0]}"
fi

if [[ ! -f "$wheel" ]]; then
  printf 'Vexcalibur wheel was not found: %s\n' "$wheel" >&2
  exit 2
fi

venv_dir="$work_dir/venv"
"$uv_bin" venv "$venv_dir"
"$uv_bin" pip install --python "$venv_dir/bin/python" "$wheel"
VEXCALIBUR_BIN_DIR="$venv_dir/bin" "$venv_dir/bin/python" tests/integration/check_installed_cli.py
