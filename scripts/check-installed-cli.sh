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

distribution="${VEXCALIBUR_DISTRIBUTION:-${VEXCALIBUR_WHEEL:-}}"
if [[ -n "${VEXCALIBUR_DISTRIBUTION:-}" && -n "${VEXCALIBUR_WHEEL:-}" &&
  "$VEXCALIBUR_DISTRIBUTION" != "$VEXCALIBUR_WHEEL" ]]; then
  printf 'VEXCALIBUR_DISTRIBUTION and VEXCALIBUR_WHEEL name different files\n' >&2
  exit 2
fi
if [[ -z "$distribution" ]]; then
  dist_dir="$work_dir/dist"
  "$uv_bin" build --clear --no-create-gitignore --no-sources --out-dir "$dist_dir"
  shopt -s nullglob
  wheels=("$dist_dir"/*.whl)
  shopt -u nullglob
  if [[ ${#wheels[@]} -ne 1 ]]; then
    printf 'expected exactly one wheel in %s, found %s\n' "$dist_dir" "${#wheels[@]}" >&2
    exit 2
  fi
  distribution="${wheels[0]}"
fi

if [[ ! -f "$distribution" ]]; then
  printf 'Vexcalibur distribution was not found: %s\n' "$distribution" >&2
  exit 2
fi

venv_dir="$work_dir/venv"
"$repo_root/scripts/install-locked-distribution.sh" \
  "$venv_dir" \
  "$distribution" \
  "$work_dir/runtime-requirements.txt"
VEXCALIBUR_BIN_DIR="$venv_dir/bin" "$venv_dir/bin/python" tests/integration/check_installed_cli.py
