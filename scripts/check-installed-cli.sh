#!/usr/bin/env bash
set -euo pipefail

poetry_bin="${POETRY:-poetry}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/vexcalibur-installed.XXXXXX")"

cleanup() {
  rm -rf "$work_dir"
}
trap cleanup EXIT

cd "$repo_root"

export POETRY_VIRTUALENVS_CREATE=true
export POETRY_VIRTUALENVS_IN_PROJECT=false
export POETRY_VIRTUALENVS_PATH="$work_dir/poetry-venvs"
export POETRY_CACHE_DIR="${POETRY_CACHE_DIR:-$work_dir/poetry-cache}"
export PYTHON_KEYRING_BACKEND="${PYTHON_KEYRING_BACKEND:-keyring.backends.null.Keyring}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$work_dir/cache}"
export PIP_DISABLE_PIP_VERSION_CHECK=1
unset VIRTUAL_ENV CONDA_PREFIX CONDA_DEFAULT_ENV CONDA_SHLVL

wheel="${VEXCALIBUR_WHEEL:-}"
if [[ -z "$wheel" ]]; then
  dist_dir="$work_dir/dist"
  "$poetry_bin" build --output "$dist_dir"
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

"$poetry_bin" install --only main --no-root
venv_dir="$("$poetry_bin" env info --path)"
"$venv_dir/bin/python" -m pip install --no-deps "$wheel"
VEXCALIBUR_BIN_DIR="$venv_dir/bin" "$venv_dir/bin/python" tests/integration/check_installed_cli.py
