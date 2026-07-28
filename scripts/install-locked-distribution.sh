#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  printf 'usage: %s VENV_DIR DISTRIBUTION REQUIREMENTS_FILE\n' "$0" >&2
  exit 2
fi

uv_bin="${UV:-uv}"
python_request="${PYTHON:-${UV_PYTHON:-${VEXCALIBUR_EXPECTED_PYTHON:-}}}"
python_find_args=()
if [[ -n "${python_request}" ]]; then
  python_find_args+=("${python_request}")
fi
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
venv_dir="$1"
distribution="$2"
requirements_file="$3"
build_root=

cleanup() {
  if [[ -n "${build_root}" ]]; then
    rm -rf -- "${build_root}"
  fi
}
trap cleanup EXIT

if [[ ! -f "$distribution" ]]; then
  printf 'Vexcalibur distribution was not found: %s\n' "$distribution" >&2
  exit 2
fi
if ! python_bin="$("$uv_bin" python find "${python_find_args[@]}")"; then
  printf 'Python interpreter was not found for request: %s\n' \
    "${python_request:-project default}" >&2
  exit 2
fi

cd "$repo_root"

if [[ "${distribution}" == *.tar.gz ]]; then
  build_root="$(mktemp -d "${TMPDIR:-/tmp}/vexcalibur-sdist-build.XXXXXXXX")"
  build_venv="${build_root}/venv"
  build_requirements="${build_root}/requirements.txt"
  wheel_dir="${build_root}/wheel"

  "$uv_bin" export \
    --quiet \
    --frozen \
    --only-group sdist-build \
    --no-emit-project \
    --no-annotate \
    --output-file "$build_requirements"
  "$uv_bin" venv --python "$python_bin" "$build_venv"
  "$uv_bin" pip sync \
    --require-hashes \
    --only-binary :all: \
    --python "$build_venv/bin/python" \
    "$build_requirements"
  mkdir -- "$wheel_dir"
  VIRTUAL_ENV="$build_venv" "$uv_bin" build \
    --wheel \
    --no-build-isolation \
    --offline \
    --python "$build_venv/bin/python" \
    --out-dir "$wheel_dir" \
    "$distribution"

  shopt -s nullglob
  built_wheels=("$wheel_dir"/*.whl)
  shopt -u nullglob
  if [[ "${#built_wheels[@]}" -ne 1 ]]; then
    printf 'expected one wheel built from %s, found %d\n' \
      "$distribution" "${#built_wheels[@]}" >&2
    exit 1
  fi
  distribution="${built_wheels[0]}"
fi

"$uv_bin" export \
  --quiet \
  --frozen \
  --no-dev \
  --no-emit-project \
  --no-annotate \
  --output-file "$requirements_file"

"$python_bin" scripts/append_locked_distribution_requirement.py \
  "$distribution" \
  "$requirements_file"

"$uv_bin" venv --python "$python_bin" "$venv_dir"
"$uv_bin" pip sync \
  --require-hashes \
  --only-binary :all: \
  --python "$venv_dir/bin/python" \
  "$requirements_file"
