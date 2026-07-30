#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -lt 1 || "$#" -gt 5 ]]; then
  printf 'usage: %s DIST_DIR [EXPECTED_PYTHON [EXPECTED_VERSION [WHEEL_SHA256 [SDIST_SHA256]]]]\n' \
    "$0" >&2
  exit 2
fi

dist_dir="$1"
expected_python="${2:-}"
expected_version="${3:-}"
expected_wheel_sha256="${4:-}"
expected_sdist_sha256="${5:-}"

if [[ -z "$expected_python" ]]; then
  expected_python="$(python -I -c \
    'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
fi
if [[ -z "$expected_version" ]]; then
  expected_version="$(uv run --frozen python -I -c \
    'import importlib.metadata; print(importlib.metadata.version("vexcalibur"))')"
fi

uv run --frozen pytest -q \
  tests/test_execution_report_destination.py \
  tests/test_execution_report_destination_cli.py \
  tests/test_execution_report_destination_locks.py \
  tests/test_execution_report_hardening.py \
  tests/test_generation_output.py \
  tests/test_generation_output_concurrency.py \
  tests/test_cli_execution_report.py

shopt -s nullglob
wheels=("${dist_dir}"/*.whl)
sdists=("${dist_dir}"/*.tar.gz)
if [[ "${#wheels[@]}" -ne 1 ]]; then
  printf 'expected one wheel in %s, found %s\n' "$dist_dir" "${#wheels[@]}" >&2
  exit 2
fi
if [[ "${#sdists[@]}" -ne 1 ]]; then
  printf 'expected one sdist in %s, found %s\n' "$dist_dir" "${#sdists[@]}" >&2
  exit 2
fi

verify_digest() {
  local path="$1"
  local expected="$2"
  local role="$3"
  local actual

  if [[ -z "$expected" ]]; then
    return
  fi
  if [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then
    printf 'expected %s digest is not a lowercase SHA-256\n' "$role" >&2
    exit 2
  fi
  actual="$(python -I -c \
    'import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' \
    "$path")"
  if [[ "$actual" != "$expected" ]]; then
    printf '%s digest did not match the canonical build\n' "$role" >&2
    exit 2
  fi
}

verify_digest "${wheels[0]}" "$expected_wheel_sha256" "wheel"
verify_digest "${sdists[0]}" "$expected_sdist_sha256" "sdist"

for distribution in "${wheels[0]}" "${sdists[0]}"; do
  VEXCALIBUR_DISTRIBUTION="$distribution" \
    VEXCALIBUR_EXPECTED_PYTHON="$expected_python" \
    VEXCALIBUR_EXPECTED_VERSION="$expected_version" \
    make installed-cli-check
done
