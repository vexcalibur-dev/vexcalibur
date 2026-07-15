#!/usr/bin/env bash
set -euo pipefail

uv_bin="${UV:-uv}"
node_bin="${NODE:-node}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/vexcalibur-csaf-installed.XXXXXX")"
validator="$repo_root/tests/integration/csaf-validator/validate.mjs"

cleanup() {
  rm -rf "$work_dir"
}
trap cleanup EXIT

cd "$repo_root"

export UV_CACHE_DIR="${UV_CACHE_DIR:-$work_dir/uv-cache}"
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$work_dir/cache}"
export PIP_DISABLE_PIP_VERSION_CHECK=1
unset VIRTUAL_ENV CONDA_PREFIX CONDA_DEFAULT_ENV CONDA_SHLVL

if [[ ! -d "$repo_root/tests/integration/csaf-validator/node_modules" ]]; then
  printf '%s\n' 'CSAF validator dependencies are missing; run make csaf-validator-install.' >&2
  exit 2
fi

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
"$repo_root/scripts/install-locked-wheel.sh" \
  "$venv_dir" \
  "$wheel" \
  "$work_dir/runtime-requirements.txt"

output_path="$work_dir/acme-vex-2026-001.json"
"$venv_dir/bin/vexcalibur" generate \
  tests/fixtures/sbom/cyclonedx-json-simple.json \
  --findings-file tests/fixtures/findings/all-analysis-states.json \
  --offline \
  --format csaf \
  --csaf-version 2.0 \
  --csaf-document-id ACME-VEX-2026-001 \
  --csaf-document-title "ACME component exploitability assessment" \
  --csaf-publisher-name "ACME Product Security" \
  --csaf-publisher-namespace https://security.example.com \
  --csaf-publisher-category vendor \
  --csaf-document-status final \
  --timestamp 2026-07-15T00:00:00Z \
  --output "$output_path"

"$node_bin" "$validator" "$output_path"
"$venv_dir/bin/python" tests/integration/check_installed_csaf.py "$output_path"

negative_stdout="$work_dir/missing-metadata.stdout"
negative_stderr="$work_dir/missing-metadata.stderr"
set +e
"$venv_dir/bin/vexcalibur" generate \
  tests/fixtures/sbom/cyclonedx-json-simple.json \
  --findings-file tests/fixtures/findings/all-analysis-states.json \
  --offline \
  --format csaf \
  >"$negative_stdout" 2>"$negative_stderr"
negative_status=$?
set -e

if [[ $negative_status -ne 1 ]]; then
  printf 'missing CSAF metadata returned %s instead of 1\n' "$negative_status" >&2
  cat "$negative_stderr" >&2
  exit 1
fi
if [[ -s "$negative_stdout" ]]; then
  printf '%s\n' 'missing CSAF metadata unexpectedly wrote to stdout' >&2
  cat "$negative_stdout" >&2
  exit 1
fi
if ! grep -Fq -- '--csaf-document-id' "$negative_stderr" || \
  ! grep -Fq -- 'required with --format csaf' "$negative_stderr"; then
  printf '%s\n' 'missing CSAF metadata did not report required CSAF options' >&2
  cat "$negative_stderr" >&2
  exit 1
fi
if grep -Fq 'Traceback' "$negative_stderr"; then
  printf '%s\n' 'missing CSAF metadata emitted a traceback' >&2
  cat "$negative_stderr" >&2
  exit 1
fi
