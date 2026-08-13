#!/usr/bin/env bash
set -euo pipefail

readonly fuzz_entrypoint="tests.fuzz.fuzz_boundaries"
readonly tracked_corpus="tests/fuzz/corpus"
readonly generated_corpus="${FUZZ_CORPUS_ROOT:-.fuzz-corpus}"
readonly artifact_root="${FUZZ_ARTIFACT_ROOT:-fuzz-artifacts}"

require_positive_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "${value}" =~ ^[1-9][0-9]*$ ]]; then
    printf '%s must be a positive integer, got %q\n' "${name}" "${value}" >&2
    exit 2
  fi
}

max_len="${FUZZ_MAX_LEN:-65536}"
per_input_timeout="${FUZZ_TIMEOUT_SECONDS:-5}"
rss_limit_mb="${FUZZ_RSS_LIMIT_MB:-2048}"
max_total_time="${FUZZ_MAX_TOTAL_TIME:-30}"

require_positive_integer FUZZ_MAX_LEN "${max_len}"
require_positive_integer FUZZ_TIMEOUT_SECONDS "${per_input_timeout}"
require_positive_integer FUZZ_RSS_LIMIT_MB "${rss_limit_mb}"
require_positive_integer FUZZ_MAX_TOTAL_TIME "${max_total_time}"
if ((max_len > 65536)); then
  printf 'FUZZ_MAX_LEN must be less than or equal to 65536, got %q\n' "${max_len}" >&2
  exit 2
fi

target_inventory="$(
  uv run --frozen --group fuzz python -m tests.fuzz.corpus_staging list-targets
)"
if [[ -z "${target_inventory}" ]]; then
  printf '%s\n' 'fuzz target inventory is empty' >&2
  exit 2
fi
mapfile -t all_targets <<<"${target_inventory}"
readonly -a all_targets

targets=("${all_targets[@]}")
if [[ -n "${FUZZ_TARGET:-}" ]]; then
  target_is_known=false
  for candidate in "${all_targets[@]}"; do
    if [[ "${FUZZ_TARGET}" == "${candidate}" ]]; then
      target_is_known=true
      break
    fi
  done
  if [[ "${target_is_known}" != true ]]; then
    printf 'FUZZ_TARGET must be one of: %s\n' "${all_targets[*]}" >&2
    exit 2
  fi
  targets=("${FUZZ_TARGET}")
fi

mkdir -p "${artifact_root}"
uv run --frozen --group fuzz python -m tests.fuzz.corpus_staging \
  stage "${tracked_corpus}" "${generated_corpus}"

for target in "${targets[@]}"; do
  corpus_dir="${generated_corpus}/${target}"
  artifact_dir="${artifact_root}/${target}"
  mkdir -p "${corpus_dir}" "${artifact_dir}"
  printf 'Fuzzing %s for %s seconds\n' "${target}" "${max_total_time}"
  FUZZ_TARGET="${target}" uv run --frozen --group fuzz python -m "${fuzz_entrypoint}" \
    "${corpus_dir}" \
    "-artifact_prefix=${artifact_dir}/" \
    "-max_len=${max_len}" \
    "-timeout=${per_input_timeout}" \
    "-rss_limit_mb=${rss_limit_mb}" \
    "-max_total_time=${max_total_time}" \
    -print_final_stats=1
done
