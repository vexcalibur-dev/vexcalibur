#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 5 || $# -gt 6 ]]; then
  printf 'usage: %s WHEEL REVIEW FINDINGS OUTPUT_DIR RELEASE_SHA [--allow-synthetic]\n' "$0" >&2
  exit 2
fi

wheel="$1"
review="$2"
findings="$3"
output_dir="$4"
release_sha="$5"
synthetic_option="${6:-}"

if [[ -n "$synthetic_option" && "$synthetic_option" != "--allow-synthetic" ]]; then
  printf 'unknown option: %s\n' "$synthetic_option" >&2
  exit 2
fi

uv_bin="${UV:-uv}"
python_bin="${PYTHON:-python3}"
node_bin="${NODE:-node}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
helper="$repo_root/scripts/release_evidence.py"

for input_file in "$wheel" "$review" "$findings"; do
  if [[ ! -f "$input_file" || -L "$input_file" ]]; then
    printf 'expected a regular, non-symlink input file: %s\n' "$input_file" >&2
    exit 2
  fi
done
if [[ -e "$output_dir" || -L "$output_dir" ]]; then
  printf 'output directory already exists: %s\n' "$output_dir" >&2
  exit 2
fi
if [[ ! "$release_sha" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'release SHA must be a lowercase 40-character Git commit\n' >&2
  exit 2
fi

wheel="$("$python_bin" -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve(strict=True))' "$wheel")"
review="$("$python_bin" -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve(strict=True))' "$review")"
findings="$("$python_bin" -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve(strict=True))' "$findings")"
wheel_sha256_before="$(sha256sum -- "$wheel" | awk '{print $1}')"

cd "$repo_root"
head_sha="$(git rev-parse --verify HEAD)"
if [[ "$head_sha" != "$release_sha" ]]; then
  printf 'release SHA %s does not match checked-out HEAD %s\n' "$release_sha" "$head_sha" >&2
  exit 1
fi

source_tree_clean=true
if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  source_tree_clean=false
  if [[ "${VEXCALIBUR_EVIDENCE_ALLOW_DIRTY:-0}" != "1" ]]; then
    printf 'release evidence requires a clean source tree\n' >&2
    exit 1
  fi
  printf 'warning: generating non-publishable evidence from an explicitly allowed dirty tree\n' >&2
fi

commit_epoch="$(git show -s --format=%ct "$release_sha")"
if [[ ! "$commit_epoch" =~ ^[0-9]+$ ]]; then
  printf 'release commit has an invalid timestamp: %s\n' "$commit_epoch" >&2
  exit 1
fi
if [[ -n "${SOURCE_DATE_EPOCH:-}" && "$SOURCE_DATE_EPOCH" != "$commit_epoch" ]]; then
  printf 'SOURCE_DATE_EPOCH %s does not match release commit epoch %s\n' \
    "$SOURCE_DATE_EPOCH" "$commit_epoch" >&2
  exit 1
fi
export SOURCE_DATE_EPOCH="$commit_epoch"

pinned_uv_version="$(awk '$1 == "uv" {print $2}' .tool-versions)"
actual_uv_version="$("$uv_bin" --version | awk '{print $2}')"
if [[ -z "$pinned_uv_version" || "$actual_uv_version" != "$pinned_uv_version" ]]; then
  printf 'uv version %s does not match pinned version %s\n' \
    "$actual_uv_version" "$pinned_uv_version" >&2
  exit 1
fi

"$uv_bin" run --frozen python "$helper" validate-wheel \
  --wheel "$wheel" \
  --release-sha "$release_sha" >/dev/null

temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/vexcalibur-release-evidence.XXXXXX")"
chmod 700 "$temporary_root"
staging_dir=""
cleanup() {
  if [[ -n "$staging_dir" && -d "$staging_dir" ]]; then
    rm -rf -- "$staging_dir"
  fi
  if [[ -d "$temporary_root" ]]; then
    rm -rf -- "$temporary_root"
  fi
}
trap cleanup EXIT

output_parent="$(dirname "$output_dir")"
mkdir -p "$output_parent"
staging_dir="$(mktemp -d "$output_parent/.release-evidence.XXXXXX")"

venv_dir="$temporary_root/venv"
install_requirements="$temporary_root/install-requirements.txt"
scripts/install-locked-wheel.sh "$venv_dir" "$wheel" "$install_requirements"
installed_python="$venv_dir/bin/python"
installed_cli="$venv_dir/bin/vexcalibur"

env -u PYTHONPATH -u PYTHONHOME "$installed_python" -c \
  'from pathlib import Path; import sys, vexcalibur; root=Path(sys.argv[1]).resolve(); module=Path(vexcalibur.__file__).resolve(); assert module.is_relative_to(root), (module, root)' \
  "$venv_dir"
release_version="$(env -u PYTHONPATH -u PYTHONHOME "$installed_python" -c \
  'from importlib.metadata import version; print(version("vexcalibur"))')"
release_timestamp="$(env -u PYTHONPATH -u PYTHONHOME "$installed_python" "$helper" \
  timestamp --epoch "$SOURCE_DATE_EPOCH")"

review_arguments=()
if [[ "$synthetic_option" == "--allow-synthetic" ]]; then
  review_arguments+=(--allow-synthetic)
fi
review_result="$(env -u PYTHONPATH -u PYTHONHOME "$installed_python" "$helper" \
  validate-review \
  --review "$review" \
  --findings "$findings" \
  --lock "$repo_root/uv.lock" \
  "${review_arguments[@]}")"
IFS=$'\t' read -r review_kind assertion_count <<<"$review_result"
if [[ "$review_kind" == "synthetic_fixture" && "$synthetic_option" != "--allow-synthetic" ]]; then
  printf 'synthetic review was not explicitly enabled\n' >&2
  exit 1
fi
if [[ ! "$assertion_count" =~ ^[0-9]+$ ]]; then
  printf 'review validator returned an invalid assertion count: %s\n' "$assertion_count" >&2
  exit 1
fi

cp -- "$review" "$staging_dir/review.json"
cp -- "$findings" "$staging_dir/findings.json"

"$uv_bin" export \
  --quiet \
  --frozen \
  --no-dev \
  --no-emit-project \
  --no-annotate \
  --no-header \
  --output-file "$staging_dir/runtime-constraints.txt"

raw_sbom="$temporary_root/uv-export.cdx.json"
"$uv_bin" export \
  --quiet \
  --preview-features sbom-export \
  --format cyclonedx1.5 \
  --frozen \
  --no-dev \
  --output-file "$raw_sbom"
lock_sha256="$(sha256sum -- uv.lock | awk '{print $1}')"
env -u PYTHONPATH -u PYTHONHOME "$installed_python" "$helper" normalize-sbom \
  --input "$raw_sbom" \
  --output "$staging_dir/sbom.cdx.json" \
  --release-version "$release_version" \
  --timestamp "$release_timestamp" \
  --lock-sha256 "$lock_sha256"
"$uv_bin" run --frozen python "$helper" validate-cyclonedx \
  --document "$staging_dir/sbom.cdx.json" \
  --spec-version 1.5

runtime_dir="$temporary_root/runtime"
mkdir "$runtime_dir"
(
  cd "$runtime_dir"
  env -u PYTHONPATH -u PYTHONHOME \
    HTTP_PROXY="http://127.0.0.1:9" \
    HTTPS_PROXY="http://127.0.0.1:9" \
    ALL_PROXY="http://127.0.0.1:9" \
    NO_PROXY="" \
    "$installed_cli" generate \
    "$staging_dir/sbom.cdx.json" \
    --findings-file "$staging_dir/findings.json" \
    --offline \
    --timestamp "$release_timestamp" \
    --output "$staging_dir/vex.cdx.json"
)
"$uv_bin" run --frozen python "$helper" validate-cyclonedx \
  --document "$staging_dir/vex.cdx.json" \
  --spec-version 1.6

if (( assertion_count > 0 )); then
  (
    cd "$runtime_dir"
    env -u PYTHONPATH -u PYTHONHOME \
      HTTP_PROXY="http://127.0.0.1:9" \
      HTTPS_PROXY="http://127.0.0.1:9" \
      ALL_PROXY="http://127.0.0.1:9" \
      NO_PROXY="" \
      "$installed_cli" generate \
      "$staging_dir/sbom.cdx.json" \
      --findings-file "$staging_dir/findings.json" \
      --offline \
      --format openvex \
      --author "Vexcalibur maintainers" \
      --author-role "VEX issuer" \
      --timestamp "$release_timestamp" \
      --output "$staging_dir/vex.openvex.json"
  )
  (
    cd "$runtime_dir"
    env -u PYTHONPATH -u PYTHONHOME \
      HTTP_PROXY="http://127.0.0.1:9" \
      HTTPS_PROXY="http://127.0.0.1:9" \
      ALL_PROXY="http://127.0.0.1:9" \
      NO_PROXY="" \
      "$installed_cli" generate \
      "$staging_dir/sbom.cdx.json" \
      --findings-file "$staging_dir/findings.json" \
      --offline \
      --format csaf \
      --csaf-document-id "vexcalibur-vex" \
      --csaf-document-title "Vexcalibur release VEX" \
      --csaf-publisher-name "Vexcalibur maintainers" \
      --csaf-publisher-namespace "https://github.com/vexcalibur-dev/vexcalibur" \
      --csaf-publisher-category vendor \
      --csaf-document-status interim \
      --timestamp "$release_timestamp" \
      --output "$staging_dir/vexcalibur-vex.json"
  )

  go -C tests/integration/openvex-go run . "$staging_dir/vex.openvex.json"
  "$python_bin" -c \
    'from pathlib import Path; import sys; path=Path(sys.argv[1]); assert path.is_dir(), f"CSAF validator dependencies are not installed: {path}"' \
    tests/integration/csaf-validator/node_modules
  "$node_bin" tests/integration/csaf-validator/validate.mjs \
    "$staging_dir/vexcalibur-vex.json"
  env -u PYTHONPATH -u PYTHONHOME "$installed_python" "$helper" compare-formats \
    --cyclonedx "$staging_dir/vex.cdx.json" \
    --openvex "$staging_dir/vex.openvex.json" \
    --csaf "$staging_dir/vexcalibur-vex.json"
else
  if [[ -e "$staging_dir/vex.openvex.json" || -e "$staging_dir/vexcalibur-vex.json" ]]; then
    printf 'zero-finding bundle unexpectedly contains OpenVEX or CSAF output\n' >&2
    exit 1
  fi
fi

if [[ "$(git rev-parse --verify HEAD)" != "$release_sha" ]]; then
  printf 'checked-out HEAD changed during evidence generation\n' >&2
  exit 1
fi
if [[ "$source_tree_clean" == "true" ]] && \
  [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  printf 'source tree changed during evidence generation\n' >&2
  exit 1
fi
wheel_sha256_after="$(sha256sum -- "$wheel" | awk '{print $1}')"
if [[ "$wheel_sha256_after" != "$wheel_sha256_before" ]]; then
  printf 'local wheel changed during evidence generation\n' >&2
  exit 1
fi

env -u PYTHONPATH -u PYTHONHOME "$installed_python" "$helper" finalize \
  --bundle-dir "$staging_dir" \
  --release-sha "$release_sha" \
  --release-version "$release_version" \
  --source-date-epoch "$SOURCE_DATE_EPOCH" \
  --lock "$repo_root/uv.lock" \
  --wheel "$wheel" \
  --review "$staging_dir/review.json" \
  --findings "$staging_dir/findings.json" \
  --uv-version "$actual_uv_version" \
  --source-tree-clean "$source_tree_clean"

if ! mv --no-clobber --no-target-directory -- "$staging_dir" "$output_dir"; then
  printf 'output directory appeared during evidence generation: %s\n' "$output_dir" >&2
  exit 1
fi
if [[ -d "$staging_dir" ]]; then
  printf 'output directory appeared during evidence generation: %s\n' "$output_dir" >&2
  exit 1
fi
staging_dir=""
printf 'release evidence written to %s\n' "$output_dir"
