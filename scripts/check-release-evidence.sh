#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
wheel="${VEXCALIBUR_WHEEL:-}"

if [[ -z "$wheel" || ! -f "$wheel" || -L "$wheel" ]]; then
  printf 'VEXCALIBUR_WHEEL must name one regular, non-symlink wheel\n' >&2
  exit 2
fi

cd "$repo_root"
release_sha="$(git rev-parse --verify HEAD)"
temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/vexcalibur-release-evidence-check.XXXXXX")"
chmod 700 "$temporary_root"
cleanup() {
  if [[ -d "$temporary_root" ]]; then
    rm -rf -- "$temporary_root"
  fi
}
trap cleanup EXIT

scripts/generate-release-evidence.sh \
  "$wheel" \
  release-evidence/review.json \
  release-evidence/findings.json \
  "$temporary_root/production-one" \
  "$release_sha"
scripts/generate-release-evidence.sh \
  "$wheel" \
  release-evidence/review.json \
  release-evidence/findings.json \
  "$temporary_root/production-two" \
  "$release_sha"

diff --recursive --no-dereference \
  "$temporary_root/production-one" \
  "$temporary_root/production-two"
test ! -e "$temporary_root/production-one/vex.openvex.json"
test ! -e "$temporary_root/production-one/vexcalibur-vex.json"

scripts/generate-release-evidence.sh \
  "$wheel" \
  tests/fixtures/release-evidence/review.json \
  tests/fixtures/release-evidence/findings.json \
  "$temporary_root/synthetic-one" \
  "$release_sha" \
  --allow-synthetic
scripts/generate-release-evidence.sh \
  "$wheel" \
  tests/fixtures/release-evidence/review.json \
  tests/fixtures/release-evidence/findings.json \
  "$temporary_root/synthetic-two" \
  "$release_sha" \
  --allow-synthetic

diff --recursive --no-dereference \
  "$temporary_root/synthetic-one" \
  "$temporary_root/synthetic-two"

test -f "$temporary_root/synthetic-one/vex.cdx.json"
test -f "$temporary_root/synthetic-one/vex.openvex.json"
test -f "$temporary_root/synthetic-one/vexcalibur-vex.json"
python3 - "$temporary_root/production-one/manifest.json" \
  "$temporary_root/synthetic-one/manifest.json" <<'PY'
import json
import os
import sys
from pathlib import Path

production = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
synthetic = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
expected_clean = os.environ.get("VEXCALIBUR_EVIDENCE_ALLOW_DIRTY") != "1"
assert production["review"]["assertion_count"] == 0
assert production["formats"]["openvex"]["status"] == "omitted"
assert production["formats"]["csaf"]["status"] == "omitted"
assert production["intended_use"] == "release_evidence_candidate"
assert production["source_tree_clean"] is expected_clean
assert synthetic["review"]["assertion_count"] == 1
assert synthetic["validation"]["cross_format_assertion_equivalence"] == "passed"
assert synthetic["intended_use"] == "ci_conformance_only"
PY

printf 'release-evidence production and synthetic fixture checks passed\n'
