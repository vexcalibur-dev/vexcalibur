#!/bin/bash -p
set -euo pipefail

if [[ "$#" -ne 0 ]]; then
  echo "usage: check-immutable-release-policy.sh" >&2
  exit 2
fi

if [[ ! "${GITHUB_REPOSITORY:-}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "GITHUB_REPOSITORY must identify one GitHub repository." >&2
  exit 2
fi
if [[ -z "${RUNNER_TEMP:-}" ]] || [[ ! -d "${RUNNER_TEMP}" ]]; then
  echo "RUNNER_TEMP must identify an existing directory." >&2
  exit 2
fi

policy_dir="$(mktemp -d "${RUNNER_TEMP}/immutable-release-policy.XXXXXX")"
chmod 700 "${policy_dir}"
cleanup() {
  rm -rf -- "${policy_dir}"
}
trap cleanup EXIT

policy_path="${policy_dir}/response.json"
policy_error="${policy_dir}/request.error"
if ! gh api \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2026-03-10' \
  "repos/${GITHUB_REPOSITORY}/immutable-releases" \
  > "${policy_path}" 2> "${policy_error}"; then
  echo "Could not verify the repository immutable-release policy." >&2
  sed -n '1,5p' "${policy_error}" >&2
  exit 1
fi

if ! jq -e '.enabled == true and .enforced_by_owner == true' \
  "${policy_path}" >/dev/null; then
  echo "Immutable releases are not enabled and owner-enforced for this repository." >&2
  exit 1
fi
