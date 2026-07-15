#!/bin/bash -p
set -euo pipefail

if [[ "$#" -ne 3 ]]; then
  echo "usage: prepare-local-release-tag.sh TAG SHA SYNTHETIC_CI_VERSION" >&2
  exit 2
fi

release_tag="$1"
release_sha="$2"
synthetic_ci_version="$3"

if [[ ! "${release_tag}" =~ ^v(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$ ]]; then
  echo "release tag must be a bounded vMAJOR.MINOR.PATCH value" >&2
  exit 2
fi
if [[ ! "${release_sha}" =~ ^[0-9a-f]{40}$ ]] || \
  ! git cat-file -e "${release_sha}^{commit}" 2>/dev/null; then
  echo "release SHA must identify a local Git commit" >&2
  exit 2
fi
if [[ "${synthetic_ci_version}" != "true" && "${synthetic_ci_version}" != "false" ]]; then
  echo "synthetic CI version must be true or false" >&2
  exit 2
fi

if [[ "${synthetic_ci_version}" == "true" ]]; then
  if [[ "${release_tag}" != "v0.0.0" ]]; then
    echo "the synthetic CI version is restricted to v0.0.0" >&2
    exit 2
  fi
  mapfile -t local_tags < <(git tag --list)
  for local_tag in "${local_tags[@]}"; do
    git tag --delete -- "${local_tag}" >/dev/null
  done
  git tag "${release_tag}" "${release_sha}"
  exit 0
fi

if git rev-parse -q --verify "refs/tags/${release_tag}" >/dev/null; then
  tag_sha="$(git rev-parse --verify "refs/tags/${release_tag}^{commit}")"
  if [[ "${tag_sha}" != "${release_sha}" ]]; then
    echo "release tag ${release_tag} already exists on ${tag_sha}, not ${release_sha}" >&2
    exit 1
  fi
else
  git tag "${release_tag}" "${release_sha}"
fi
