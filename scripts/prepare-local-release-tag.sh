#!/bin/bash -p
set -euo pipefail

if [[ "$#" -ne 3 ]]; then
  echo "usage: prepare-local-release-tag.sh TAG SHA SCM_PYTHON" >&2
  exit 2
fi

release_tag="$1"
release_sha="$2"
scm_python="$3"

if [[ ! "${release_tag}" =~ ^v(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$ ]]; then
  echo "release tag must be a bounded vMAJOR.MINOR.PATCH value" >&2
  exit 2
fi
if [[ ! "${release_sha}" =~ ^[0-9a-f]{40}$ ]] || \
  ! git cat-file -e "${release_sha}^{commit}" 2>/dev/null; then
  echo "release SHA must identify a local Git commit" >&2
  exit 2
fi
if [[ ! -x "${scm_python}" ]]; then
  echo "SCM Python must be an executable file" >&2
  exit 2
fi
if [[ "$(git rev-parse --verify HEAD)" != "${release_sha}" ]]; then
  echo "release SHA must be the checked-out commit" >&2
  exit 2
fi

set +e
existing_tags="$(git tag --points-at "${release_sha}")"
tag_enumeration_status="$?"
set -e
if [[ "${tag_enumeration_status}" -ne 0 ]]; then
  echo "could not enumerate tags on the release SHA" >&2
  exit 1
fi

competing_tags=()
while IFS= read -r existing_tag; do
  if [[ "${existing_tag}" =~ ^v(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$ ]] && \
    [[ "${existing_tag}" != "${release_tag}" ]]; then
    competing_tags+=("${existing_tag}")
  fi
done <<<"${existing_tags}"
if [[ "${#competing_tags[@]}" -ne 0 ]]; then
  printf 'release SHA already has competing version tag(s): %s\n' \
    "${competing_tags[*]}" >&2
  exit 1
fi

created_tag=false
set +e
existing_tag_ref="$(
  git rev-parse -q --verify "refs/tags/${release_tag}" 2>/dev/null
)"
existing_tag_status="$?"
set -e
if [[ "${existing_tag_status}" -eq 0 ]]; then
  if ! tag_sha="$(git rev-parse --verify "refs/tags/${release_tag}^{commit}")"; then
    echo "could not resolve existing release tag ${release_tag}" >&2
    exit 1
  fi
  if [[ "${tag_sha}" != "${release_sha}" ]]; then
    echo "release tag ${release_tag} already exists on ${tag_sha}, not ${release_sha}" >&2
    exit 1
  fi
elif [[ "${existing_tag_status}" -eq 1 ]] && [[ -z "${existing_tag_ref}" ]]; then
  git tag "${release_tag}" "${release_sha}"
  created_tag=true
else
  echo "could not inspect existing release tag ${release_tag}" >&2
  exit 1
fi

set +e
resolved_version="$(
  env \
    -u SETUPTOOLS_SCM_PRETEND_METADATA \
    -u SETUPTOOLS_SCM_PRETEND_VERSION \
    "${scm_python}" -c \
    "from setuptools_scm import get_version; print(get_version(root='.', local_scheme='no-local-version'))"
)"
resolve_status="$?"
set -e
expected_version="${release_tag#v}"
if [[ "${resolve_status}" -ne 0 ]] || [[ "${resolved_version}" != "${expected_version}" ]]; then
  if [[ "${created_tag}" = true ]]; then
    git tag --delete "${release_tag}" >/dev/null
  fi
  if [[ "${resolve_status}" -ne 0 ]]; then
    echo "setuptools-scm could not resolve the release version" >&2
  else
    printf 'setuptools-scm resolved %s, expected %s\n' \
      "${resolved_version}" "${expected_version}" >&2
  fi
  exit 1
fi
