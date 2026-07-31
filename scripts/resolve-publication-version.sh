#!/bin/bash -p
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: resolve-publication-version.sh SHA" >&2
  exit 2
fi

release_sha="$1"
if [[ ! "${release_sha}" =~ ^[0-9a-f]{40}$ ]] || \
  ! git cat-file -e "${release_sha}^{commit}" 2>/dev/null; then
  echo "release SHA must identify a local Git commit" >&2
  exit 2
fi

release_tags=()
if ! tag_references="$(
  git for-each-ref \
    --format='%(refname:strip=2)|%(objecttype)|%(object)|%(type)' \
    refs/tags
)"; then
  printf 'could not enumerate release tags\n' >&2
  exit 1
fi
while IFS='|' read -r existing_tag reference_type target_object target_type; do
  if [[ "${existing_tag}" =~ ^v(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$ ]]; then
    if ! tag_commit="$(
      git rev-parse --verify "refs/tags/${existing_tag}^{commit}" 2>/dev/null
    )" || [[ "${tag_commit}" != "${release_sha}" ]]; then
      continue
    fi
    if [[ "${reference_type}" != "tag" ]]; then
      printf 'release tag must be annotated: %s\n' "${existing_tag}" >&2
      exit 1
    fi
    if [[ "${target_type}" != "commit" ]] || [[ "${target_object}" != "${release_sha}" ]]; then
      printf 'release tag must directly annotate the release commit: %s\n' \
        "${existing_tag}" >&2
      exit 1
    fi
    release_tags+=("${existing_tag}")
  fi
done <<< "${tag_references}"

if [[ "${#release_tags[@]}" -gt 1 ]]; then
  printf 'release SHA has multiple version tags: %s\n' "${release_tags[*]}" >&2
  exit 1
fi

release_tag="${release_tags[0]:-v0.0.0}"
if [[ "${#release_tags[@]}" -eq 0 ]]; then
  printf 'synthetic=true\n'
else
  printf 'synthetic=false\n'
fi
printf 'tag=%s\n' "${release_tag}"
printf 'version=%s\n' "${release_tag#v}"
