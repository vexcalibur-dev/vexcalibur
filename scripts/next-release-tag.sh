#!/usr/bin/env bash
set -euo pipefail

manual_version="${1:-}"
max_version_component=999999

breaking_pattern='^[a-zA-Z]+(\([^)]+\))?!:|^(BREAKING CHANGE|BREAKING-CHANGE):'
feature_pattern='^feat(\([^)]+\))?:'
patch_pattern='^(fix|perf|refactor|deps|revert)(\([^)]+\))?:|^(build|chore)\(deps\):|^Revert "'

emit() {
  local key="$1"
  local value="$2"

  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf '%s=%s\n' "${key}" "${value}" >> "${GITHUB_OUTPUT}"
  else
    printf '%s=%s\n' "${key}" "${value}"
  fi
}

normalize_version() {
  local value="$1"
  value="${value#v}"
  printf '%s\n' "${value}"
}

require_version() {
  local version="$1"

  if [[ ! "${version}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    printf 'version %q must be MAJOR.MINOR.PATCH without leading zeros\n' "${version}" >&2
    exit 1
  fi

  local major minor patch
  IFS=. read -r major minor patch <<< "${version}"
  for component in "${major}" "${minor}" "${patch}"; do
    if ((${#component} > 6)) || ((10#${component} > max_version_component)); then
      printf 'version component %q must be less than or equal to %s\n' "${component}" "${max_version_component}" >&2
      exit 1
    fi
  done
}

version_gt() {
  local left="$1"
  local right="$2"

  [[ "$(printf '%s\n%s\n' "${right}" "${left}" | sort -V | tail -n 1)" == "${left}" && "${left}" != "${right}" ]]
}

tag_commit() {
  local tag="$1"
  git rev-parse --verify "refs/tags/${tag}^{commit}"
}

require_direct_annotated_commit_tag() {
  local tag="$1"
  local target_type

  if [[ "$(git cat-file -t "refs/tags/${tag}")" != "tag" ]]; then
    printf 'release tag %q must be annotated\n' "${tag}" >&2
    exit 1
  fi
  target_type="$(git cat-file -p "refs/tags/${tag}" | sed -n '2s/^type //p')"
  if [[ "${target_type}" != "commit" ]]; then
    printf 'release tag %q must directly annotate a commit\n' "${tag}" >&2
    exit 1
  fi
}

classify_bump() {
  local messages="$1"

  if grep -Eiq "${breaking_pattern}" <<< "${messages}"; then
    printf 'major\n'
  elif grep -Eiq "${feature_pattern}" <<< "${messages}"; then
    printf 'minor\n'
  elif grep -Eiq "${patch_pattern}" <<< "${messages}"; then
    printf 'patch\n'
  else
    printf 'skip\n'
  fi
}

head_sha="$(git rev-parse HEAD)"
head_release_tags=()
if ! release_like_tags="$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*')"; then
  printf 'could not enumerate release tags\n' >&2
  exit 1
fi
while IFS= read -r release_like_tag; do
  if [[ "${release_like_tag}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    require_direct_annotated_commit_tag "${release_like_tag}"
    if [[ "$(tag_commit "${release_like_tag}")" == "${head_sha}" ]]; then
      require_version "$(normalize_version "${release_like_tag}")"
      head_release_tags+=("${release_like_tag}")
    fi
  fi
done <<< "${release_like_tags}"
if ((${#head_release_tags[@]} > 1)); then
  printf 'release SHA already has competing version tags: %s\n' \
    "${head_release_tags[*]}" >&2
  exit 1
fi

if ! merged_release_like_tags="$(
  git tag --merged HEAD --list 'v[0-9]*.[0-9]*.[0-9]*'
)"; then
  printf 'could not enumerate release tags merged into HEAD\n' >&2
  exit 1
fi
release_tags=()
while IFS= read -r merged_tag; do
  if [[ "${merged_tag}" =~ ^v(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$ ]]; then
    release_tags+=("${merged_tag}")
  fi
done <<< "${merged_release_like_tags}"
if ((${#release_tags[@]} > 0)); then
  if ! sorted_release_tags="$(printf '%s\n' "${release_tags[@]}" | sort -V)"; then
    printf 'could not sort release tags\n' >&2
    exit 1
  fi
  mapfile -t release_tags <<< "${sorted_release_tags}"
fi

latest_tag=""
previous_tag=""
if ((${#release_tags[@]} > 0)); then
  latest_tag="${release_tags[$((${#release_tags[@]} - 1))]}"
fi
if ((${#release_tags[@]} > 1)); then
  previous_tag="${release_tags[$((${#release_tags[@]} - 2))]}"
fi

if [[ -z "${manual_version}" ]] && [[ -n "${latest_tag}" ]] && [[ "$(tag_commit "${latest_tag}")" == "${head_sha}" ]]; then
  existing_version="$(normalize_version "${latest_tag}")"
  require_version "${existing_version}"
  emit skip false
  emit tag "${latest_tag}"
  emit version "${existing_version}"
  emit previous_tag "${previous_tag}"
  emit bump existing
  exit 0
fi

base_tag="${latest_tag}"
base_version="0.0.0"
if [[ -n "${base_tag}" ]]; then
  base_version="$(normalize_version "${base_tag}")"
fi
require_version "${base_version}"

if [[ -z "${manual_version}" ]]; then
  head_message="$(git log -1 --format=%B)"
  if grep -qiE '\[(skip release|release skip)\]' <<< "${head_message}"; then
    emit skip true
    emit tag ""
    emit version ""
    emit previous_tag "${base_tag}"
    emit bump skip
    exit 0
  fi
fi

if [[ -n "${manual_version}" ]]; then
  if ((${#head_release_tags[@]} > 0)); then
    printf 'manual version cannot add a second release tag to HEAD; existing tag: %s\n' \
      "${head_release_tags[0]}" >&2
    exit 1
  fi
  next_version="$(normalize_version "${manual_version}")"
  require_version "${next_version}"

  if ! version_gt "${next_version}" "${base_version}"; then
    printf 'manual version %s must be greater than base version %s\n' "${next_version}" "${base_version}" >&2
    exit 1
  fi

  emit skip false
  emit tag "v${next_version}"
  emit version "${next_version}"
  emit previous_tag "${base_tag}"
  emit bump manual
  exit 0
fi

if [[ -z "${base_tag}" ]]; then
  emit skip false
  emit tag "v0.1.0"
  emit version "0.1.0"
  emit previous_tag ""
  emit bump initial
  exit 0
fi

range="${base_tag}..HEAD"
messages="$(git log --format=%B "${range}")"
bump="$(classify_bump "${messages}")"
if [[ "${bump}" == "skip" ]]; then
  emit skip true
  emit tag ""
  emit version ""
  emit previous_tag "${base_tag}"
  emit bump skip
  exit 0
fi

IFS=. read -r major minor patch <<< "${base_version}"
case "${bump}" in
  major)
    next_version="$((major + 1)).0.0"
    ;;
  minor)
    next_version="${major}.$((minor + 1)).0"
    ;;
  patch)
    next_version="${major}.${minor}.$((patch + 1))"
    ;;
  *)
    printf 'unknown bump type %q\n' "${bump}" >&2
    exit 1
    ;;
esac
require_version "${next_version}"

emit skip false
emit tag "v${next_version}"
emit version "${next_version}"
emit previous_tag "${base_tag}"
emit bump "${bump}"
