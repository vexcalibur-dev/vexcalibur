# Publish To PyPI

Use this runbook to publish Vexcalibur from the automated release workflow. Do
not upload Vexcalibur with a local API token or password.

## Prerequisites

- You are on `main`, and `main` contains the commit to release.
- The release tag uses `vMAJOR.MINOR.PATCH`, for example `v0.1.0`.
- The `vexcalibur-dev` organization has the `AUTOMATION_ID` variable and
  `AUTOMATION_SECRET` secret available to this repository. These identify a
  GitHub App named `vexcalibur-dev-automation`, installed on
  `vexcalibur-dev/vexcalibur` with Contents read/write permission so the release
  workflow can create tags and GitHub Releases. PyPI publishing verifies that
  GitHub Releases are authored by `vexcalibur-dev-automation[bot]`.
- Anyone who can manually dispatch the `Release` workflow is trusted to publish
  a GitHub Release and trigger the PyPI publishing workflow.
- If the GitHub `pypi` environment is protected, you can approve or request the
  required approval for that environment.
- You have PyPI maintainer or owner rights for configuring Trusted Publishing
  and yanking a bad release.
- The PyPI project or pending publisher is configured for:
  - project `vexcalibur`
  - repository `vexcalibur-dev/vexcalibur`
  - workflow `pypi.yml`
  - environment `pypi`
- The GitHub `pypi` environment exists. It should not contain a PyPI token; the
  workflow uses PyPI Trusted Publishing.
- Local release preflight requires `uv`, `actionlint`, and `shellcheck` on
  `PATH`. Their versions are pinned in `.tool-versions`; install or activate
  them with a `.tool-versions`-compatible tool manager such as `mise` or `asdf`,
  or with direct package installs that provide the pinned versions.

PyPI can create a project from a pending Trusted Publisher on the first publish.
A pending publisher does not reserve the project name until the first upload
succeeds.

## Preflight

Start from a clean, current checkout:

```bash
git fetch origin main --tags
git switch main
git pull --ff-only origin main
git status --short
```

Run the local gates:

```bash
actionlint -version
shellcheck --version
uv lock --check
uv sync --frozen --extra docs
uv run --frozen ruff format --check src tests scripts/*.py docs/conf.py
uv run --frozen ruff check src tests scripts/*.py docs/conf.py
uv run --frozen mypy src
make workflow-lint
uv run --frozen pytest -m "not live" --cov-fail-under=75
make docs
uv run --frozen pip-audit --cache-dir /tmp/vexcalibur-pip-audit-cache
make secrets
```

Build and inspect the release artifacts with a temporary local tag. Delete the
temporary tag before creating the real release tag. Use the release script output
so the local preflight checks the same version the workflow will publish.

```bash
release_metadata="$(scripts/next-release-tag.sh)"
printf '%s\n' "$release_metadata"

RELEASE_SKIP="$(printf '%s\n' "$release_metadata" | awk -F= '$1 == "skip" { print $2 }')"
RELEASE_TAG="$(printf '%s\n' "$release_metadata" | awk -F= '$1 == "tag" { print $2 }')"

if [ "$RELEASE_SKIP" = "true" ]; then
  echo "The release workflow will skip this commit."
  exit 0
fi

RELEASE_VERSION=${RELEASE_TAG#v}
DIST_DIR=/tmp/vexcalibur-dist

if git rev-parse --verify --quiet "refs/tags/$RELEASE_TAG" >/dev/null &&
  [ "$(git rev-parse --verify "refs/tags/$RELEASE_TAG^{commit}")" != "$(git rev-parse HEAD)" ]; then
  echo "Local tag already exists: $RELEASE_TAG" >&2
  exit 1
fi

if git rev-parse --verify --quiet "refs/tags/$RELEASE_TAG" >/dev/null; then
  TEMP_TAG_CREATED=false
else
  git tag "$RELEASE_TAG"
  TEMP_TAG_CREATED=true
  trap 'git tag --delete "$RELEASE_TAG" >/dev/null 2>&1 || true' EXIT
fi

uv build --clear --no-create-gitignore --no-sources --out-dir "$DIST_DIR"
python scripts/verify-dist-metadata.py "$DIST_DIR" \
  --expected-name vexcalibur \
  --expected-version "$RELEASE_VERSION"
uv run --frozen twine check "$DIST_DIR"/*
VEXCALIBUR_WHEEL="$(find "$DIST_DIR" -maxdepth 1 -type f -name '*.whl')" \
  VEXCALIBUR_EXPECTED_VERSION="$RELEASE_VERSION" \
  make installed-cli-check
if [ "$TEMP_TAG_CREATED" = "true" ]; then
  git tag --delete "$RELEASE_TAG"
  trap - EXIT
fi
```

If the release tag already exists on `HEAD`, this preflight checks that tag
instead of recreating it. That matches the automation recovery path for an
existing tag whose GitHub Release was not created. Do not continue if any command
fails or if `git status --short` shows an unexpected tracked change.

## Publish

The preferred path is the `Release` workflow. It runs after pushes to `main`,
computes the next `vMAJOR.MINOR.PATCH` tag from Conventional Commits, runs
release quality gates against the exact release commit, creates an annotated tag
with the automation GitHub App, and publishes a GitHub Release. The first
automatic release is `v0.1.0`.

The workflow can also be started manually from GitHub Actions. Leave `version`
empty to compute the next version, or provide an explicit `MAJOR.MINOR.PATCH`
version such as `0.1.0`.

Automatic version bumps use these rules:

- `BREAKING CHANGE:` or a `!` marker in the Conventional Commit type creates a
  major release.
- `feat:` creates a minor release.
- `fix:`, `perf:`, `refactor:`, `deps:`, `build(deps):`, and `chore(deps):`
  create a patch release.
- `docs:`, `test:`, `ci:`, and ordinary `chore:` commits do not create a release
  by themselves after the first tag exists.
- `[skip release]` and `[release skip]` in the head commit skip automatic
  release creation.

The release workflow publishes the GitHub Release with generated release notes
after scanning those notes with `detect-secrets`. That release triggers
`.github/workflows/pypi.yml`. The PyPI workflow validates that the release was
created by the `vexcalibur-dev-automation` GitHub App, validates the tag format,
confirms the GitHub Release is not marked as a prerelease, confirms the tag
points at current `origin/main`, re-runs the quality, workflow lint, shell lint,
security, test, documentation, package build, and installed-wheel gates, verifies
both distribution metadata records match the tag, and publishes through the
`pypi` environment.

Pushing a tag alone does not publish to PyPI. Manually creating a GitHub Release
does not publish to PyPI because the publishing workflow rejects releases not
created by the automation app.

## Verify

After the `PyPI` workflow succeeds:

```bash
RELEASE_VERSION=0.1.0
python -m venv /tmp/vexcalibur-release-check
/tmp/vexcalibur-release-check/bin/python -m pip install "vexcalibur==$RELEASE_VERSION"
/tmp/vexcalibur-release-check/bin/python - <<'PY'
import importlib.metadata
import vexcalibur

print(importlib.metadata.version("vexcalibur"))
print(vexcalibur.__version__)
PY
```

Both printed versions must match the released version. Also check the PyPI
project page and the GitHub Release assets or workflow artifacts before
announcing the release.

## Mitigate A Bad Release

If a bad release was uploaded, prefer yanking the release instead of deleting it.
Yanking is PyPI's non-destructive mitigation for broken, incompatible, or
vulnerable releases.

1. Open `https://pypi.org/manage/project/vexcalibur/releases/`.
2. Open the bad version's `Options` menu.
3. Select `Yank`.
4. Enter a reason that downstream users can act on.
5. Confirm the release shows as yanked on PyPI.
6. Fix the problem and publish a higher version.
