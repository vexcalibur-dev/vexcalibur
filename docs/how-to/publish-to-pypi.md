# Publish Vexcalibur to PyPI

Use the automated release path. Do not upload Vexcalibur with a local PyPI password or API token.

## Check release access

Before starting, confirm:

- `main` contains the commit to release.
- the `vexcalibur-dev-automation` GitHub App is installed on the repository with Contents read/write permission.
- the repository has `AUTOMATION_CLIENT_ID` and `AUTOMATION_SECRET` configured for that app.
- the GitHub `pypi` environment exists and contains no PyPI token.
- PyPI Trusted Publishing names project `vexcalibur`, repository `vexcalibur-dev/vexcalibur`, workflow `pypi.yml`, and environment `pypi`.
- you have the PyPI project access needed to yank a release if necessary.

Anyone who can dispatch the `Release` workflow can cause a GitHub Release and PyPI publication. Treat that permission as release access.

The `pypi` environment currently has no protection rules or required reviewers. Publication does not pause for an environment approval.

For local checks, install the `uv`, `actionlint`, and `shellcheck` versions from `.tool-versions`.

## Run the preflight

Start from a clean, current checkout:

```bash
git fetch origin main --tags
git switch main
git pull --ff-only origin main
git status --short
test -z "$(git status --porcelain)"
```

Stop if `git status --short` prints any tracked or untracked path, or if the final command fails.

Run the same classes of checks used by release validation:

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

Build with the version that automation would select. The temporary local tag gives `setuptools-scm` the same version context as the release workflow:

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

If the tag already points to `HEAD`, the script checks that existing tag. This is the recovery path for a tag whose GitHub Release was not created.

## Start the release

Push the releasable commit to `main`. The `Release` workflow computes the next `vMAJOR.MINOR.PATCH` tag from Conventional Commits and validates the exact commit. It scans generated release notes before the automation app creates an annotated tag and GitHub Release.

You may also dispatch the workflow. Leave `version` empty to compute it, or enter `MAJOR.MINOR.PATCH` to choose it explicitly.

Automatic version selection follows these rules:

| Commit | Release change |
| --- | --- |
| `BREAKING CHANGE:`, `BREAKING-CHANGE:`, or a `!` marker | Major |
| `feat:` | Minor |
| `fix:`, `perf:`, `refactor:`, `deps:`, `revert:`, `build(deps):`, `chore(deps):`, or Git's `Revert "..."` | Patch |
| `docs:`, `test:`, `ci:`, ordinary `chore:` | No release by itself |
| Head commit containing `[skip release]` or `[release skip]` | Skip |

Automatic selection examines all commit messages since the latest release and uses the highest matching bump.

A manual version may have a leading `v`, but otherwise must use `MAJOR.MINOR.PATCH` without leading zeros. Each component must be at most `999999`, and the version must be higher than the latest release. If the latest tag already points to current `main`, leave the manual version empty; the resolver returns that existing tag for recovery.

The GitHub Release triggers `.github/workflows/pypi.yml`. That workflow accepts only a non-prerelease release authored by `vexcalibur-dev-automation[bot]`. Its SemVer tag must point to current `origin/main`.

The workflow reuses release validation and checks both distribution metadata records. It tests the installed wheel on the minimum and maximum Python versions, then publishes through Trusted Publishing.

Pushing a tag alone does not publish. A manually authored GitHub Release is also rejected.

## Verify the publication

After the `PyPI` workflow succeeds, install the exact release in a fresh environment:

```bash
RELEASE_VERSION=0.1.1
python -m venv /tmp/vexcalibur-release-check
/tmp/vexcalibur-release-check/bin/python -m pip install "vexcalibur==$RELEASE_VERSION"
/tmp/vexcalibur-release-check/bin/python - <<'PY'
import importlib.metadata
import vexcalibur

distribution_version = importlib.metadata.version("vexcalibur")
assert distribution_version == vexcalibur.__version__
print(distribution_version)
PY
```

Set `RELEASE_VERSION` to the release you published. Confirm that the printed version matches, then inspect the PyPI page and GitHub Release artifacts before announcing it.

## Yank a bad release

Prefer a yank to deletion. A yank preserves the release record while steering normal dependency resolution away from the bad version.

1. Open the Vexcalibur releases page in PyPI's project management interface.
2. Open the bad version's **Options** menu and select **Yank**.
3. Give downstream users a useful reason.
4. Confirm that PyPI marks the version as yanked.
5. Fix the problem and publish a higher version.
