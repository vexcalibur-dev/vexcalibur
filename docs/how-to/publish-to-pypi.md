# Publish To PyPI

Use this runbook to publish Vexcalibur from a GitHub Release. Do not upload
Vexcalibur with a local API token or password.

## Prerequisites

- You are on `main`, and `main` contains the commit to release.
- The release tag uses `vMAJOR.MINOR.PATCH`, for example `v0.1.0`.
- You can push `v*` tags to `vexcalibur-dev/vexcalibur`.
- You are authenticated with `gh` and can create GitHub Releases in
  `vexcalibur-dev/vexcalibur`.
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
uv lock --check
uv sync --frozen --extra docs
uv run --frozen ruff format --check src tests docs/conf.py
uv run --frozen ruff check src tests docs/conf.py
uv run --frozen mypy src
uv run --frozen pytest -m "not live" --cov-fail-under=75
make docs
uv run --frozen pip-audit --cache-dir /tmp/vexcalibur-pip-audit-cache
make secrets
```

Build and inspect the release artifacts with a temporary local tag. Delete the
temporary tag before creating the real release tag.

```bash
RELEASE_TAG=v0.1.0
RELEASE_VERSION=${RELEASE_TAG#v}
DIST_DIR=/tmp/vexcalibur-dist

if git rev-parse --verify --quiet "refs/tags/$RELEASE_TAG" >/dev/null; then
  echo "Local tag already exists: $RELEASE_TAG" >&2
  exit 1
fi

git tag "$RELEASE_TAG"
trap 'git tag --delete "$RELEASE_TAG" >/dev/null 2>&1 || true' EXIT

uv build --clear --no-create-gitignore --no-sources --out-dir "$DIST_DIR"
python scripts/verify-dist-metadata.py "$DIST_DIR" \
  --expected-name vexcalibur \
  --expected-version "$RELEASE_VERSION"
uv run --frozen twine check "$DIST_DIR"/*
VEXCALIBUR_WHEEL="$(find "$DIST_DIR" -maxdepth 1 -type f -name '*.whl')" \
  VEXCALIBUR_EXPECTED_VERSION="$RELEASE_VERSION" \
  make installed-cli-check
git tag --delete "$RELEASE_TAG"
trap - EXIT
```

Do not continue if any command fails or if `git status --short` shows an
unexpected tracked change.

## Publish

Create and push the release tag from the checked commit:

```bash
RELEASE_TAG=v0.1.0

git tag -a "$RELEASE_TAG" -m "$RELEASE_TAG"
git push origin "$RELEASE_TAG"
```

Publish a GitHub Release for that tag:

```bash
gh release create "$RELEASE_TAG" --title "$RELEASE_TAG" --generate-notes
```

Publishing the GitHub Release triggers `.github/workflows/pypi.yml`. The
workflow validates that the tag is reachable from `origin/main`, resolves the tag
to one commit SHA, runs the release quality gates, builds one wheel and one
source distribution, verifies both distribution metadata records match the tag,
smoke-tests the built wheel, and publishes through the `pypi` environment.

Pushing a tag alone does not publish to PyPI.

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
