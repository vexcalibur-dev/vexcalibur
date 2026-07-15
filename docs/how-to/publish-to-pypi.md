# Publish Vexcalibur to GitHub and PyPI

Use the automated release workflows. Never upload Vexcalibur with a local PyPI
password, API token, `twine upload`, or a hand-built distribution.

The release path publishes one checked set of bytes:

```text
clean main commit
  -> isolated validation and one build
  -> immutable GitHub Release with schema-2 evidence
  -> exact GitHub-hosted wheel and sdist
  -> PyPI Trusted Publishing
```

## Check release configuration

Use a recent GitHub CLI that provides `gh release verify` and
`gh release verify-asset`. Authenticate as an organization owner or repository
administrator who can read rulesets, security settings, environments,
repository variables and secrets, the App installation, and organization
Actions policy. From the repository root, require every command to succeed:

```bash
REPOSITORY=vexcalibur-dev/vexcalibur

gh auth status --active --hostname github.com
make governance-check
gh variable get AUTOMATION_CLIENT_ID --repo "$REPOSITORY" >/dev/null
test "$(
  gh secret list --repo "$REPOSITORY" --json name \
    --jq 'map(select(.name == "AUTOMATION_SECRET")) | length'
)" -eq 1
test "$(
  gh secret list --repo "$REPOSITORY" --env pypi --json name --jq length
)" -eq 0
```

`make governance-check` must exit `0`, not the inaccessible-endpoint status
`2`. It verifies the live GitHub App scope and installation, owner-enforced
immutable releases, the `pypi` environment, and its single `v*` tag policy. The
remaining commands prove that the workflow's App variable and secret names are
present and that the environment contains no stored publishing secret. They do
not reveal the App private key.

PyPI does not expose the Trusted Publisher configuration through this
repository's governance check. Sign in to PyPI as a project owner and inspect
the `vexcalibur` project's Publishing settings. Require exactly this publisher:

| Field | Required value |
| --- | --- |
| Owner | `vexcalibur-dev` |
| Repository | `vexcalibur` |
| Workflow | `pypi.yml` |
| Environment | `pypi` |

Also use the project's Collaborators settings to confirm that the release
operator can yank a bad version. Record the successful GitHub command output
and the manual PyPI review in the release issue or checklist.

The `pypi` environment's tag policy is a deployment restriction, but it has no
required reviewer. Anyone allowed to dispatch the release workflows should be
treated as a release operator.

The immutable-policy status endpoint requires Administration-read permission,
which the ordinary workflow token may not have. A 401 or 403 produces a
prominent deferred-preflight warning. Any readable false policy, 404, malformed
response, or other failure stops publication. Regardless of preflight access,
the publisher requires GitHub to report `immutable: true` and verify the
release plus every asset after publication.

## Prepare the release commit

Start from current `main` with no local changes:

```bash
git fetch origin main --tags
git switch main
git pull --ff-only origin main
git status --short
test -z "$(git status --porcelain)"
```

Run the repository gates:

```bash
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

Validate the reviewed self-evidence inputs and local conformance bundle by
following [Build and review local release evidence](build-release-evidence.md).

Preview automatic version selection:

```bash
scripts/next-release-tag.sh
```

Automatic selection examines commits after the latest release and chooses the
highest applicable change:

| Commit message | Version effect |
| --- | --- |
| `BREAKING CHANGE:`, `BREAKING-CHANGE:`, or a `!` marker | Major |
| `feat:` | Minor |
| `fix:`, `perf:`, `refactor:`, `deps:`, `revert:`, `build(deps):`, or `chore(deps):` | Patch |
| `docs:`, `test:`, `ci:`, or ordinary `chore:` | No release by itself |
| Head commit containing `[skip release]` or `[release skip]` | Skip |

An explicit version must be `MAJOR.MINOR.PATCH`, with no leading zeros and no
component above `999999`. It must be higher than the latest release.

## Start a normal release

Push the release commit to `main`. The `Release` workflow normally starts from
that push. You may also dispatch it manually:

- leave `version` empty to use Conventional Commit selection; or
- set `version` to an explicit `MAJOR.MINOR.PATCH`;
- leave `recovery-tag` empty.

`version` and `recovery-tag` are mutually exclusive.

Normal mode repeatedly requires the validated commit to equal the current tip
of `main`. If `main` advances, the run stops. A draft created before that race
is left intact for explicit recovery.

The workflow builds the wheel and source distribution once, creates the
candidate-free inventory, generates VEX independently with the installed wheel
and full-commit-pinned companion Action, and finalizes a flat schema-2 asset
set on a fresh runner. Release notes cross a separate digest and secret-scan
boundary.

Only after all proposed bytes are verified does the final job mint a short-lived
App token. It creates an annotated bot-authored tag whose canonical JSON message
binds the exact scanned release notes and their SHA-256, then creates the exact
draft. It reconciles assets without clobbering, requires GitHub to identify
every completed asset's uploader as `vexcalibur-dev-automation[bot]`, downloads
every asset for a byte comparison, and publishes. The run succeeds only after
the release becomes immutable and the release and every asset pass bounded
attestation verification.

Do not create or edit the tag or release manually while this workflow runs.

## Recover an interrupted GitHub Release

Use recovery only for an existing annotated release tag created by the
automation contract. The dispatch itself must run from `main`; the workflow's
resolver rejects every other Git ref. With a recent authenticated GitHub CLI:

```bash
RELEASE_TAG=v0.4.0

gh auth status --active --hostname github.com
gh workflow run release.yml \
  --repo vexcalibur-dev/vexcalibur \
  --ref main \
  -f recovery-tag="$RELEASE_TAG"
```

Leave `version` empty and inspect every reconciliation message. GitHub Release
recovery deliberately uses `--ref main`; the later PyPI recovery dispatch uses
the exact release tag as both `--ref` and `release-tag`.

The tag must directly annotate a commit that is still an ancestor of current
`main`; it need not remain the tip. Validation regenerates the complete asset
set deterministically. Existing draft assets must have the same names and
bytes. The workflow may delete and retry only a zero-byte GitHub
`state=starter` upload marker. It never replaces a completed asset.

Recovery does not trust the mutable draft body. It validates the protected tag
ref, annotated object, target commit, automation-bot tagger, closed-world
release-note payload, and notes SHA-256. It reconstructs the notes from that tag,
runs the digest and secret-scan boundary again, and requires any existing draft
or release body to match those exact bytes. Do not edit either the tag or draft
body to repair a mismatch.

If the exact release is already published and immutable, recovery is
idempotent: it reconstructs and rechecks the protected notes, verifies every
asset, and repeats the immutable/attestation checks.

Stop and investigate if the existing tag, author, target, title, notes, asset
set, or any completed asset differs. The workflow intentionally offers no
force or clobber recovery path.

## Let PyPI publish the exact release bytes

Publishing the immutable GitHub Release triggers `.github/workflows/pypi.yml`.
That workflow accepts only an automation-bot-authored, published,
non-prerelease, immutable release whose first-level annotated tag is authored by
the automation bot, directly targets a commit that remains an ancestor of
`main`, and protects the exact release body through its notes payload.

It downloads all schema-2 assets and verifies:

- GitHub release and per-asset attestations, with bounded retries;
- the closed-world manifest and `SHA256SUMS` contract;
- the exact lock-derived constraints and normalized SBOM;
- wheel and source-distribution names, metadata, version, source identity, and
  archive safety;
- installed-wheel behavior;
- CycloneDX, official OpenVEX, and strict CSAF validation; and
- exact hashes already present on PyPI.

Release resolution, asset validation, and the immediate pre-OIDC check each
query GitHub independently and require every asset to be in the completed state
with server-authenticated uploader `vexcalibur-dev-automation[bot]` and no
display label. Resolve and pre-OIDC checks also repeat the protected-tag schema,
tagger, digest, and release-body comparison.

The workflow never rebuilds. Its selector creates a fresh directory containing
only release distributions absent from PyPI. Existing files must have the exact
expected SHA-256 and package type. A conflicting expected filename or any
unexpected extra file for that PyPI version stops the run.

The OIDC-bearing publish job has no repository checkout, setup action, package
installation, cache, or repository script. It receives only that filename
subset, checks the compact JSON filename contract and every digest again,
re-resolves the immutable release, then invokes the pinned PyPI publisher.

If the GitHub release event was missed or a PyPI upload stopped after one file,
dispatch `PyPI` from the exact release tag and supply the same tag as input:

```bash
RELEASE_TAG=v0.4.0
gh workflow run pypi.yml \
  --repo vexcalibur-dev/vexcalibur \
  --ref "$RELEASE_TAG" \
  -f release-tag="$RELEASE_TAG"
```

The workflow rejects a dispatch whose Git ref and `release-tag` differ. This
binding is also what satisfies the `pypi` environment's `v*` tag deployment
policy. Publishing both files already present at the expected hashes is a
successful no-op.

## Verify the release

Run this from a Vexcalibur checkout after both workflows succeed. It requires a
recent authenticated GitHub CLI, Git with the release tag available, GNU
`sha256sum`, `jq`, uv, and Python 3. The temporary directories must be new so
stale files cannot satisfy a check:

```bash
set -euo pipefail

RELEASE_TAG=v0.4.0
RELEASE_VERSION=${RELEASE_TAG#v}
REPOSITORY=vexcalibur-dev/vexcalibur
RELEASE_ASSETS="$(mktemp -d)"
PYPI_ASSETS="$(mktemp -d)"
INSTALL_ENV="$(mktemp -d)"
VERIFICATION_METADATA="$(mktemp -d)"
export RELEASE_TAG RELEASE_VERSION RELEASE_ASSETS PYPI_ASSETS

gh auth status --active --hostname github.com
git fetch origin "refs/tags/$RELEASE_TAG:refs/tags/$RELEASE_TAG"
RELEASE_SHA="$(git rev-parse --verify "$RELEASE_TAG^{commit}")"
RELEASE_RECORD="$VERIFICATION_METADATA/release.json"
gh api "repos/$REPOSITORY/releases/tags/$RELEASE_TAG" > "$RELEASE_RECORD"
RELEASE_ID="$(jq --raw-output --exit-status .id "$RELEASE_RECORD")"

AUTOMATION_APP_SLUG=vexcalibur-dev-automation
BOT_LOGIN="${AUTOMATION_APP_SLUG}[bot]"
BOT_ID="$(gh api "/users/${AUTOMATION_APP_SLUG}%5Bbot%5D" --jq .id)"
BOT_EMAIL="${BOT_ID}+${BOT_LOGIN}@users.noreply.github.com"
TAG_REF="$VERIFICATION_METADATA/tag-ref.json"
TAG_OBJECT="$VERIFICATION_METADATA/tag-object.json"
PROTECTED_NOTES="$VERIFICATION_METADATA/protected-release-notes.md"
RELEASE_BODY="$VERIFICATION_METADATA/release-body.md"

jq --exit-status \
  --arg tag "$RELEASE_TAG" \
  --arg sha "$RELEASE_SHA" \
  --arg author "$BOT_LOGIN" \
  '.tag_name == $tag and .target_commitish == $sha and .name == $tag and
   .draft == false and .prerelease == false and .immutable == true and
   .author.login == $author and (.body | type == "string")' \
  "$RELEASE_RECORD"

gh api "repos/$REPOSITORY/git/ref/tags/$RELEASE_TAG" > "$TAG_REF"
TAG_OBJECT_SHA="$(
  jq --raw-output --exit-status --arg ref "refs/tags/$RELEASE_TAG" \
    'select(.ref == $ref and .object.type == "tag" and
            (.object.sha | test("^[0-9a-f]{40}$"))) | .object.sha' \
    "$TAG_REF"
)"
gh api "repos/$REPOSITORY/git/tags/$TAG_OBJECT_SHA" > "$TAG_OBJECT"
jq --exit-status \
  --arg tag "$RELEASE_TAG" \
  --arg sha "$RELEASE_SHA" \
  --arg name "$BOT_LOGIN" \
  --arg email "$BOT_EMAIL" \
  '(.message | fromjson) as $message |
   .tag == $tag and .object.type == "commit" and .object.sha == $sha and
   .tagger.name == $name and .tagger.email == $email and
   ($message | type == "object") and
   ($message | keys) ==
     ["release_notes", "release_notes_sha256", "schema_version", "tag"] and
   $message.schema_version == 1 and $message.tag == $tag and
   ($message.release_notes | type == "string") and
   ($message.release_notes_sha256 | type == "string" and
    test("^[0-9a-f]{64}$"))' \
  "$TAG_OBJECT"
jq --join-output '.message | fromjson | .release_notes' \
  "$TAG_OBJECT" > "$PROTECTED_NOTES"
NOTES_SHA256="$(
  jq --raw-output '.message | fromjson | .release_notes_sha256' "$TAG_OBJECT"
)"
test "$(sha256sum "$PROTECTED_NOTES" | awk '{print $1}')" = "$NOTES_SHA256"
jq --join-output '.body' "$RELEASE_RECORD" > "$RELEASE_BODY"
cmp --silent "$PROTECTED_NOTES" "$RELEASE_BODY"

gh api --paginate \
  "repos/$REPOSITORY/releases/$RELEASE_ID/assets?per_page=100" \
  --jq '.[]' | jq -s -e \
    --arg uploader 'vexcalibur-dev-automation[bot]' \
    'length > 0 and
     ([.[].name] | length == (unique | length)) and
     all(.[]; (.id | type == "number") and .id > 0 and
              (.size | type == "number") and .size > 0 and
              .state == "uploaded" and .uploader.login == $uploader and
              (.label == null or .label == ""))'

gh release verify "$RELEASE_TAG" --repo "$REPOSITORY"
gh release download "$RELEASE_TAG" \
  --repo "$REPOSITORY" \
  --dir "$RELEASE_ASSETS"
while IFS= read -r -d '' asset; do
  gh release verify-asset "$RELEASE_TAG" "$asset" --repo "$REPOSITORY"
done < <(find "$RELEASE_ASSETS" -maxdepth 1 -type f -print0)
(
  cd "$RELEASE_ASSETS"
  sha256sum --check --strict SHA256SUMS
)

uv run --frozen python scripts/release_evidence.py verify-publication \
  --bundle-dir "$RELEASE_ASSETS" \
  --release-tag "$RELEASE_TAG" \
  --release-sha "$RELEASE_SHA"
```

Fetch both distributions from PyPI's public JSON API. This uses neither pip
configuration nor a package cache. It requires the public version to contain
exactly the wheel and source distribution named by the schema-2 manifest, checks
PyPI's recorded digest, and compares the downloaded bytes with the GitHub
Release assets:

```bash
python - <<'PY'
import hashlib
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen

version = os.environ["RELEASE_VERSION"]
release_dir = Path(os.environ["RELEASE_ASSETS"])
pypi_dir = Path(os.environ["PYPI_ASSETS"])
manifest = json.loads((release_dir / "manifest.json").read_text())
expected_names = {
    manifest["generator"]["wheel_filename"],
    manifest["generator"]["sdist_filename"],
}

request = Request(
    f"https://pypi.org/pypi/vexcalibur/{version}/json",
    headers={"Accept": "application/json"},
)
with urlopen(request, timeout=30) as response:
    release = json.load(response)
records = release["urls"]
files = {record["filename"]: record for record in records}
assert len(files) == len(records), "PyPI returned duplicate filenames"
assert set(files) == expected_names, (set(files), expected_names)

for name in sorted(expected_names):
    record = files[name]
    with urlopen(record["url"], timeout=60) as response:
        payload = response.read()
    digest = hashlib.sha256(payload).hexdigest()
    assert digest == record["digests"]["sha256"], name
    assert payload == (release_dir / name).read_bytes(), name
    (pypi_dir / name).write_bytes(payload)
    print(f"verified identical PyPI and GitHub bytes: {name} ({digest})")
PY
```

Finally, install the exact public wheel in a fresh environment. `--isolated`
ignores pip configuration and environment variables, `--no-cache-dir` prevents
cache reuse, and the explicit index excludes a private package source:

```bash
python -m venv "$INSTALL_ENV"
"$INSTALL_ENV/bin/python" -m pip install \
  --isolated \
  --no-cache-dir \
  --index-url https://pypi.org/simple \
  --only-binary=:all: \
  "vexcalibur==$RELEASE_VERSION"
"$INSTALL_ENV/bin/python" - "$RELEASE_VERSION" <<'PY'
import importlib.metadata
import sys

import vexcalibur

expected = sys.argv[1]
installed = importlib.metadata.version("vexcalibur")
assert installed == expected, (installed, expected)
assert vexcalibur.__version__ == expected, (vexcalibur.__version__, expected)
print(f"verified installed PyPI version: {installed}")
PY
```

Inspect the published schema-2 manifest before announcing the release. Remove
the four fresh temporary directories after retaining any verification record
required by the release issue.

## Respond to a bad release

Immutable GitHub Releases cannot be edited in place. PyPI files also must not be
replaced.

1. Yank the affected version from the PyPI project management page and record a
   useful reason. Open the public [Vexcalibur project page on
   PyPI](https://pypi.org/project/vexcalibur/), select the affected version from
   its release history, and confirm that the version is visibly marked as yanked
   and displays that reason. Also require every file in the version-specific
   JSON response to report `yanked: true`:

   ```bash
   RELEASE_VERSION=0.4.0
   python - "$RELEASE_VERSION" <<'PY'
   import json
   import sys
   from urllib.request import urlopen

   with urlopen(
       f"https://pypi.org/pypi/vexcalibur/{sys.argv[1]}/json", timeout=30
   ) as response:
       files = json.load(response)["urls"]
   assert files, "PyPI returned no release files"
   assert all(record["yanked"] is True for record in files), files
   print(f"verified {len(files)} yanked PyPI files for {sys.argv[1]}")
   PY
   ```
2. Publish a security advisory or issue when appropriate.
3. Fix the defect on `main`.
4. Publish a higher version through the same automated path.

A yank preserves the audit record while steering normal dependency resolution
away from the bad version.
