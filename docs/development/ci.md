# CI And Recurring Checks

Vexcalibur CI separates repository security gates from live-service compatibility checks.

## Pull Requests, Pushes, And Manual Runs

The main CI workflow runs these repository gates on pull requests and pushes to `main`:

- lock-file check with `uv lock --check`
- Ruff formatting and linting
- MyPy type checking
- dependency audit with `pip-audit`
- secret enforcement with `detect-secrets-hook`
- offline pytest matrix across supported Python versions
- package build
- installed wheel console-script checks for `vexcalibur` and `vexy`
- documentation build

Manual runs execute the same repository gates. The live external-service
compatibility job runs manually when `run_live_services` is selected.

Use `run_scheduled_profile` when you need to validate the scheduled job shape before a scheduled run occurs. That profile runs repository security and live external-service compatibility while skipping the normal pull request gates: quality, test, package build, installed CLI, documentation build, and CI result.

## PyPI Publishing

PyPI publishing is handled by `.github/workflows/pypi.yml`.

The workflow publishes through PyPI Trusted Publishing, so it does not use a
password or API token secret. The PyPI publisher configuration must match:

| Field | Value |
| --- | --- |
| Project | `vexcalibur` |
| Repository | `vexcalibur-dev/vexcalibur` |
| Workflow | `pypi.yml` |
| Environment | `pypi` |

Release versions come from Git tags through `setuptools-scm`; do not commit a
literal version number to `pyproject.toml`. The first package release should use
tag `v0.1.0`.
Builds may generate `src/vexcalibur/_version.py` from tag metadata so source and
source distributions remain buildable without a committed release version. That
generated file is ignored and should not be committed.

Publish by creating a GitHub Release for a matching `v*` tag on `main`. The
workflow rejects tags that are not reachable from `origin/main`; it does not
support manual dispatch publishing.

The publishing workflow:

- validates the release tag format and confirms the tag is on `origin/main`;
- checks out the release tag with full Git history so tags are available;
- runs quality, security, offline test, and documentation gates against the
  release tag before publishing;
- builds source and wheel distributions with `uv build --clear --no-create-gitignore --no-sources`;
- verifies the source and wheel distribution metadata names and versions match
  the release tag;
- runs `twine check`;
- runs installed CLI smoke tests against the exact wheel artifact on the minimum
  and maximum supported Python versions; and
- publishes from the `pypi` environment with `id-token: write`.

## Scheduled Runs

Scheduled CI intentionally keeps repository security checks visible and separate from public-service compatibility:

- `Repository security` runs `pip-audit` and `detect-secrets-hook`.
- `Live external-service compatibility` runs only the tests marked `live` and
  may contact public services such as OSV and GitHub.

Do not treat a live external-service failure as evidence that repository
security checks failed. Triage live failures as public-service, network, schema,
or compatibility changes.

## Secret Baselines

Pull request secret scans use the base branch `.secrets.baseline`. A PR cannot add a secret and suppress it by updating `.secrets.baseline` in the same change.

Use this command for enforcement:

```bash
make secrets
```

Use this command to reproduce pull request enforcement against the base branch baseline:

```bash
make secrets-pr
```

Use this command only for an intentional baseline refresh:

```bash
make secrets-baseline
```

Baseline refreshes should be reviewed separately from code that adds or changes sensitive-looking content. If a recurring secret-scan failure appears after tool or dependency updates, remove the secret-like content, add an inline allowlist only for a verified false positive, or open a dedicated baseline maintenance PR.

## Recurring Failure Handling

For recurring `pip-audit` failures:

- Confirm the vulnerable package and advisory from the job log.
- Prefer dependency upgrades that preserve the supported Python range.
- If no fixed version exists, open a tracking issue with the advisory, affected package, impact, and planned mitigation.

For recurring `detect-secrets-hook` failures:

- Do not refresh the baseline in the same PR that introduced the finding.
- Remove the sensitive value or move it to a secret manager.
- For a verified false positive, use the narrowest inline allowlist or a dedicated baseline maintenance PR.

For recurring live external-service failures:

- Check whether `https://api.osv.dev`, `https://api.github.com`, or another
  covered public service changed behavior or is unavailable.
- Reproduce with `uv run --frozen pytest -m live -q` only when contacting the
  covered public services is acceptable.
- Keep fixes isolated from repository security-gate changes.

For recurring installed CLI failures:

- Reproduce with `make installed-cli-check`.
- Check that `[project.scripts]` in `pyproject.toml` still exposes `vexcalibur` and `vexy`.
- Keep packaging, console-entrypoint, and dependency fixes separate from unrelated behavior changes.
