# CI, releases, and recurring checks

Vexcalibur separates deterministic repository checks from tests that call public services. This keeps a provider outage from obscuring a code or security failure.

## Pull requests and pushes

The `CI` workflow runs these jobs on pull requests and pushes to `main`:

- lock-file validation.
- Ruff formatting and linting.
- strict MyPy checking.
- `actionlint` and `shellcheck`.
- dependency and secret scans.
- offline tests on Python 3.10–3.14.
- source and wheel builds.
- installed-wheel checks for `vexcalibur` and `vexy`.
- a warning-free Sphinx build.

The `CI result` job combines the normal required results into one status that can be selected by branch protection. The current `main` ruleset does not require a status check, so CI success is not enforced as a merge rule. CodeQL, dependency review, OpenSSF Scorecard, and pre-commit run in dedicated workflows.

A normal manual run executes the same job set as a pull request or push. Its secret scan uses the current branch baseline, while a pull request uses the exact base-commit baseline. Set `run_live_services` to add live compatibility tests. Set `run_scheduled_profile` to run only the scheduled profile: repository security checks plus live-service tests.

## Scheduled checks

The scheduled CI run has two parts:

| Job | Purpose |
| --- | --- |
| Repository security | Run `pip-audit` and enforce the committed secret baseline. |
| Live external-service compatibility | Run tests marked `live` against services such as OSV and GitHub. |

A live failure may be a service outage, network problem, or upstream schema change. It does not mean the repository security job failed.

Reproduce a live failure only when its fixture package data is approved for the public services:

```bash
make test-live
```

## Release automation

The `Release` workflow runs after a push to `main` and supports manual dispatch. It refuses a stale workflow run, then derives a `vMAJOR.MINOR.PATCH` tag from Conventional Commits unless the operator supplies a version.

Before gaining write access, the workflow calls `release-validation.yml` against the exact commit. That workflow checks quality, workflows, security, offline tests, docs, builds, metadata, and the installed wheel. The release job then creates a short-lived installation token for the `vexcalibur-dev-automation` GitHub App.

The write-capable job confirms that `main` still points to the validated commit. It generates release notes and scans them for secrets. It then creates an annotated tag and publishes the GitHub Release.

An existing tag or release is accepted only when it already points to the same commit.

See [Publish Vexcalibur to PyPI](../how-to/publish-to-pypi.md) for operator steps and version rules.

## PyPI publishing

Publishing begins only from a published GitHub Release. `.github/workflows/pypi.yml` requires:

- author `vexcalibur-dev-automation[bot]`.
- a non-prerelease GitHub Release.
- a valid SemVer tag.
- a tag at current `origin/main`.
- successful shared release validation.

The workflow publishes through PyPI Trusted Publishing from the `pypi` environment. It has `id-token: write` only in the publish job and uses no stored PyPI password.

The Trusted Publisher identity is:

| Field | Value |
| --- | --- |
| Project | `vexcalibur` |
| Repository | `vexcalibur-dev/vexcalibur` |
| Workflow | `pypi.yml` |
| Environment | `pypi` |

Versions come from tags through `setuptools-scm`. Do not commit a literal package version or generated `src/vexcalibur/_version.py`.

## Secret baselines

Pull requests compare tracked files with the base branch's `.secrets.baseline`. A pull request cannot add a secret and suppress it by changing the baseline in the same diff.

Run current-branch enforcement:

```bash
make secrets
```

Reproduce pull-request enforcement:

```bash
make secrets-pr
```

Refresh the baseline only in a dedicated, reviewed maintenance change:

```bash
make secrets-baseline
```

Prefer removing a secret-like value or adding a narrow inline allowlist for a verified false positive.

## Triage recurring failures

For `pip-audit`, confirm the advisory and upgrade while preserving the supported Python range. If no fix exists, record the affected dependency, impact, and mitigation in an issue.

For `detect-secrets`, do not refresh the baseline in the change that introduced the finding. Remove the value, move it to a secret manager, or isolate a verified false-positive update.

For an installed CLI failure, run `make installed-cli-check` and check `[project.scripts]` in `pyproject.toml`. Keep packaging and entry-point repairs separate from unrelated behavior changes.
