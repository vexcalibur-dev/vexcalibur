# CI And Recurring Checks

Vexcalibur CI separates repository security gates from live-service compatibility checks.

## Pull Requests, Pushes, And Manual Runs

The main CI workflow runs these repository gates on pull requests and pushes to `main`:

- package metadata and lock-file checks
- Ruff formatting and linting
- MyPy type checking
- dependency audit with `pip-audit`
- secret enforcement with `detect-secrets-hook`
- offline pytest matrix across supported Python versions
- package build
- documentation build

Manual runs execute the same repository gates. The live OSV compatibility job runs manually when `run_live_osv` is selected.

Use `run_scheduled_profile` when you need to validate the scheduled job shape before a scheduled run occurs. That profile runs repository security and live OSV compatibility while skipping the normal pull request package, test, build, and docs jobs.

## Scheduled Runs

Scheduled CI intentionally keeps repository security checks visible and separate from public-service compatibility:

- `Repository security` runs `pip-audit` and `detect-secrets-hook`.
- `Live OSV compatibility` runs only the tests marked `live` and may contact the public OSV service.

Do not treat a live OSV failure as evidence that repository security checks failed. Triage live OSV failures as public-service, network, schema, or compatibility changes.

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

For recurring live OSV failures:

- Check whether `https://api.osv.dev` changed behavior or is unavailable.
- Reproduce with `poetry run pytest -m live -q` only when public OSV access is acceptable.
- Keep fixes isolated from repository security-gate changes.
