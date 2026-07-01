# Python Style Policy

This is Vexcalibur's enforceable Python style policy. It is inspired by the vendored <a href="../external/google-python-style-guide.md">Google Python Style Guide</a>, but this document and the checked-in tool configuration are authoritative for this repository.

If this policy conflicts with the vendored Google guide, follow this policy. In particular, Vexcalibur does not require `pylint`, 80-character lines, Black, or Pyink just because those appear in the upstream guide.

## Tooling

- Ruff is the formatter and linter source of truth.
- Line length is 100 characters.
- MyPy strict mode is required for `src/vexcalibur`.
- Pytest is the test runner.
- `pyproject.toml` is the canonical machine-readable configuration.

Run the usual local quality gate:

```bash
make check
```

For a full pre-PR pass, run:

```bash
uv lock --check
uv sync --frozen
uv run --frozen ruff format --check src tests docs/conf.py
uv run --frozen ruff check src tests docs/conf.py
uv run --frozen mypy src
uv run --frozen pytest -m "not live" --cov-fail-under=75
make docs
uv build --clear --no-create-gitignore --no-sources
uv run --frozen pip-audit --cache-dir /tmp/vexcalibur-pip-audit-cache
git ls-files -z | xargs -0 uv run --frozen detect-secrets-hook --baseline .secrets.baseline --
git show origin/main:.secrets.baseline > /tmp/vexcalibur-base.secrets.baseline
git ls-files -z | xargs -0 uv run --frozen detect-secrets-hook --baseline /tmp/vexcalibur-base.secrets.baseline --
```

Use `make secrets` for current-branch baseline enforcement, `make secrets-pr` for PR-mode
base-baseline enforcement, and `make secrets-baseline` only for an intentional, separately
reviewed baseline refresh.

## Conventions

- Prefer precise types on public functions and domain boundaries.
- Keep imports grouped and sorted by Ruff.
- Use Google-style docstrings for public APIs when the signature and name do not fully explain behavior.
- Keep exceptions explicit and user-facing CLI messages free of tracebacks for expected input/configuration errors.
- Keep functions small enough to scan. Extract helpers when a workflow starts mixing parsing, policy, I/O, and rendering concerns.
- Do not add comments that restate obvious code. Add short comments only when they prevent misreading of non-obvious logic.
- Treat public-service access as security-sensitive; code must fail closed unless the caller explicitly opts in.

## Tests

- Put tests under `tests/`.
- Mark external-service tests with `@pytest.mark.live`.
- Prefer deterministic fixtures and golden files for VEX output.
- Add regression tests for security, compatibility, and parsing fixes.
- For SBOM and VEX changes, test both successful behavior and malformed or unsafe input.
