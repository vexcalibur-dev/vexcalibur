# Python style policy

This file and `pyproject.toml` define Vexcalibur's enforceable Python style. The vendored <a href="../external/google-python-style-guide.md">Google Python Style Guide</a> is background reference.

When they differ, follow the local policy. Vexcalibur does not adopt the upstream guide's `pylint`, 80-character line limit, Black, or Pyink rules.

## Tooling

Development tools require Python 3.14 or newer. The checkout's `.python-version`
selects Python 3.14 for uv. This does not change the supported runtime range:
Vexcalibur still runs on Python 3.10 through 3.14.

| Tool | Project rule |
| --- | --- |
| Ruff | Formatter, import sorter, and linter; 100-character line length |
| MyPy | Strict mode for `src/vexcalibur` |
| Pytest | Test runner; external-service tests use the `live` marker |
| `pyproject.toml` | Machine-readable source of truth |

Run the quick local quality gate while you work:

```bash
make check
```

Before a pull request that changes packaging or documentation, also check the lock file, build the manual, and build the distributions:

```bash
git fetch origin main
uv lock --check
uv sync --frozen --extra docs
uv run --frozen ruff format --check src tests scripts/*.py docs/conf.py docs/examples/*.py
make check
make coverage COVERAGE_COMPARE_REF=origin/main
make docs
uv build --clear --no-create-gitignore --no-sources
make secrets-pr
```

## Code conventions

- Give public functions and domain boundaries precise types.
- Use Google-style docstrings when a public name and signature do not explain the behavior.
- Keep expected CLI errors free of tracebacks.
- Split work when one function mixes parsing, policy, I/O, and rendering.
- Comment non-obvious reasoning, not the next line of code.
- Fail closed before sending package inventory to a public service.

## Test conventions

The `test` dependency group supports every runtime in the CI matrix without
installing development tools. To check Python 3.10 locally, keep its environment
separate from your development environment:

```bash
UV_PROJECT_ENVIRONMENT=.venv310 uv sync --frozen --python 3.10 --no-dev --group test
UV_PROJECT_ENVIRONMENT=.venv310 uv run --frozen --python 3.10 --no-dev --group test pytest -m "not live"
```

uv can download the requested interpreter if it isn't installed. A passing run
confirms the runtime tests; it doesn't replace the Python 3.14 development gate.
Run ordinary `uv sync --frozen` commands outside that compatibility environment.

- Put tests under `tests/`.
- Mark external-service tests with `@pytest.mark.live`.
- Prefer deterministic fixtures and golden files for VEX output.
- Add a regression test for a parsing, compatibility, or security fix.
- Test malformed and unsafe input as well as success paths at SBOM and VEX boundaries.

Use `make secrets-baseline` only for an intentional baseline refresh reviewed separately from sensitive-looking content.
