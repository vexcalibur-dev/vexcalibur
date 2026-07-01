# Contributing

Vexcalibur is usable for documented workflows, but compatibility decisions are still being made before 1.0. Keep changes focused, tested, and explicit about user-facing behavior.

## Development

Prerequisites:

- Python 3.10 or newer
- uv 0.11.17

Install dependencies from the repository root:

```bash
uv sync
```

Run the local quality gate:

```bash
make check
```

Run the live OSV compatibility test when changing OSV behavior:

```bash
make test-live
```

Build documentation when changing docs, CLI behavior, package metadata, or public APIs:

```bash
uv sync --extra docs
make docs
```

## Versioning And Releases

Package versions come from Git tags through `setuptools-scm`; do not commit a
literal release version to `pyproject.toml` or package source files.
`setuptools-scm` may generate `src/vexcalibur/_version.py` while building
distributions; leave it ignored and uncommitted.

Use tags like `v0.1.0` for releases. Publishing to PyPI runs from
`.github/workflows/pypi.yml` when a GitHub Release is published for a matching
tag on `main`. The workflow uses the `pypi` GitHub environment and verifies that
the built distribution metadata matches the release tag.
Follow the [PyPI publishing runbook](docs/how-to/publish-to-pypi.md) for
preflight, release, verification, and mitigation steps.

## Style

Vexcalibur's enforceable Python style policy is [docs/development/python-style.md](docs/development/python-style.md). The vendored Google Python Style Guide is reference material only; when it conflicts with the project policy or `pyproject.toml`, follow the project policy.

## Pull Requests

Pull requests should include:

- A short description of the problem and solution.
- Tests for changed behavior.
- The commands used to verify the change.
- Compatibility or security notes when the change affects VEX output, vulnerability source behavior, package URL handling, or CI permissions.
