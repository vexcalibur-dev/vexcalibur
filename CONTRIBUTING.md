# Contributing

Vexcalibur is usable for documented workflows, but compatibility decisions are still being made before 1.0. Keep changes focused, tested, and explicit about user-facing behavior.

## Development

Prerequisites:

- Python 3.10 or newer
- Poetry 2.x

Install dependencies from the repository root:

```bash
poetry install
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
poetry install --extras docs
make docs
```

## Style

Vexcalibur's enforceable Python style policy is [docs/development/python-style.md](docs/development/python-style.md). The vendored Google Python Style Guide is reference material only; when it conflicts with the project policy or `pyproject.toml`, follow the project policy.

## Pull Requests

Pull requests should include:

- A short description of the problem and solution.
- Tests for changed behavior.
- The commands used to verify the change.
- Compatibility or security notes when the change affects VEX output, vulnerability source behavior, package URL handling, or CI permissions.
