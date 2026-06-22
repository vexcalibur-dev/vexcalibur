# Contributing

Vexcalibur is pre-alpha, so compatibility decisions are still being made. Keep changes focused, tested, and explicit about user-facing behavior.

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

## Pull Requests

Pull requests should include:

- A short description of the problem and solution.
- Tests for changed behavior.
- The commands used to verify the change.
- Compatibility or security notes when the change affects VEX output, vulnerability source behavior, package URL handling, or CI permissions.
