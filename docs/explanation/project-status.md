# Project Status

Vexcalibur is usable for documented SBOM-to-VEX workflows, but it has not
published a stable 1.0 compatibility policy. Treat command names, flags, Python
imports, and detailed output shapes as changeable until a release notes page or
compatibility policy says otherwise.

## Usable Now

The current implementation supports:

- CycloneDX JSON and XML SBOM ingest for CycloneDX `1.4`, `1.5`, and `1.6`.
- Public OSV queries when the caller explicitly opts in with
  `--allow-public-osv`.
- Private OSV-compatible endpoints with `--osv-url`.
- No-network local findings with `--offline --findings-file`.
- CycloneDX 1.6 VEX JSON output.
- Deterministic metadata and serial numbers when `--timestamp` and controlled
  finding inputs are used.
- A narrow `vexy` compatibility executable for CycloneDX JSON VEX generation
  from supported SBOM inputs and explicit Vexcalibur source modes.
- CI quality gates for tests, typing, linting, package build, installed CLI
  checks, documentation build, secret scanning, dependency audit, CodeQL,
  dependency review, and OpenSSF Scorecard.

## Compatibility Limits

Before 1.0, these surfaces can still change:

- CLI command names, flags, defaults, and exit behavior.
- Python import paths, type shapes, and exception classes.
- Generated VEX details beyond the documented CycloneDX 1.6 output contract.
- Provider configuration and extension hooks.
- GitHub Action release tags and package compatibility tables.

Pin exact package and action versions once releases begin. Do not use mutable
branches for production workflows.

## Deferred Work

The `vexy` compatibility executable does not support legacy CycloneDX XML VEX
output, CycloneDX `1.4` VEX output, or legacy OSS Index data-source behavior.
Those paths are intentionally not part of the current compatibility subset.

Policy-driven VEX state selection for OSV-derived findings is also deferred.
OSV-derived findings currently use `in_triage` with an analysis detail that
requires manual exploitability analysis.
