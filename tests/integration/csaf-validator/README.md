# CSAF 2.0 conformance harness

This directory contains Vexcalibur's CI-only semantic validator for CSAF 2.0
VEX output. It is deliberately separate from the Python package: installing or
running Vexcalibur does not install Node.js or a CSAF library.

The harness runs every function exported by the validator's `basic.js` suite
through `validateStrict`. The pinned suite contains 42 named mandatory tests
plus strict schema validation. Test 6.1.8 is covered by the strict schema test,
so the expected export count is 43 rather than 44.

## Pins

- Node.js: `24.14.1`, declared in the repository `.tool-versions`
- Validator: [`@secvisogram/csaf-validator-lib` 2.0.27](https://github.com/secvisogram/csaf-validator-lib/releases/tag/v2.0.27)
- Validator release commit: [`db0999f174b69e5857cef1434e1cbdf83a759b69`](https://github.com/secvisogram/csaf-validator-lib/commit/db0999f174b69e5857cef1434e1cbdf83a759b69)
- npm integrity: `sha512-QqpVNUs42BbgSR4k9cRIvOx33CX8cg5CuY8FpBwBKsimlz5aHL8m6Zc2SZ0mXSinBNqvAYD/pLZR6AjVFV9TwA==`

The lockfile pins transitive dependencies. npm lifecycle scripts are disabled
in `.npmrc` and explicitly disabled by the install command.

## Run the checks

From the repository root, with the versions in `.tool-versions` active:

```console
make csaf-validator-install
make csaf-interop
make installed-csaf-check
```

`make csaf-interop` first verifies the vendored OASIS schema checksum, then
validates the checked-in CSAF golden. `make installed-csaf-check` builds a wheel
when `VEXCALIBUR_WHEEL` is unset, installs it in an isolated environment,
generates a named CSAF document, and validates that output with this harness.

A successful semantic check ends with output shaped like:

```text
tests/golden/csaf-vex-all-analysis-states.json: valid (42 mandatory tests + strict schema)
```

The official schema fixture and its provenance are documented in
[`tests/fixtures/schemas/README.md`](../../fixtures/schemas/README.md). Both
layers matter: the OASIS schema cannot express every mandatory VEX profile
rule.

## Update the validator

Review validator upgrades as conformance changes, not routine formatting.
Confirm the upstream release and commit, set an exact version in `package.json`,
regenerate `package-lock.json` with the pinned Node.js toolchain, and record the
new integrity value above. Then run all three commands from the previous
section. If the basic-suite export count changes, compare the exports with the
applicable OASIS mandatory tests before updating `validate.mjs`.
