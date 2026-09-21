# Compatibility policy

The guarantees below apply to Vexcalibur 1.x. They do not retroactively apply
to 0.x releases. Pin an exact release in automation and read its release notes
before upgrading, regardless of the release series.

## Command line

Existing documented command names, option names, positional arguments,
defaults, and meanings remain compatible within 1.x. That includes the
documented subset of the `vexy` adapter, not every feature of the original
Vexy project. A minor release may add a command or an optional flag without
changing an existing invocation's meaning.

The [CLI reference](cli.md) defines each command's failures. The status
classes are:

| Status | Meaning |
| --- | --- |
| `0` | Success, including a help request |
| `1` | A handled configuration, input, provider, rendering, or output failure |
| `2` | A command-line syntax or parameter parsing error |

Some invalid combinations of otherwise parsed options return `1`, not `2`.
Use the command-specific table rather than assuming every invalid invocation
has the same status. Signals, interpreter failures, and unexpected defects
can produce other nonzero statuses. Automation must treat all nonzero
statuses as failure.

For `generate`, standard output is the VEX document unless `--output` selects
a file. An execution report is a separate machine-readable interface. Help
layout, completion scripts, diagnostic wording, and `query-osv`'s human-readable
summary are not parsing contracts. Do not extract structured results from
those messages.

Public-provider consent, offline mode, and GitHub credential-selection rules
are part of the documented behavior. A compatible release does not turn an
offline invocation into a network query or treat GitHub access as consent to
send inventory to public OSV.

## Python and extensions

The [Python API reference](python-api.rst) defines the supported exports from
`vexcalibur.api`, signatures, data types, exceptions, and deprecation rules.
Implementation-module imports are not supported extension points.

The [source protocol](provider-contract.md) and
[renderer protocol](renderer-contract.md) remain callable with their existing
signatures throughout 1.x. New features must not require existing providers
or renderers to implement another method or accept another argument. An
optional protocol or adapter can add behavior while preserving the original
call. Custom extensions remain trusted application code, not sandboxed code.

## Documents and reports

Existing format selectors keep their specification versions and meanings:

| Selector | Output specification |
| --- | --- |
| `cyclonedx` (default) | [CycloneDX 1.6](cyclonedx-vex-output.md) |
| `openvex` | [OpenVEX 0.2.0](openvex-output.md) |
| `csaf` | [CSAF 2.0 VEX profile](csaf-output.md) |
| `spdx3` | [SPDX 3.0.1 security profile](spdx3-output.md) |

The format references define analysis-state mappings, identity, provenance,
required evidence, grouping, and deliberate information loss. Schema-valid
output alone is not enough to satisfy that contract. A new format or
specification version must be opt-in; it cannot replace an existing selector's
output or change the default within 1.x.

For built-in renderers, repeatability means the same installed release,
input, findings, metadata, and timestamp produce the same output. Custom
sources and renderers own their repeatability; Vexcalibur cannot make
arbitrary extension code deterministic. The built-in guarantee does not
promise byte-identical
documents across package or dependency upgrades. Tool metadata, serialized
details, and content-derived document IDs can change. Retain the original
document and its report when exact bytes matter; do not regenerate an old
document to verify its digest.

The [execution report](execution-report.md) has its own schema version.
For existing invocations in 1.x, report fields, types, meanings, canonical
serialization, and accepted category values remain compatible with the
schema shipped at 1.0. Adding a required field or changing an existing value's
meaning needs a new schema, not just a new package version. A new report
schema must be opt-in during 1.x. Consumers reject unknown schemas rather
than guessing from the package version.

New opt-in features may add category values for those features, as SPDX 3
output did before 1.0. Existing invocations must still validate against their
reviewed schema copy. Adopt an updated schema before enabling a new feature;
do not weaken closed-world validation to make it pass.

## Release changes

Removing or incompatibly changing a supported interface requires a major
release. Deprecations are documented before removal and remain available for
the rest of 1.x. Minor releases can add compatible features. Patch releases
correct behavior within the documented contract.

A security fix may reject previously accepted unsafe input or tighten a
resource limit. Release notes must explain that exception and its operational
effect. It is not permission to change unrelated semantics in a patch.

The package, GitHub Action, and CircleCI Orb have independent release numbers.
A package compatibility promise does not imply that every wrapper release
supports it. Use the Action's
[tested-pair declaration](https://github.com/vexcalibur-dev/vexcalibur-action/blob/main/docs/reference/compatibility.md)
or the Orb's
[interface reference](https://github.com/vexcalibur-dev/vexcalibur-orb/blob/main/docs/reference/orb.md)
when choosing integration pins. Release tags are immutable; any future mutable
alias must be a branch.
