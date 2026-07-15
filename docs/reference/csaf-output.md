# CSAF output

`vexcalibur generate --format csaf` writes CSAF 2.0 JSON with the CSAF VEX
profile. A controlled timestamp and finding set produce repeatable output.
Vexcalibur implements the renderer directly without a CSAF runtime library.

Vexcalibur targets the [CSAF 2.0 OASIS
Standard](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html),
including the [Approved Errata 01
context](https://docs.oasis-open.org/csaf/csaf/v2.0/errata01/os/csaf-v2.0-errata01-os.html).
CSAF 2.1 remains [Committee Specification Draft
02](https://docs.oasis-open.org/csaf/csaf/v2.1/csd02/csaf-v2.1-csd02.html),
so this renderer does not silently opt users into it. `--csaf-version` accepts
only `2.0`.

## Document contract

| Field | Value |
| --- | --- |
| `document.category` | `csaf_vex` |
| `document.csaf_version` | `2.0` |
| `document.title` | Required `--csaf-document-title` value |
| `document.publisher.name` | Required `--csaf-publisher-name` value |
| `document.publisher.namespace` | Required normalized absolute publisher URL |
| `document.publisher.category` | `coordinator`, `discoverer`, `other`, `user`, or `vendor` |
| `document.tracking.id` | Required `--csaf-document-id` value |
| `document.tracking.status` | `draft` by default; optionally `final` or `interim` |
| `document.tracking.version` | `1` |
| `document.tracking.generator.engine.name` | `Vexcalibur` |
| `document.tracking.generator.engine.version` | Installed Vexcalibur version |
| `product_tree.full_product_names` | Flat list of products referenced by assertions |
| `vulnerabilities` | One object per vulnerability ID |

The initial release, current release, revision, and generator dates all use
`--timestamp`; when it is absent, generation uses current UTC. The sole
revision-history item has number `1`, summary `Initial version.`, and the same
date. A draft, final, or interim initial document still uses version `1`.

The root does not contain `$schema`: strict CSAF 2.0 validation rejects that
additional property. Vexcalibur does not invent `document.distribution`, TLP,
or other publication policy.

JSON keys and arrays are deterministic. Products, vulnerabilities, status
product IDs, references, notes, remediations, and threats have stable ordering.

## CLI metadata rules

These values are required with `--format csaf`:

- `--csaf-document-id`.
- `--csaf-document-title`.
- `--csaf-publisher-name`.
- `--csaf-publisher-namespace`.
- `--csaf-publisher-category`.

The namespace must be a normalized absolute HTTP or HTTPS URL controlled by
the publisher. Supply an ASCII RFC 3986 URI. Encode an internationalized host
with IDNA and percent-encode non-ASCII path characters. Malformed escapes and
raw Unicode are rejected because they would fail CSAF schema validation.

The document ID cannot contain a line terminator. The category does not accept
`translator`, because Vexcalibur produces a new document rather than
translating an existing CSAF advisory.

`--csaf-document-status` defaults to `draft` and accepts `draft`, `final`, or
`interim`. `--csaf-version` has a semantic default of `2.0` and rejects other
versions. Every CSAF option is rejected for CycloneDX or OpenVEX output.
OpenVEX's `--author` and `--author-role` are rejected for CSAF.

The CLI validates format metadata before fetching a GitHub SBOM or querying a
finding service.

## Product identity

Only products referenced by assertions appear in the output. Each distinct
canonical product package URL becomes one `full_product_names` entry with:

- a human-readable name that includes the version.
- a stable `CSAFPID-<uuid>` derived from the canonical versioned package URL.
- `product_identification_helper.purl` set to that URL.

When a component has an unversioned package URL and a separate version,
Vexcalibur adds the known version. It rejects an assertion when both fields are
unversioned because that identity could apply to every version of the package.

Identical products collapse into one entry. Duplicate component references,
unknown references, and finding package URLs that disagree with their
component are rejected before rendering. One vulnerability and product may
have only one effective CSAF status. Same-status provenance and evidence may be
grouped, but contradictory statuses for that pair are a conflict.

The renderer deliberately uses a flat product tree. It does not emit product
branches, groups, relationships, ranges, or a complete SBOM hierarchy.

## Vulnerability identity and provenance

Assertions are grouped into one vulnerability object per vulnerability ID.
An ID matching `^CVE-[0-9]{4}-[0-9]{4,}$` appears in `cve`. Every other ID
appears in `ids` with its source name.

Distinct source URLs become external references. They must use the same ASCII
RFC 3986 URI encoding as the publisher namespace. Each vulnerability has at
least one `details` note. Notes preserve the applicable CSAF product IDs,
analysis detail, original Vexcalibur state, source, source-record modification
time, and confirmed fixed version when present.

CSAF 2.0 cannot bind vulnerability notes structurally to products. Vexcalibur
therefore includes the applicable product IDs in note text. Product-scoped
notes from CSAF 2.1 are outside this renderer's contract.

A finding's `modified` value describes an upstream source record. It stays in
notes and never becomes a CSAF document release, revision, or generator date.

## State and evidence mapping

| Vexcalibur state | CSAF product status | Required evidence | Emitted structure |
| --- | --- | --- | --- |
| `resolved` | `fixed` | `fixed_version` equal to the emitted product version | Product ID in `product_status.fixed`; confirmed version in notes |
| `exploitable` | `known_affected` | `action_statement` and `remediation_category` | Product ID in `known_affected`; product-scoped remediation |
| `in_triage` | `under_investigation` | None | Product ID in `under_investigation` |
| `false_positive` | `known_not_affected` | `impact_statement` | Product ID in `known_not_affected`; product-scoped impact threat; original state in notes |
| `not_affected` | `known_not_affected` | `impact_statement` | Product ID in `known_not_affected`; product-scoped impact threat |

The `false_positive` mapping is lossy because CSAF 2.0 has no separate status
for it. Keeping the original state and product IDs in notes lets a consumer see
why the broad status was selected.

An affected remediation uses the supplied action as `details`, the supplied
remediation category as `category`, and all covered products in `product_ids`.
Accepted categories are `mitigation`, `no_fix_planned`, `none_available`,
`vendor_fix`, and `workaround`.

An unaffected impact uses the supplied impact statement as a `threat` with
category `impact` and its covered products in `product_ids`.

Vexcalibur groups identical action or impact evidence across products. It does
not infer a category, action, impact, or machine-readable status from prose.
Every affected or unaffected product remains explicitly covered by its
evidence object.

## Filename contract

For direct file output, the basename is derived from
`document.tracking.id`:

1. Lowercase the ID.
2. Replace every run matching `[^+\-a-z0-9]+` with one underscore. This
   includes existing underscores.
3. Append `.json`.

`ACME VEX:2026/001` therefore requires `acme_vex_2026_001.json`. Directories
do not affect the comparison. The rule does not apply to standard output.

The CSAF document validator receives parsed JSON and cannot inspect an external
filename, so the repository tests this rule separately.

## Validation

The repository vendors the immutable OASIS Draft 2020-12 document schema from
the `csaf-2.0-os` tag at commit
`a0b55d3b8a51f8e3d1ec94f03df3d48edf11c828`. Its SHA-256 is
`29c114b35b0a30831f1674f2ab8b3ed9b2890cfeaa63b924ac6ed9d70ef44262`.
Approved Errata 01 uses a byte-identical document schema.

Schema validation is necessary but not sufficient. CSAF also defines
mandatory semantic tests. CI runs the golden and installed-wheel output
through [`@secvisogram/csaf-validator-lib`
2.0.27](https://github.com/secvisogram/csaf-validator-lib/releases/tag/v2.0.27)
on Node 24. The pinned suite
executes 42 separately exported mandatory tests plus strict schema validation;
mandatory test 6.1.8 is covered by that schema test.

The validator release commit is
`db0999f174b69e5857cef1434e1cbdf83a759b69`. The committed npm lockfile records
integrity
`sha512-QqpVNUs42BbgSR4k9cRIvOx33CX8cg5CuY8FpBwBKsimlz5aHL8m6Zc2SZ0mXSinBNqvAYD/pLZR6AjVFV9TwA==`.
CI installs that lock with `npm ci --ignore-scripts`; it does not resolve a
mutable upstream branch.

The strict suite catches conditions that the official schema alone accepts,
including unknown properties, contradictory product statuses, an affected
product without a scoped remediation, and an unaffected product without a
scoped impact threat.

The Node validator is a test dependency, not a Python runtime dependency.
Vexcalibur enforces its renderer contract before serialization, while the two
independent validation layers guard the committed output and packaged CLI.

## Validation errors

Rendering stops with a format error when:

- required document or publisher metadata is empty or invalid.
- the publisher category or document status is unsupported.
- a finding list is empty.
- a finding references an unknown component or mismatched package URL.
- an emitted product lacks a precise version.
- a required action, impact, category, or fixed version is missing.
- an evidence field appears on a state where it is not valid.
- a fixed version differs from the emitted product version.
- one vulnerability and product have contradictory effective statuses.
- component references are duplicated.
- direct output uses a basename that does not match the tracking ID.

## Scope

CSAF support is output-only and creates an initial `csaf_vex` document. It
does not read CSAF, convert between VEX formats, model later revisions, produce
trusted-provider metadata, add distribution policy or TLP, sign documents, or
publish them.
