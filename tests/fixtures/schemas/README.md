# Vendored schemas

These files pin the external contracts used by offline conformance tests. They
are test fixtures, not runtime dependencies. Keep each file byte-for-byte
identical to its documented source so its checksum remains independently
verifiable.

## CSAF 2.0

`csaf-2.0.schema.json` is copied without modification from the immutable
[CSAF 2.0 OASIS Standard document schema](https://docs.oasis-open.org/csaf/csaf/v2.0/os/schemas/csaf_json_schema.json).

- OASIS tag: [`csaf-2.0-os`](https://github.com/oasis-tcs/csaf/tree/csaf-2.0-os)
- OASIS repository commit: [`a0b55d3b8a51f8e3d1ec94f03df3d48edf11c828`](https://github.com/oasis-tcs/csaf/commit/a0b55d3b8a51f8e3d1ec94f03df3d48edf11c828)
- SHA-256: `29c114b35b0a30831f1674f2ab8b3ed9b2890cfeaa63b924ac6ed9d70ef44262`
- Standard publication date: 2022-11-18

The schema is machine-readable content in the CSAF 2.0 OASIS Standard work
product: Copyright © OASIS Open 2022. It is redistributed here unmodified under
the copying and implementation permissions, conditions, and warranty disclaimer
in the Standard's [OASIS Notices](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#notices).
OASIS does not assign an SPDX license identifier to this work product; do not
describe the schema as Apache-2.0 merely because Vexcalibur's source code uses
that license.

Approved Errata 01 changed the aggregator schema, not the document schema. The
[Approved Errata 01 document schema](https://docs.oasis-open.org/csaf/csaf/v2.0/errata01/os/schemas/csaf_json_schema.json)
has the same SHA-256.

To verify the committed copy from the repository root:

```console
echo "29c114b35b0a30831f1674f2ab8b3ed9b2890cfeaa63b924ac6ed9d70ef44262  tests/fixtures/schemas/csaf-2.0.schema.json" \
  | sha256sum --check
```

To update it, choose a new stable OASIS publication and document its immutable
source, repository tag and commit, checksum, and standard version here. Replace
the file byte for byte, update the conformance pins as one reviewed change, and
run `make csaf-interop`. Do not fetch a mutable upstream branch during a
test run.

The document schema is only one conformance layer. CSAF also defines mandatory
semantic tests that JSON Schema cannot express. The pinned validator under
`tests/integration/csaf-validator/` runs those tests; a schema-valid document
is not necessarily a conformant CSAF VEX document.

The repository exposes three CSAF conformance targets:

- `make csaf-validator-install` installs the locked, CI-only Node validator.
- `make csaf-interop` checks this schema's hash and validates the checked-in
  golden with the strict/basic suite.
- `make installed-csaf-check` generates output from an isolated wheel and
  validates that output with the same suite.

## OpenVEX 0.2.0

`openvex-0.2.0.schema.json` is copied without modification from the
[OpenVEX specification repository](https://github.com/openvex/spec/blob/a68ccd19b15a9604d28ef66ebf33f27a772ba4ec/openvex_json_schema.json).
The pinned source commit is `a68ccd19b15a9604d28ef66ebf33f27a772ba4ec`, dated 2025-03-31.
The upstream specification repository publishes this schema under CC0-1.0.

To update it, choose and document a new upstream commit. Replace the file byte
for byte, then run the OpenVEX schema and interoperability tests. Do not follow
the upstream default branch during a test run.
