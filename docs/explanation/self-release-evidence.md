# Why Vexcalibur builds its own release evidence

Vexcalibur's self-release evidence exercises the same installed command-line
interface, CycloneDX input path, local-findings source, and output renderers
that a downstream user runs. The foundation is intentionally narrower than a
publication system: it builds and validates a local bundle but does not attach
assets to a GitHub Release or publish them elsewhere.

## Trust model

The bundle joins four independently reviewable inputs:

| Input | What it establishes | What it does not establish |
| --- | --- | --- |
| Exact release commit | Source identity and one fixed commit timestamp | That a working tree with other changes is publishable |
| `uv.lock` | The project's locked, cross-platform reference runtime | Every marker-selected resolution on every consumer platform |
| Local wheel | The installed Vexcalibur distribution used to render VEX; embedded SCM metadata must name the exact clean release commit | PyPI availability or equivalence with a future GitHub Action run |
| `release-evidence/review.json` and `findings.json` | A claimed, public review attribution and finding snapshot bound to the exact lock digest | Independent authentication of the reviewer or an assertion that unlisted vulnerabilities do not exist |

The repository's commit and pull-request history supplies provenance for the
claimed `reviewed_by` value. The JSON validator checks that the attribution is
present, but it cannot authenticate a person or substitute for repository
review policy.

The lock deliberately includes environment markers such as Windows-only and
older-Python dependencies. It describes the reference runtime that the project
locks across supported environments. A consumer's concrete installation will
select only the dependencies whose markers apply. Consumers that need evidence
for one deployed environment should generate an environment-specific SBOM and
VEX instead of treating this bundle as that inventory.

## Deterministic data flow

The generator performs this sequence:

1. It requires the requested 40-character commit to be the checked-out `HEAD`
   and rejects a dirty tree by default.
2. It derives `SOURCE_DATE_EPOCH` from that commit. A caller-supplied value must
   match the commit epoch.
3. Pinned `uv` exports the non-development lock graph as CycloneDX 1.5. The
   normalizer removes uv's random serial number and timestamp, applies the
   installed wheel version and PURL to the root component, inserts the lock
   digest, and sorts order-insensitive collections.
4. The generator reads exactly one
   `vexcalibur-*.dist-info/scm_version.json` member from the wheel. Its full Git
   node must equal the requested commit and `dirty` must be `false`.
5. `scripts/install-locked-wheel.sh` creates an isolated environment from
   hash-locked runtime requirements and the SHA-256-pinned local wheel.
6. The absolute `vexcalibur` console script in that environment runs outside
   the checkout with `--offline --findings-file`. Proxy variables point at an
   unreachable loopback port as an additional failure boundary.
7. Applicable format validators run before the manifest is written. The
   canonical CycloneDX assertion count must equal the reviewed count, including
   when different selector forms resolve to one component. The manifest and
   filename-sorted `SHA256SUMS` then bind the result.

The commit timestamp controls the normalized SBOM and all VEX timestamps. Temp
directory names, local wheel paths, uv's random UUID, and wall-clock time do not
enter the bundle. CI generates both the zero-finding and synthetic all-format
bundles twice in different temp directories and requires byte-for-byte equality.

## Honest empty evidence

The initial public findings file contains an empty array. The generated
CycloneDX 1.6 VEX document is schema-valid and records zero vulnerabilities.
OpenVEX 0.2.0 and the CSAF 2.0 VEX profile require at least one finding, so the
generator omits those files. `manifest.json` records both omissions, their
reasons, and an assertion count of zero.

Inventing a vulnerability would make the other file formats nonempty but would
destroy the evidence contract. Interpreting an empty source response as
`not_affected` would be worse: it would turn missing analysis into a strong
exploitability claim. The production policy therefore accepts only explicitly
reviewed `in_triage` findings. Stronger states need a separate evidence and
approval design.

## Synthetic conformance is separate

The fixture under `tests/fixtures/release-evidence/` contains one clearly
synthetic `in_triage` CVE and a reserved `.test` source URL. CI uses it to
generate CycloneDX, OpenVEX, and CSAF documents, then checks schema or official
tool conformance and compares normalized vulnerability, product PURL, and state
assertions across all three formats.

The fixture review has `review_kind: synthetic_fixture`; its manifest marks the
intended use as `ci_conformance_only`. The production generator requires an
explicit `--allow-synthetic` option before accepting it.

## Deferred boundaries

This foundation does not:

- query OSV or another live vulnerability service.
- permit `resolved`, `exploitable`, `false_positive`, or `not_affected` in the
  production snapshot.
- compare output with the companion GitHub Action.
- change the GitHub Release or PyPI workflows.
- publish, revise, supersede, or sign evidence bundles.

Those boundaries keep the first tranche reversible. The local bundle and its
validators can mature before publication receives credentials or mutates a
release.
