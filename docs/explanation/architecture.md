# Architecture and trust boundaries

Vexcalibur separates package inventory, source access, provider findings, atomic assertions, and VEX rendering. Provider rules stay out of the output writer. Format rules stay out of network clients.

## Generation flow

This diagram traces inventory through one finding source and one renderer. The
report-aware path retains the normalized values used at those boundaries.

```text
CycloneDX JSON/XML file       GitHub Dependency Graph SBOM
        |                                 |
        v                                 v
   sbom loader                    GitHub SBOM client
        |                                 |
        +----------------+----------------+
                         |
                         v
              ComponentIdentity values
                         |
                         v
           one VulnerabilitySource adapter
                  /                 \
                 v                   v
       OSV-compatible API      local findings JSON
                  \                 /
                   v               v
              VulnerabilityFinding values
                         |
                         v
                 selected VexRenderer
                   /             \
                  v               v
          custom renderer    built-in adapter
                  |               |
                  |               v
                  |          VexDocument
                  |      atomic assertions
                  |               |
                  |       +-------+-------+-------+
                  |       |               |       |
                  |       v               v       v
                  |  CycloneDX 1.6   OpenVEX   CSAF 2.0
                  |                   0.2.0      VEX
                  |       \               |       /
                  +--------+--------------+------+
                           |
                           v
                    GenerationResult
                       /         \
                      v           v
              VEX JSON bytes   complete context?
                               /            \
                             no              yes
                             |                |
                             v                v
                    report unavailable   execution report
                                       counts, categories,
                                         digest, and size
```

The two inventory paths meet at `ComponentIdentity`. The two finding paths meet at `VulnerabilityFinding`. This remains the documented custom-renderer interface.

Generation returns an immutable `GenerationResult` before either output is
written. It contains the rendered document plus the normalized components and
findings used by the renderer. Its UTF-8 bytes are calculated once, when a
caller first needs them. Built-in workflows also retain source categories and
the selected format, so an execution report cannot relabel a completed
operation. Custom sources and renderers can provide the same context explicitly
when Vexcalibur cannot infer it.

## Inventory boundary

`vexcalibur.sbom` handles local CycloneDX JSON and XML. A shared input reader opens each path once in nonblocking mode, verifies the opened target is a regular file, and reads no more than the configured limit from that descriptor. Symbolic links to regular files remain usable, while FIFOs, devices, and links to them fail before a read can block.

A shared JSON decoder rejects duplicate keys, excessive nesting, oversized integers, invalid UTF-8, and malformed syntax for CycloneDX, local findings, GitHub SPDX, and OSV responses. CycloneDX XML uses its hardened XML path. The inventory loaders also apply component-count, package URL, duplicate-reference, and XML checks before they return components.

`vexcalibur.github_sbom` handles GitHub's asynchronous Dependency Graph API. It requests the SPDX 2.3 JSON report and waits for the download. It then validates the response and extracts package URL references. Multiple equivalent references collapse to their canonical package URL; multiple distinct package URLs for one package are ambiguous and rejected. Both loaders produce the same component fields.

Components without package URLs do not cross this boundary. Source adapters need package identity, and a VEX `affects` entry needs a stable component reference.

The component model has one version rule across local files, GitHub SPDX, OSV queries, and rendering. A PURL version is authoritative when present. A separate CycloneDX `version` or SPDX `versionInfo` is the fallback for an unversioned PURL. When both exist, their decoded values must match.

## Finding-source boundary

A `VulnerabilitySource` receives all normalized components and returns `VulnerabilityFinding` values.

`OsvSource` builds version-specific OSV queries and maps matches to findings.
It carries the effective service provenance into every finding. Only the
canonical public endpoint receives the official OSV name and URL. A mirror
uses its own canonical endpoint unless the caller supplies an explicit public
name-and-URL alias. `LocalFindingsSource` validates a JSON file. It matches each
item by component reference or unique package URL.

Provider-specific request and parsing logic stays inside the adapter.

`VulnerabilitySourceInputError` means the inventory cannot form valid provider input. Other source failures inherit from `VulnerabilitySourceError`, with provider-specific subclasses for useful error categories.

## Document boundary

The built-in renderers adapt components and findings into an immutable `VexDocument`. Each `VexAssertion` connects one vulnerability to one product. Products keep their source component reference, so two SBOM components with the same package URL remain distinct.

The model uses four broad dispositions: `fixed`, `affected`, `under_investigation`, and `not_affected`. Qualifiers retain narrower provider meaning. For example, `exploitable` becomes `affected` with an `exploitable` qualifier, while `false_positive` becomes `not_affected` with a `false_positive` qualifier.

The adapter rejects duplicate component references, unknown references, finding package URLs that disagree with their component, contradictory product versions, and vulnerability source URLs containing userinfo. It removes exact duplicate assertions but keeps records that differ in source, state, analysis, or evidence. Each renderer decides whether its format can represent those records together.

This model represents generated snapshots only. Vexcalibur still does not read VEX documents or convert between formats.

The document model is an internal pre-1.0 model. It is not yet a stable public API.

## Network boundary

An SBOM can expose internal package names, exact versions, and dependency choices. Vexcalibur does not treat a vulnerability lookup as harmless metadata access.

Public OSV fails closed until the caller passes `--allow-public-osv`. A private mirror uses `--osv-url`. Local findings do not create an OSV client.

Library helpers perform the same public-endpoint check when they can identify the client's effective URL.

The OSV client treats a compatible service as untrusted. It disables redirects
for every request, even when an injected HTTP client normally follows them. It
streams raw success and error bodies through independent encoded and decoded
budgets. Gzip is decompressed in bounded chunks, and the wall-clock deadline is
checked for every transport chunk, so slow-drip and compressed responses cannot
defer enforcement. Those budgets are shared across pagination and batch
chunks. The client also limits tokens and identifiers, deduplicates normalized
IDs across pages, and retains the newest reported modification time without
changing first-seen ID order. The public API's 1,000-query batch maximum is an
individual request boundary, so a larger accepted inventory is split into
ordered chunks under the same operation budget.

Before provider results become domain findings, the source counts the complete
component-and-vulnerability relation set. It rejects an over-limit expansion
before allocating the individual findings. This prevents repeated package URLs
and large result sets from turning two bounded inputs into an unbounded
Cartesian product.

Fetching a GitHub SBOM is a separate choice. `--github-repo` permits that input request, but it does not permit a later public OSV query. This is also why `--github-repo` and `--offline` conflict.

## Rendering boundary

`VexRenderer` separates generation from a serialization format. Its component-and-finding signature remains available to custom renderers. The `generate_vex_from_*` helpers use `CycloneDxJsonRenderer` unless a caller supplies another renderer.

Generation measures every renderer result as UTF-8 and rejects output over the
shared limit before the CLI writes it. A renderer that uses one of
Vexcalibur's built-in `render_document` methods also gets an allocation-free
preflight bound for repeated, JSON-escaped, and derived package-URL text. An
empty subclass still uses the built-in method, so it keeps that protection.
The estimate considers only products referenced by findings and scales
OpenVEX versioned package URLs per finding. Grouping can make the eventual
document smaller than this bound, so preflight may reject before the exact
limit. A subclass that overrides serialization, like any other custom
renderer, uses the post-render check because Vexcalibur doesn't know its
expansion rules. Built-in OSV relation expansion is bounded before findings
are materialized.

The built-in renderers also implement `VexDocumentRenderer`. Their compatibility method creates the atomic document, then delegates to the document renderer.

`vexcalibur.vex` renders CycloneDX 1.6 JSON. `vexcalibur.openvex` renders
OpenVEX 0.2.0 JSON. `vexcalibur.csaf` renders CSAF 2.0 JSON with the VEX
profile. Each renderer owns grouping, required metadata, validation, and state
mapping.

OSV says that a vulnerability matches a package version; it does not decide exploitability for a particular deployment. OSV findings therefore enter VEX as `in_triage`. A local finding can carry a reviewed state such as `not_affected` or `exploitable`.

The atomic document boundary is where another output format can fit. A new format still needs an explicit semantic mapping. Similar field names do not guarantee that states, products, provenance, or timestamps mean the same thing.

Format conversion should expose any loss or default instead of hiding it in serialization code.

OpenVEX demonstrates this rule. It collapses `false_positive` into
`not_affected` and records the original state in notes. It emits `resolved` as
`fixed` only when `fixed_version` matches the identified product.

CSAF makes a different set of tradeoffs. It collapses `false_positive` and
`not_affected` into `known_not_affected`, then preserves the narrower state and
applicable product IDs in notes. An `exploitable` assertion needs both action
text and a machine-readable remediation category before it can become
`known_affected`. A not-affected assertion needs an impact statement. The
renderer places that evidence in product-scoped remediation and threat
objects.

The OpenVEX renderer requires explicit action and impact statements for the
states that need them. It also rejects nonidentical assertions for one
vulnerability and product. CSAF can group same-status provenance and evidence,
but rejects contradictory effective statuses for that pair.

Source `modified` timestamps describe upstream records. The OpenVEX renderer
does not claim they are statement revision times. CSAF likewise keeps them in
vulnerability notes rather than document tracking dates. The CycloneDX
renderer can place them in vulnerability `updated` because that field describes
the vulnerability record.

## Execution-report boundary

`vexcalibur.generation_result` derives a report from one `GenerationResult`.
It does not parse the rendered VEX document. Known inventory, source, and
format facts come from the generation path, so a caller-supplied context cannot
contradict them. Explicit context uses a `custom` category for an inventory,
source, or renderer that Vexcalibur cannot classify. This records the extension
without assigning it a built-in identity.

Counts come from the normalized domain values. The digest and byte size use the
same cached UTF-8 bytes that the report-aware CLI path emits.

The report-aware file writer uses one private lock below each destination's
parent directory. It acquires the needed directory locks in a stable order and
holds them until it has published both files. This serializes report-aware
writes that share a parent, but it also gives every process the same lock
without relying on locale-sensitive filename normalization. The report remains
the final success marker.

The writer tracks that work with one transaction state and one rollback guard.
The guard belongs to the transaction before it acquires any file descriptors,
so an interrupted acquisition cannot leave a completed report outside the
transaction's cleanup path.

| State | Destinations and permitted next steps |
| --- | --- |
| `PREPARED` | The stale report is gone and the bound destination descriptors remain open. The transaction can start one commit, abort, or close without publishing. |
| `COMMITTING` | Private files may exist, and the VEX document may be published. The transaction can begin acquiring the report rollback guard or move to cleanup after a failure. It does not restore a replaced VEX document. |
| `REPORT_GUARD_ARMING` | The transaction owns the guard while it acquires the lock, parent, and report identity descriptors. A completed acquisition enters `REPORT_GUARDED`; any interruption enters `ABORT_REQUIRED`. |
| `REPORT_GUARDED` | The transaction owns the report's identity-bound rollback guard. It can publish the report and enter `COMMITTED`, or enter `ABORT_REQUIRED` and remove only the report it published. |
| `COMMITTED` | The VEX document and report were published in that order. Finalization can begin releasing the rollback guard, or an earlier failure can move to `ABORT_REQUIRED` while complete removal authority remains. |
| `FINALIZING` | Rollback authority is being released. Cleanup retries descriptors whose ownership remains known. Once release has crossed its point of no return, cleanup does not turn the valid publication into a failed command. |
| `ABORT_REQUIRED` | Cleanup preserves the VEX document, removes the report when its identity still matches, and releases every descriptor whose ownership is known. Only successful cleanup enters `CLOSED`. |
| `CLOSED` | The transaction owns no retryable descriptors and cannot commit again. |

Report removal has a separate durability state. The guard enters
`PUBLICATION_PENDING` before replacement starts, then enters `PUBLISHED` only
after the report and its directory entry are flushed. Cleanup enters
`REMOVAL_PENDING` before it unlinks the report and stays there until the parent
directory `fsync` succeeds. A retry flushes that directory again even when the
report path is already absent. If descriptor release becomes ambiguous, the
writer does not reuse that numeric descriptor or claim that cleanup completed.
Before finalization crosses its point of no return, the command fails and removes
the report. After that point, the valid report remains and the command succeeds;
the transaction stays in `FINALIZING` so known descriptors can be retried.

Each private staged file has its own validated lifecycle: `STAGED`,
`PUBLISHING`, `PUBLISHED`, `ROLLBACK_REQUIRED`, `ROLLED_BACK`, and `RELEASED`.
The state decides whether cleanup removes the temporary file, removes the
published identity, or preserves a committed destination. Descriptor value and
ownership also move together as one state, so an ambiguous release cannot be
mistaken for a closed destination.

The file-output path follows this order:

```text
GenerationResult
      |
      +--> stage report bytes (private temporary file)
      |
      +--> stage VEX bytes (private temporary file)
      |
      +--> acquire output and report directory locks in stable order
              |
              +--> remove any intervening report; stop before output on failure
              |
              +--> publish VEX
              |
              +--> recheck report aliases and the exact published VEX identity
              |
              +--> publish report last
              |
              +--> recheck the VEX parent and published identity
```

An error before VEX publication removes both temporary files. An error after
VEX publication can leave a valid VEX file without a report, so consumers must
require exit status `0` and a valid report. The report is never published
before the document it describes.

Standard output is different because Vexcalibur cannot stage or roll back a
partial stream write. It holds a per-report sequence lock while it removes an
intervening report, writes and flushes the document, and publishes the report.
The directory lock is held only for the report removal and publication, not
while the stream can block. See the
[execution report reference](../reference/execution-report.md) for the
concurrency boundary when an embedding shares one output stream across
multiple report destinations.

The report omits package names and URLs, vulnerability IDs, repository names,
filesystem paths, provider URLs, credentials, and exception text. Counts,
categories, the package version, and a document digest can still be sensitive
build metadata. The closed-world schema and fixed size limit make the report
bounded, but they do not make it public data.

## Legacy command boundary

The `vexy` executable maps a small legacy command surface to the same loaders, sources, and renderer. It does not parse legacy credentials or revive OSS Index. Keeping the adapter thin preserves Vexcalibur's source validation and public-service policy.

See the [provider contract](../reference/provider-contract.md) for source
extension rules. Read the [CycloneDX](../reference/cyclonedx-vex-output.md),
[OpenVEX](../reference/openvex-output.md), and
[CSAF](../reference/csaf-output.md) references for renderer contracts.
