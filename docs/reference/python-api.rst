Python API
==========

The Python API is pre-1.0. Import paths, signatures, exceptions, and return
shapes may change between releases.

Domain objects
--------------

.. automodule:: vexcalibur.domain
   :members:
   :show-inheritance:

SBOM ingest
-----------

Use ``load_cyclonedx_sbom`` for an untrusted CycloneDX file. It enforces file,
component, nesting, package URL, XML, and duplicate-reference rules before it
returns component identities. ``load_cyclonedx_json`` is the JSON-only
compatibility helper.

.. list-table:: Loader contract
   :header-rows: 1

   * - Loader
     - Input
     - Limits and filtering
   * - ``load_cyclonedx_sbom``
     - CycloneDX JSON or XML 1.4, 1.5, or 1.6. JSON must be UTF-8. XML may use
       a parser-detected encoding.
     - Requires a regular file target and reads at most 10 MiB from one opened
       descriptor. Symbolic links to regular files are accepted. Rejects more
       than 10,000 components, nesting beyond 50 component levels,
       contradictory explicit and package URL versions, malformed package
       URLs, duplicate returned references, and XML DTD, entity, or
       external-reference declarations. Components without package URLs are
       omitted.
   * - ``load_cyclonedx_json``
     - UTF-8 CycloneDX JSON 1.4, 1.5, or 1.6.
     - Applies the same file, component, nesting, package URL, version, and
       reference checks as ``load_cyclonedx_sbom``. JSON also rejects duplicate
       keys, more than 100 nested arrays or objects, and integer literals longer
       than 1,000 decimal digits.
   * - ``component_identities_from_github_spdx_sbom``
     - A decoded GitHub Dependency Graph SPDX 2.3 JSON response.
     - Applies the component, package URL, version, and reference checks. It
       rejects multiple distinct package URLs for one SPDX package and omits
       packages without package URLs and the repository package itself.

All three return component identities sorted by package URL and reference.

.. automodule:: vexcalibur.sbom
   :members: SbomError, load_cyclonedx_sbom, load_cyclonedx_json

GitHub SBOM client
------------------

``GithubSbomClient`` requests a repository Dependency Graph SBOM and returns
the same component identities as local ingest. Public repositories may work
without a token, subject to GitHub rate limits. Token-backed requests need
repository read access. Generation helpers accept any
``GithubSbomComponentLoader`` implementation. A custom loader runs in the
caller's process and must return normalized ``ComponentIdentity`` values in a
tuple. It owns authentication, network policy, timeouts, and retries. Its
exceptions propagate unchanged, so the loader must document them for callers.

.. automodule:: vexcalibur.github_sbom
   :members: GithubSbomError, GithubSbomConfigurationError, GithubSbomClientError, GithubSbomComponentLoader, GithubRepository, GithubSbomClient, component_identities_from_github_spdx_sbom, parse_github_repository, normalize_github_api_url, resolve_github_token
   :show-inheritance:

Generation
----------

Generation helpers use CycloneDX when ``renderer`` is omitted. Pass an
``OpenVexJsonRenderer`` to select OpenVEX and supply its author metadata::

   from pathlib import Path

   from vexcalibur.generate import generate_vex_from_local_findings
   from vexcalibur.openvex import OpenVexJsonRenderer

   document = generate_vex_from_local_findings(
       input_file=Path("sbom.json"),
       findings_file=Path("findings.json"),
       renderer=OpenVexJsonRenderer(
           author="Example Security Team",
           role="VEX document producer",
       ),
   )

``Csaf20VexJsonRenderer`` accepts explicit tracking and publisher metadata::

   from pathlib import Path

   from vexcalibur.csaf import (
       Csaf20DocumentMetadata,
       Csaf20VexJsonRenderer,
       CsafDocumentStatus,
       CsafPublisherCategory,
   )
   from vexcalibur.generate import generate_vex_from_local_findings

   metadata = Csaf20DocumentMetadata(
       document_id="ACME-VEX-2026-001",
       title="ACME component exploitability assessment",
       publisher_name="ACME Product Security",
       publisher_namespace="https://security.example.test",
       publisher_category=CsafPublisherCategory.VENDOR,
       status=CsafDocumentStatus.FINAL,
   )
   document = generate_vex_from_local_findings(
       input_file=Path("sbom.json"),
       findings_file=Path("findings.json"),
       renderer=Csaf20VexJsonRenderer(metadata),
   )

The compatibility helpers return the rendered document as ``str``. Their
matching ``*_result`` helpers return ``GenerationResult``, which keeps the
normalized components and findings used by the renderer. Generation rejects
rendered output larger than 25 MiB of UTF-8.

The result helpers differ in how they establish inventory provenance:

.. list-table:: Result helper contract
   :header-rows: 1

   * - Helper
     - Inventory category
     - Source category
     - Routine failures
   * - ``generate_vex_from_components_result``
     - ``CUSTOM``. The caller supplied normalized components.
     - Inferred from the exact source type or its ``CUSTOM`` declaration.
     - ``SbomError`` for empty components or
       ``VulnerabilitySourceInputError``; ``LocalFindingsError``,
       ``OsvConfigurationError``, or ``OsvClientError`` from those built-in
       sources; ``VexRenderError`` for invalid or oversized output;
       ``TypeError`` for mistyped values; ``ValueError`` for contradictory
       context.
   * - ``generate_vex_from_source_result``
     - ``SBOM_FILE`` after local CycloneDX validation.
     - Inferred from the exact source type or its ``CUSTOM`` declaration.
     - ``SbomError`` for local inventory or source-input failures;
       ``LocalFindingsError``, ``OsvConfigurationError``, or
       ``OsvClientError`` from those built-in sources; ``VexRenderError`` for
       invalid or oversized output; ``TypeError`` for mistyped values;
       ``ValueError`` for contradictory context.
   * - ``generate_vex_from_sbom_result``
     - ``SBOM_FILE`` after local CycloneDX validation.
     - ``PUBLIC_OSV`` or ``CUSTOM_OSV`` from the effective guarded endpoint.
     - ``SbomError``, ``OsvConfigurationError``, ``OsvClientError``,
       ``VexRenderError``, ``TypeError``, or ``ValueError``.
   * - ``generate_vex_from_github_source_result``
     - ``GITHUB_DEPENDENCY_GRAPH`` when Vexcalibur creates or receives an exact
       ``GithubSbomClient``. Another injected loader is ``CUSTOM``.
     - Inferred from the exact source type or its ``CUSTOM`` declaration.
     - ``GithubSbomError``; ``OsvConfigurationError``, ``OsvClientError``, or
       ``LocalFindingsError`` for those built-in sources; ``VexRenderError``;
       ``TypeError``; ``ValueError``; or an injected loader's documented
       exception, propagated unchanged.
   * - ``generate_vex_from_github_sbom_result``
     - ``GITHUB_DEPENDENCY_GRAPH`` when Vexcalibur creates or receives an exact
       ``GithubSbomClient``. Another injected loader is ``CUSTOM``.
     - ``PUBLIC_OSV`` or ``CUSTOM_OSV`` from the effective guarded endpoint.
     - ``GithubSbomError``, ``OsvConfigurationError``, ``OsvClientError``,
       ``VexRenderError``, ``TypeError``, ``ValueError``, or an injected
       loader's documented exception, propagated unchanged.
   * - ``generate_vex_from_local_findings_result``
     - ``SBOM_FILE`` after local CycloneDX validation.
     - ``LOCAL_FILE`` after local findings validation.
     - ``SbomError``, ``LocalFindingsError``, ``VexRenderError``,
       ``TypeError``, or ``ValueError``.

Custom source and renderer exceptions propagate unchanged unless the source
raises ``VulnerabilitySourceInputError``, which Vexcalibur converts to
``SbomError``. Catch an extension's documented exception in addition to the
classes above.

Every helper passes plain ``tuple`` objects to the source and renderer. Sources
return ``VulnerabilityFinding`` values in a tuple. Renderers return UTF-8
encodable text.

The compatibility helpers preserve extension object identities. The
``*_result`` helpers isolate each extension boundary instead. They copy
component and finding subclasses into exact ``ComponentIdentity`` and
``VulnerabilityFinding`` values, give the renderer separate copies, and retain
private primitive snapshots for the result. Subclass-only state is not
retained.

.. automodule:: vexcalibur.generate
   :members: generate_vex_from_components, generate_vex_from_components_result, generate_vex_from_source, generate_vex_from_source_result, generate_vex_from_sbom, generate_vex_from_sbom_result, generate_vex_from_github_source_result, generate_vex_from_github_sbom, generate_vex_from_github_sbom_result, generate_vex_from_local_findings, generate_vex_from_local_findings_result

.. _execution-reports-python-api:

Execution reports
-----------------

The built-in result helpers retain source categories and the selected output
format while they generate the document. Call
``GenerationResult.execution_report`` to derive counts, state totals, a digest,
the byte size, and the installed Vexcalibur version without parsing the VEX
document.

Write the document from ``rendered_bytes`` so the saved bytes match the report
on every platform. Run this source-checkout example from the repository root
after ``uv sync --frozen``:

.. literalinclude:: ../examples/generate_execution_report.py
   :language: python
   :linenos:

Run the example with a new output directory:

.. code-block:: bash

   uv run --frozen python docs/examples/generate_execution_report.py \
     /tmp/vexcalibur-python-api

The example refuses to reuse the directory or replace either file. On POSIX it
sets the directory to mode ``0700`` and both files to ``0600``. On Windows,
access follows the parent directory's access control list.

Validate the files together before automation accepts either one:

.. code-block:: bash

   uv run --frozen python docs/examples/validate_execution_report.py \
     /tmp/vexcalibur-python-api/execution-report.json \
     /tmp/vexcalibur-python-api/vex.json \
     docs/execution-report-v1.schema.json

The validator prints ``execution report verified`` on success.

On Windows, use a new directory under ``$env:TEMP`` for both commands:

.. code-block:: powershell

   $ErrorActionPreference = "Stop"
   $work = Join-Path $env:TEMP ([Guid]::NewGuid().ToString())
   try {
     uv run --frozen python docs/examples/generate_execution_report.py $work
     uv run --frozen python docs/examples/validate_execution_report.py `
       (Join-Path $work "execution-report.json") `
       (Join-Path $work "vex.json") `
       docs/execution-report-v1.schema.json
   } finally {
     Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
   }

The second command prints ``execution report verified`` on success. Windows
permissions inherit the access control list of ``$env:TEMP``.

The two file writes are independent and non-atomic. They do not provide the
CLI's Linux and macOS staging, alias checks, or report-last success marker. An
embedding that needs those guarantees must provide its own transaction.

The report is evidence about one generation operation, not a vulnerability
policy verdict. A zero ``finding_count`` says only that the selected source
returned no normalized findings. The embedding still decides whether that
result passes its policy.

``InventorySourceCategory``, ``FindingSourceCategory``, and
``ExecutionReportOutputFormat`` define the accepted report context. Their
``CUSTOM`` members describe an inventory, source, or renderer that the
embedding owns and Vexcalibur cannot classify. Pass a
``GenerationExecutionContext`` to any ``*_result`` helper for those extensions.
Vexcalibur rejects context that contradicts a fact it can infer.

``ExecutionReportOutputFormat`` is separate from the CLI's ``VexOutputFormat``.
The CLI enum contains only formats that Vexcalibur can select itself, while an
embedding can use ``ExecutionReportOutputFormat.CUSTOM`` for its own renderer.

.. list-table:: Execution-report category values
   :header-rows: 1

   * - Enum member
     - Serialized value
     - Meaning
   * - ``InventorySourceCategory.SBOM_FILE``
     - ``sbom_file``
     - A local CycloneDX file loaded by Vexcalibur.
   * - ``InventorySourceCategory.GITHUB_DEPENDENCY_GRAPH``
     - ``github_dependency_graph``
     - A GitHub Dependency Graph SBOM loaded by Vexcalibur.
   * - ``InventorySourceCategory.CUSTOM``
     - ``custom``
     - Components supplied by an embedding or another injected inventory
       loader.
   * - ``FindingSourceCategory.LOCAL_FILE``
     - ``local_file``
     - A local findings file loaded by Vexcalibur.
   * - ``FindingSourceCategory.PUBLIC_OSV``
     - ``public_osv``
     - The canonical public OSV endpoint, after explicit consent.
   * - ``FindingSourceCategory.CUSTOM_OSV``
     - ``custom_osv``
     - A noncanonical OSV-compatible endpoint.
   * - ``FindingSourceCategory.CUSTOM``
     - ``custom``
     - Another source declared by an embedding.
   * - ``ExecutionReportOutputFormat.CYCLONEDX``
     - ``cyclonedx``
     - CycloneDX VEX JSON.
   * - ``ExecutionReportOutputFormat.OPENVEX``
     - ``openvex``
     - OpenVEX JSON.
   * - ``ExecutionReportOutputFormat.CSAF``
     - ``csaf``
     - CSAF 2.0 JSON.
   * - ``ExecutionReportOutputFormat.CUSTOM``
     - ``custom``
     - Another renderer declared by an embedding.

The report classes validate their complete constructor state:

.. list-table:: Execution-report class contracts
   :header-rows: 1

   * - Class
     - Field constraints
     - Failures
   * - ``GenerationExecutionContext``
     - ``inventory_source``, ``finding_source``, and ``output_format`` must be
       members of their corresponding enums.
     - ``TypeError`` for any mistyped category.
   * - ``GenerationResult``
     - ``rendered_document`` is exact built-in ``str``; ``components`` and
       ``findings`` are tuples containing their corresponding domain types;
       ``execution_context`` is optional. The first ``execution_report`` call
       snapshots and validates the installed package version.
     - ``TypeError`` for invalid constructor values; ``VexRenderError`` when
       ``rendered_bytes`` cannot encode strict UTF-8;
       ``GenerationReportMetadataError`` when package metadata is unavailable
       or unsafe; ``ValueError`` when report context is unavailable.
   * - ``GeneratedDocumentMetadata``
     - ``sha256`` is 64 lowercase hexadecimal characters. ``bytes`` is an
       integer from zero through 25 MiB.
     - ``ValueError`` for an invalid digest or byte count.
   * - ``GenerationExecutionReport``
     - Schema version and command are fixed; package version is report-safe;
       counts are nonnegative; state counts are positive, unique, follow
       ``resolved``, ``exploitable``, ``in_triage``, ``false_positive``, then
       ``not_affected`` order when present, and sum to ``finding_count``;
       ``document`` is
       ``GeneratedDocumentMetadata``.
     - ``TypeError`` for mistyped categories, state pairs, or document;
       ``ValueError`` for every invalid value or invariant. ``to_json`` also
       raises ``ValueError`` above 16 KiB.

``parse_generation_execution_report`` accepts exact ``bytes`` or ``str`` and
returns a validated ``GenerationExecutionReport``. It applies the 16 KiB
limit, rejects malformed UTF-8, duplicate keys, unknown or missing fields,
mistyped values, invalid cross-field totals, and JSON that is not the canonical
form produced by ``to_json``. It raises ``TypeError`` for another Python input
type and ``GenerationExecutionReportParseError`` for invalid serialized
content.

A custom source can implement ``execution_report_finding_source`` and return
``FindingSourceCategory.CUSTOM``. A custom renderer can implement
``execution_report_output_format`` and return
``ExecutionReportOutputFormat.CUSTOM``. Subclass
``ExecutionReportFindingSourceDeclaration`` or
``ExecutionReportOutputFormatDeclaration`` so a type checker can validate the
method signature.
A subclass does not inherit a built-in source or renderer identity. It must
provide its own category method or receive an explicit
``GenerationExecutionContext``. This prevents changed extension behavior from
being reported as a built-in operation. Extensions may declare only ``CUSTOM``.
The built-in category members are reserved for Vexcalibur's exact built-in
source and renderer types.

Code that supplies components directly can produce a complete report without
claiming a built-in inventory, source, or output identity:

.. literalinclude:: ../examples/generate_custom_execution_report.py
   :language: python
   :linenos:

Extensions run in the caller's process. Vexcalibur does not sandbox them,
control their network access, retry them, or add timeouts. A source that sends
package data must enforce its own consent and endpoint policy. An extension
should raise ``VulnerabilitySourceInputError`` for rejected source input and
``VexRenderError`` for rendering failures that callers can classify.

A result without complete context still contains the rendered document,
components, and findings, but ``execution_report()`` raises ``ValueError``.
The first report call raises ``GenerationReportMetadataError``, a ``ValueError``
subclass, when installed package metadata is unavailable or unsafe. Generation
that does not request a report never reads that metadata.
``GenerationExecutionReport.to_json`` raises ``ValueError`` if the canonical
JSON would exceed 16 KiB. The report JSON includes one trailing newline.

.. automodule:: vexcalibur.generation_result
   :members: GenerationReportMetadataError, GenerationExecutionReportParseError, GeneratedDocumentMetadataDict, GenerationExecutionReportDict, InventorySourceCategory, FindingSourceCategory, ExecutionReportOutputFormat, ExecutionReportFindingSourceDeclaration, ExecutionReportOutputFormatDeclaration, GenerationExecutionContext, GenerationResult, GeneratedDocumentMetadata, GenerationExecutionReport, parse_generation_execution_report
   :show-inheritance:

VEX rendering
-------------

``VexRenderer`` is the format boundary used by generation helpers.
``CycloneDxJsonRenderer`` is the default. ``OpenVexJsonRenderer`` and
``Csaf20VexJsonRenderer`` store their required document metadata and delegate
to native format serializers.

.. automodule:: vexcalibur.render
   :members: VexOutputFormat, VexRenderer, VexDocumentRenderer, VexRenderError

.. automodule:: vexcalibur.vex
   :members: CycloneDxJsonRenderer, parse_timestamp, render_cyclonedx_vex_json

.. automodule:: vexcalibur.openvex
   :members: OpenVexJsonRenderer, OpenVexRenderError, render_openvex_json

.. automodule:: vexcalibur.csaf
   :members: Csaf20DocumentMetadata, Csaf20VexJsonRenderer, CsafDocumentStatus, CsafPublisherCategory, CsafRenderError, csaf_filename, render_csaf20_vex_json

OSV source
----------

Prefer ``OsvSource``, ``osv_client_for_url``, or ``ensure_osv_url_allowed``.
They keep public OSV behind an explicit opt-in even when a caller injects a
client. A custom source passed to ``generate_vex_from_source`` must enforce its
own trust boundary.

``OsvSource`` reserves the ``OSV`` name and every HTTPS URL on the official
``osv.dev`` origin for the canonical public service. A custom endpoint is
identified as an
``OSV-compatible mirror`` at its canonicalized effective base URL. Set both
``source_name`` and ``source_url`` to publish an explicit HTTPS provenance
alias for a custom endpoint without exposing an internal endpoint. Neither
value may be supplied alone. The canonical public endpoint cannot be aliased,
and a custom endpoint cannot claim the reserved official name or URL.

One ``OsvClient`` query operation has independent per-request and cumulative
encoded- and decoded-body limits, an overall wall-clock deadline, page and
token limits, per-query and total vulnerability limits, and a 1,000-query
request chunk. Requests never follow redirects. Identity responses are
streamed raw, and gzip responses use bounded decompression with deadline checks
at each transport chunk. Unicode-canonically equivalent vulnerability IDs are
deduplicated before mapping; the first ID position and newest ``modified``
timestamp are retained. IDs containing controls, bidi controls, or line
separators are rejected. Constructor arguments expose the configurable limits;
generation additionally caps component-to-vulnerability expansion and
serialized UTF-8 output.

The lower-level ``findings_from_osv_results`` mapper never infers official OSV
provenance from an arbitrary result list. Callers must provide ``source_name``,
``source_url``, and ``analysis_detail`` explicitly. Prefer ``OsvSource`` when
the effective endpoint should determine guarded official-or-mirror provenance.

Generation helpers apply a conservative allocation-free pre-render estimate to
the exact built-in renderer classes. It accounts for JSON escaping, repeated
fields, and synthesized versioned package URLs, so it may reject an input whose
grouped output would fall below the nominal limit. Custom renderers and
subclasses retain the exact post-render UTF-8 check.

.. warning::

   Constructing ``OsvClient`` directly does not apply the public-OSV consent
   check. Its default URL is ``https://api.osv.dev``, and its query methods do
   not accept an opt-in flag. Use a guarded helper or ``OsvSource`` for normal
   application code. A direct caller must validate the URL with
   ``ensure_osv_url_allowed`` before sending package data.

.. automodule:: vexcalibur.sources.osv
   :members:
   :show-inheritance:

Local findings source
---------------------

.. automodule:: vexcalibur.sources.local
   :members:
   :show-inheritance:
