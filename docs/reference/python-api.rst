Python API
==========

``vexcalibur.api`` is the supported Python interface. Import application and
extension code from this module rather than from implementation modules such as
``vexcalibur.generate`` or ``vexcalibur.sources.osv``.

The compatibility guarantee begins with Vexcalibur 1.0. Before 1.0, pin an
exact Vexcalibur release. For a 1.x release, the contract covers exported names,
call signatures and defaults, documented return types and behavior, documented
exceptions, public dataclass fields, protocol methods, and enum names and
values. Modules and names outside this facade may change in any release.

A minor release may add an export, add an optional keyword argument with a
default to a caller-facing function or constructor, or add a more specific
exception beneath a documented base class. Protocol method signatures remain
fixed throughout 1.x. Vexcalibur may extend a protocol behind an adapter only
when existing implementations still receive the original call. Deprecations
are identified in the API reference and release notes, emit
``DeprecationWarning`` when practical, and remain available until the next
major release. A security fix may reject input that was previously accepted as
unsafe; release notes call out that change.

The installation metadata accepts Python 3.10 or later within Python 3. CI
currently tests Python 3.10 through 3.14. Other Python 3 versions are
unverified. Dropping a tested Python version changes the installation contract
and is announced in release notes.

Runnable example
----------------

The :doc:`Python API how-to <../how-to/use-python-api>` runs against committed
fixtures, handles documented failures, writes a real CycloneDX VEX document,
and verifies the result.

Generation
----------

Generation functions without a ``_result`` suffix return serialized JSON as
``str``. CycloneDX 1.6 is the default output. Pass ``OpenVexJsonRenderer`` or
``Csaf20VexJsonRenderer`` to select another format.

``generate_vex_from_source`` and ``generate_vex_from_components`` accept a
custom ``VulnerabilitySource``. A source receives immutable component values
and returns immutable findings. ``VexRenderer`` defines the corresponding
output extension contract.

.. currentmodule:: vexcalibur.api

.. autofunction:: generate_vex_from_components

.. autofunction:: generate_vex_from_source

.. autofunction:: generate_vex_from_sbom

.. autofunction:: generate_vex_from_github_sbom

.. autofunction:: generate_vex_from_local_findings

Report-aware generation
-----------------------

Each supported generation path has a ``*_result`` variant. These functions
return ``GenerationResult`` instead of ``str``. The result retains the exact
rendered bytes and the normalized values needed to build a versioned execution
report, so callers do not need to parse VEX output to calculate counts or a
digest.

Built-in sources and renderers supply their execution-report categories. When
a result uses a custom source or renderer, pass ``GenerationExecutionContext``
with the corresponding ``custom`` category before calling
``GenerationResult.execution_report()``. Generation can succeed without that
context, but the result cannot produce an execution report and the method
raises ``ValueError``.

``EXECUTION_REPORT_SCHEMA_VERSION`` is the feature-detection constant for this
contract. Require the exact integer value your application supports. A missing,
mistyped, or different value means the installed package does not provide that
report contract.

.. autofunction:: generate_vex_from_components_result

.. autofunction:: generate_vex_from_source_result

.. autofunction:: generate_vex_from_sbom_result

.. autofunction:: generate_vex_from_github_sbom_result

.. autofunction:: generate_vex_from_github_source_result

.. autofunction:: generate_vex_from_local_findings_result

.. autodata:: EXECUTION_REPORT_SCHEMA_VERSION

.. autoclass:: GenerationResult
   :members:

.. autoclass:: GenerationExecutionContext

.. autoclass:: GenerationSourcePreflight
   :members:

.. autoclass:: GenerationExecutionReport
   :members:

.. autoclass:: GeneratedDocumentMetadata

.. autoclass:: GeneratedDocumentMetadataDict

.. autoclass:: GenerationExecutionReportDict

The typed dictionaries expose these required fields:

.. list-table:: Execution-report dictionary fields
   :header-rows: 1

   * - Type
     - Field
     - Value
   * - ``GeneratedDocumentMetadataDict``
     - ``sha256``
     - Lowercase SHA-256 digest text for the exact UTF-8 document bytes
   * - ``GeneratedDocumentMetadataDict``
     - ``bytes``
     - UTF-8 document byte count as an integer
   * - ``GenerationExecutionReportDict``
     - ``schema_version``
     - Report schema integer
   * - ``GenerationExecutionReportDict``
     - ``command``
     - Literal ``generate``
   * - ``GenerationExecutionReportDict``
     - ``vexcalibur_version``
     - Installed package version text
   * - ``GenerationExecutionReportDict``
     - ``inventory_source``
     - Serialized ``InventorySourceCategory`` value
   * - ``GenerationExecutionReportDict``
     - ``finding_source``
     - Serialized ``FindingSourceCategory`` value
   * - ``GenerationExecutionReportDict``
     - ``output_format``
     - Serialized ``ExecutionReportOutputFormat`` value
   * - ``GenerationExecutionReportDict``
     - ``component_count``
     - Normalized component count as an integer
   * - ``GenerationExecutionReportDict``
     - ``finding_count``
     - Normalized finding count as an integer
   * - ``GenerationExecutionReportDict``
     - ``analysis_state_counts``
     - Mapping from serialized analysis-state values to positive integer counts
   * - ``GenerationExecutionReportDict``
     - ``document``
     - ``GeneratedDocumentMetadataDict`` value

.. autoclass:: InventorySourceCategory
   :members:

.. autoclass:: FindingSourceCategory
   :members:

.. autoclass:: ExecutionReportOutputFormat
   :members:

.. autofunction:: parse_generation_execution_report

The :doc:`execution-report reference <execution-report>` defines the serialized
fields, category values, size limit, and security boundary. This checked-in
example writes matching VEX and report bytes without replacing existing files:

.. literalinclude:: ../examples/generate_execution_report.py
   :language: python
   :linenos:

Run it from Bash or PowerShell at the repository root with a new output
directory::

   uv run --frozen python docs/examples/generate_execution_report.py vexcalibur-python-api

Success prints both output paths. The two writes are independent and can leave
partial files. On Windows, their privacy depends on the ACL of the existing
parent directory. Python embeddings do not receive the CLI's coordinated
publication transaction.

SBOM ingest and GitHub
----------------------

``load_cyclonedx_sbom`` reads CycloneDX JSON or XML 1.4, 1.5, or 1.6. It
returns component identities sorted by package URL and reference. Components
without package URLs are omitted.

The loader opens its path once in nonblocking mode and requires the opened
target to be a regular file. A symbolic link to a regular file works. The
loader reads at most 10 MiB, accepts at most 10,000 components and 50 nested
component levels, and rejects duplicate returned references. JSON input also
rejects duplicate keys, more than 100 nested arrays or objects, and integer
literals longer than 1,000 decimal digits. XML input rejects DTD, entity, and
external-reference declarations.

``generate_vex_from_github_sbom`` requests a repository's Dependency Graph
SBOM. Public repositories may work without a token, subject to GitHub's rate
limits. Token-backed requests need read access to the repository. Set
``github_token_env`` to read a named environment variable. Otherwise,
Vexcalibur checks ``GH_TOKEN`` and then ``GITHUB_TOKEN`` for GitHub.com before
falling back to ``gh auth token``. Pass ``use_gh_auth=False`` to disable that
fallback. GitHub Enterprise requires either ``github_token_env`` or credentials
available to ``gh`` for the configured host. Token text must be printable ASCII
without whitespace.

.. autofunction:: load_cyclonedx_sbom

Sources and renderers
---------------------

The local-findings generation helper reads Vexcalibur's local findings format.
The built-in OSV helpers deny public OSV unless the caller passes
``allow_public_osv=True``; fetching an SBOM from GitHub does not supply that
consent. Low-level OSV clients remain outside the supported facade so callers
cannot bypass this check through a built-in helper.

A custom ``VulnerabilitySource`` is trusted application code. It owns consent,
authentication, redirect handling, resource limits, and disclosure policy for
every service it contacts. The supported facade does not inspect or constrain
that provider's I/O.

Pass ``osv_headers`` when a private mirror needs application authentication.
Vexcalibur sends those headers only to the configured endpoint and does not
follow redirects. Header names use HTTP token characters. Values accept
printable ASCII and horizontal tabs.

One client operation has independent limits for each response and for all
responses combined. It also bounds elapsed time, pages, page-token length,
queries, vulnerability IDs, vulnerabilities per query, and total
vulnerabilities. Requests don't follow redirects. Generation adds a 25 MiB
limit for serialized UTF-8 output; built-in renderers also apply a conservative
estimate before they allocate their document structures.

.. autoclass:: ComponentIdentity

``ComponentIdentity.purl`` uses :class:`packageurl.PackageURL`. Construct it
with the third-party ``packageurl`` package::

   from packageurl import PackageURL

   purl = PackageURL.from_string("pkg:pypi/example@1.0.0")

.. autoclass:: packageurl.PackageURL

.. autoclass:: VulnerabilityFinding

.. autoclass:: VexAnalysisState
   :members:

.. autoclass:: VexRemediationCategory
   :members:

.. autoclass:: VulnerabilitySource
   :members:

.. autoclass:: VexRenderer
   :members:

.. autoclass:: CycloneDxJsonRenderer
   :members:

.. autoclass:: OpenVexJsonRenderer
   :members:

.. autoclass:: Csaf20DocumentMetadata

.. autoclass:: Csaf20VexJsonRenderer
   :members:

.. autoclass:: CsafDocumentStatus
   :members:

.. autoclass:: CsafPublisherCategory
   :members:

Enumeration values
------------------

.. list-table:: Public enum values
   :header-rows: 1

   * - Enum
     - Member
     - Serialized value
   * - ``InventorySourceCategory``
     - ``SBOM_FILE``
     - ``sbom_file``
   * - ``InventorySourceCategory``
     - ``GITHUB_DEPENDENCY_GRAPH``
     - ``github_dependency_graph``
   * - ``InventorySourceCategory``
     - ``CUSTOM``
     - ``custom``
   * - ``FindingSourceCategory``
     - ``LOCAL_FILE``
     - ``local_file``
   * - ``FindingSourceCategory``
     - ``PUBLIC_OSV``
     - ``public_osv``
   * - ``FindingSourceCategory``
     - ``CUSTOM_OSV``
     - ``custom_osv``
   * - ``FindingSourceCategory``
     - ``CUSTOM``
     - ``custom``
   * - ``ExecutionReportOutputFormat``
     - ``CYCLONEDX``
     - ``cyclonedx``
   * - ``ExecutionReportOutputFormat``
     - ``OPENVEX``
     - ``openvex``
   * - ``ExecutionReportOutputFormat``
     - ``CSAF``
     - ``csaf``
   * - ``ExecutionReportOutputFormat``
     - ``CUSTOM``
     - ``custom``
   * - ``VexAnalysisState``
     - ``RESOLVED``
     - ``resolved``
   * - ``VexAnalysisState``
     - ``EXPLOITABLE``
     - ``exploitable``
   * - ``VexAnalysisState``
     - ``IN_TRIAGE``
     - ``in_triage``
   * - ``VexAnalysisState``
     - ``FALSE_POSITIVE``
     - ``false_positive``
   * - ``VexAnalysisState``
     - ``NOT_AFFECTED``
     - ``not_affected``
   * - ``VexRemediationCategory``
     - ``MITIGATION``
     - ``mitigation``
   * - ``VexRemediationCategory``
     - ``NO_FIX_PLANNED``
     - ``no_fix_planned``
   * - ``VexRemediationCategory``
     - ``NONE_AVAILABLE``
     - ``none_available``
   * - ``VexRemediationCategory``
     - ``VENDOR_FIX``
     - ``vendor_fix``
   * - ``VexRemediationCategory``
     - ``WORKAROUND``
     - ``workaround``
   * - ``CsafDocumentStatus``
     - ``DRAFT``
     - ``draft``
   * - ``CsafDocumentStatus``
     - ``FINAL``
     - ``final``
   * - ``CsafDocumentStatus``
     - ``INTERIM``
     - ``interim``
   * - ``CsafPublisherCategory``
     - ``COORDINATOR``
     - ``coordinator``
   * - ``CsafPublisherCategory``
     - ``DISCOVERER``
     - ``discoverer``
   * - ``CsafPublisherCategory``
     - ``OTHER``
     - ``other``
   * - ``CsafPublisherCategory``
     - ``USER``
     - ``user``
   * - ``CsafPublisherCategory``
     - ``VENDOR``
     - ``vendor``

Exceptions
----------

Catch the most specific exception when the recovery action differs. The base
classes support broader boundaries:

* ``SbomError`` covers local and GitHub SBOM input failures.
* ``VulnerabilitySourceError`` covers provider failures. ``OsvClientError``
  and ``LocalFindingsError`` add provider-specific detail.
* ``VexRenderError`` covers invalid or oversized output. Format-specific
  renderers raise its ``OpenVexRenderError`` or ``CsafRenderError`` subclasses.
* ``ComponentVersionError`` reports contradictory explicit and package URL
  versions when an application constructs ``ComponentIdentity`` directly.
* ``GenerationReportMetadataError`` means package metadata cannot prove which
  Vexcalibur code produced a report.
* ``GenerationExecutionReportParseError`` rejects oversized, malformed,
  noncanonical, or schema-incompatible report bytes.

The API does not wrap unexpected exceptions raised by custom providers or
renderers. Their implementations own those failures.

.. autoexception:: ComponentVersionError

.. autoexception:: GenerationReportMetadataError

.. autoexception:: GenerationExecutionReportParseError

.. autoexception:: SbomError

.. autoexception:: GithubSbomError

.. autoexception:: GithubSbomConfigurationError

.. autoexception:: GithubSbomClientError

.. autoexception:: VulnerabilitySourceError

.. autoexception:: VulnerabilitySourceInputError

.. autoexception:: LocalFindingsError

.. autoexception:: OsvClientError

.. autoexception:: OsvConfigurationError

.. autoexception:: OsvResponseError

.. autoexception:: VexRenderError

.. autoexception:: OpenVexRenderError

.. autoexception:: CsafRenderError

Supported names
---------------

``vexcalibur.api.__all__`` is the machine-readable public surface. This page is
generated from docstrings beside the implementation. Names omitted from
``__all__`` are implementation details even when Python can import them.
