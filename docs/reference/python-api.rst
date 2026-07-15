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
repository read access.

.. automodule:: vexcalibur.github_sbom
   :members: GithubSbomError, GithubSbomConfigurationError, GithubSbomClientError, GithubRepository, GithubSbomClient, component_identities_from_github_spdx_sbom, parse_github_repository, normalize_github_api_url, resolve_github_token
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

.. automodule:: vexcalibur.generate
   :members: generate_vex_from_components, generate_vex_from_source, generate_vex_from_sbom, generate_vex_from_github_sbom, generate_vex_from_local_findings

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
