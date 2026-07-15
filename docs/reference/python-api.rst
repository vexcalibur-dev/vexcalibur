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
     - Rejects files over 10 MiB, more than 10,000 components, nesting beyond
       50 component levels, malformed package URLs, duplicate returned
       references, and XML DTD, entity, or external-reference declarations.
       Components without package URLs are omitted.
   * - ``load_cyclonedx_json``
     - UTF-8 CycloneDX JSON 1.4, 1.5, or 1.6.
     - Applies the same file, component, nesting, package URL, and reference
       checks as ``load_cyclonedx_sbom``.
   * - ``component_identities_from_github_spdx_sbom``
     - A decoded GitHub Dependency Graph SPDX 2.3 JSON response.
     - Applies the component, package URL, and reference checks. It omits
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

.. automodule:: vexcalibur.generate
   :members: generate_vex_from_components, generate_vex_from_source, generate_vex_from_sbom, generate_vex_from_github_sbom, generate_vex_from_local_findings

VEX rendering
-------------

.. automodule:: vexcalibur.vex
   :members: VexRenderError, parse_timestamp, render_cyclonedx_vex_json

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
