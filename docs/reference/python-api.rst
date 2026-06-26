Python API Reference
====================

The Python API is pre-alpha. Public import paths and return shapes can still change before a stable release.

Domain Objects
--------------

.. automodule:: vexcalibur.domain
   :members:
   :show-inheritance:

SBOM Ingest
-----------

Use ``load_cyclonedx_sbom`` for untrusted CycloneDX input. It applies Vexcalibur's
size limits, XML parser hardening, component limits, and duplicate-reference checks
before returning component identities. ``load_cyclonedx_json`` is the JSON-only
compatibility helper.

.. list-table:: SBOM loader contract
   :header-rows: 1

   * - Loader
     - Accepted formats
     - Encodings
     - Limits and filtering
   * - ``load_cyclonedx_sbom``
     - CycloneDX JSON ``1.4``, ``1.5``, or ``1.6``; CycloneDX XML rooted at
       ``bom`` in the ``http://cyclonedx.org/schema/bom/1.4``, ``/1.5``, or
       ``/1.6`` namespace.
     - JSON must be UTF-8. XML may use parser-detected XML encodings such as
       UTF-8 or UTF-16.
     - Files over 10 MiB, more than 10,000 components, nesting deeper than 50
       component levels, malformed package URLs, and duplicate returned
       ``bom-ref`` values raise ``SbomError``. Components without package URLs
       are ignored.
   * - ``load_cyclonedx_json``
     - CycloneDX JSON ``1.4``, ``1.5``, or ``1.6`` only.
     - UTF-8 JSON.
     - Applies the same file size, component count, nesting, package URL, and
       duplicate returned ``bom-ref`` checks as ``load_cyclonedx_sbom``.

Both loaders return a tuple of ``ComponentIdentity`` values sorted by package URL
and component reference. XML input also rejects DTD, entity, and
external-reference declarations before component extraction.

.. automodule:: vexcalibur.sbom
   :members: SbomError, load_cyclonedx_sbom, load_cyclonedx_json

VEX Rendering
-------------

.. automodule:: vexcalibur.vex
   :members: VexRenderError, parse_timestamp, render_cyclonedx_vex_json

Generation Workflow
-------------------

.. automodule:: vexcalibur.generate
   :members: generate_vex_from_source, generate_vex_from_sbom, generate_vex_from_local_findings

OSV Provider
------------

The OSV client can contact the public OSV API by default. Library callers should prefer
``OsvSource``, ``osv_client_for_url``, or ``ensure_osv_url_allowed`` so public OSV access
still requires an explicit opt-in before package URLs or SBOM-derived inventories leave
the local environment. ``generate_vex_from_source`` delegates policy to the supplied
source adapter; custom network sources must enforce their own trust boundary.

.. automodule:: vexcalibur.sources.osv
   :members:
   :show-inheritance:

Local Findings Provider
-----------------------

.. automodule:: vexcalibur.sources.local
   :members:
   :show-inheritance:
