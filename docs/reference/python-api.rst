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

.. automodule:: vexcalibur.sbom
   :members: SbomError, load_cyclonedx_json

VEX Rendering
-------------

.. automodule:: vexcalibur.vex
   :members: VexRenderError, parse_timestamp, render_cyclonedx_vex_json

Generation Workflow
-------------------

.. automodule:: vexcalibur.generate
   :members: generate_vex_from_sbom

OSV Provider
------------

.. automodule:: vexcalibur.sources.osv
   :members:
   :show-inheritance:
