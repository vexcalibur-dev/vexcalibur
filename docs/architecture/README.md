# Internal architecture and requirements

These pages describe Vexcalibur's implementation and the obligations its
contributors must preserve. They are separate from the
[user manual](../index.md), which covers installation, supported interfaces,
and generating VEX documents.

- [Internal requirements](quality-attributes.md) is the canonical home for
  internal policy. Other pages link to it rather than maintaining a second set.
- [Architecture and trust boundaries](overview.md) describes the generation
  flow, module responsibilities, and validation boundaries.
- [Why Vexcalibur publishes evidence about itself](self-release-evidence.md)
  explains the release architecture.
- [Release-evidence reference](release-evidence.md) defines the internal
  evidence formats consumed by release tooling.

Use the [planning guide](../planning/README.md) for open designs, decision
records, and evidence receipts. Contributor runbooks remain under
[`contributing/`](../contributing/index.md); they describe how to operate or
change the system, not another source of architectural policy.

```{toctree}
:hidden:
:maxdepth: 1

quality-attributes
overview
self-release-evidence
release-evidence
```
