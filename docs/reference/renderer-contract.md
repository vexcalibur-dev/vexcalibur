# VEX renderer contract

`vexcalibur.api.VexRenderer` is the supported extension contract for serialized output. It is a structural Python protocol, so a renderer does not register with Vexcalibur or inherit a base class.

## Method

A renderer implements this keyword-only method:

```python
def render(
    self,
    *,
    components: tuple[ComponentIdentity, ...],
    findings: tuple[VulnerabilityFinding, ...],
    timestamp: datetime | None = None,
) -> str:
    ...
```

| Parameter | Contract |
| --- | --- |
| `components` | Immutable component identities available to the document. A finding's `component_ref` identifies one of these values. |
| `findings` | Immutable provider findings. The renderer validates and adapts them for its output format. |
| `timestamp` | Requested document timestamp. `None` tells the renderer to use the current UTC time. |
| Return value | A complete VEX document serialized as a Python `str`. |

Raise `VexRenderError` or a format-specific subclass when valid provider data cannot form a document in the selected format. Unexpected exceptions remain the renderer's responsibility and pass through the generation call.

## Complete wrapper example

This renderer delegates format rules to the built-in CycloneDX renderer, then changes whitespace without changing the JSON data:

```python
import json
from datetime import datetime

from vexcalibur.api import (
    ComponentIdentity,
    CycloneDxJsonRenderer,
    VulnerabilityFinding,
)


class IndentedCycloneDxRenderer:
    def __init__(self) -> None:
        self._delegate = CycloneDxJsonRenderer()

    def render(
        self,
        *,
        components: tuple[ComponentIdentity, ...],
        findings: tuple[VulnerabilityFinding, ...],
        timestamp: datetime | None = None,
    ) -> str:
        compact = self._delegate.render(
            components=components,
            findings=findings,
            timestamp=timestamp,
        )
        return json.dumps(json.loads(compact), indent=2, sort_keys=True)
```

Pass an instance as the `renderer` argument to any supported generation helper.

## Limits and trust

Generation rejects serialized UTF-8 output larger than 25 MiB. The exact built-in renderer classes also receive a conservative input estimate before they allocate a document. Custom renderers and subclasses receive only the final size check, so they must bound their own intermediate allocations.

A custom renderer is trusted application code. Vexcalibur does not restrict its file, process, or network access. Keep credentials out of serialized output and avoid copying untrusted values into logs or exception messages.

## Validation

Test a renderer with empty findings, every supported analysis state, invalid component references, required evidence fields, Unicode text, and output at the size boundary. Parse the result with an independent implementation or the format's official schema when one exists.

Run the Vexcalibur offline suite and documentation build after changing a first-party renderer:

```bash
uv run --frozen pytest -m "not live and not fuzz"
uv run --frozen --extra docs sphinx-build -W --keep-going -b html docs docs/_build/html
```

Both commands exit with status `0` when the implementation and reference build pass.
