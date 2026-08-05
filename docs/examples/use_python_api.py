"""Generate and verify a VEX document through the supported Python API."""

from __future__ import annotations

import json
from pathlib import Path

from vexcalibur.api import (
    LocalFindingsError,
    SbomError,
    VexRenderError,
    generate_vex_from_local_findings,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def main(output_path: Path = Path("build/vexcalibur-python-api.json")) -> None:
    """Generate the example document and fail when its result is incomplete."""
    try:
        document = generate_vex_from_local_findings(
            input_file=REPOSITORY_ROOT / "tests/fixtures/sbom/cyclonedx-json-simple.json",
            findings_file=REPOSITORY_ROOT / "tests/fixtures/findings/all-analysis-states.json",
        )
    except (LocalFindingsError, SbomError, VexRenderError) as exc:
        raise SystemExit(f"VEX generation failed: {exc}") from exc

    parsed = json.loads(document)
    vulnerabilities = parsed.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or len(vulnerabilities) != 5:
        raise SystemExit("VEX generation returned an unexpected finding count")

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(document, encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"Could not write {output_path}: {exc}") from exc

    print(f"Wrote {len(vulnerabilities)} findings to {output_path}")


if __name__ == "__main__":
    main()
