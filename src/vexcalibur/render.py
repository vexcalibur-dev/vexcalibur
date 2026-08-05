"""Format-neutral VEX renderer contracts."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Protocol

import vexcalibur.errors as _errors
from vexcalibur.domain import ComponentIdentity, VulnerabilityFinding

VexRenderError = _errors.VexRenderError


class VexOutputFormat(str, Enum):
    """VEX output formats supported by the primary CLI."""

    CYCLONEDX = "cyclonedx"
    OPENVEX = "openvex"
    CSAF = "csaf"


class VexRenderer(Protocol):
    """Render provider-neutral components and findings as one VEX format."""

    def render(
        self,
        *,
        components: tuple[ComponentIdentity, ...],
        findings: tuple[VulnerabilityFinding, ...],
        timestamp: datetime | None = None,
    ) -> str:
        """Return a serialized VEX document.

        Args:
            components: Components available to the document.
            findings: Vulnerability findings associated with those components.
            timestamp: Document timestamp, or ``None`` to use the current time.

        Returns:
            Serialized VEX JSON.

        Raises:
            VexRenderError: The values cannot form a valid bounded document.
        """
