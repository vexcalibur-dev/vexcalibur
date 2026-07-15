"""Format-neutral VEX renderer contracts."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Protocol

from vexcalibur.domain import ComponentIdentity, VulnerabilityFinding


class VexOutputFormat(str, Enum):
    """VEX output formats supported by the primary CLI."""

    CYCLONEDX = "cyclonedx"
    OPENVEX = "openvex"


class VexRenderError(ValueError):
    """Raised when domain findings cannot be rendered as a valid VEX document."""


class VexRenderer(Protocol):
    """Render provider-neutral components and findings as one VEX format."""

    def render(
        self,
        *,
        components: tuple[ComponentIdentity, ...],
        findings: tuple[VulnerabilityFinding, ...],
        timestamp: datetime | None = None,
    ) -> str:
        """Return a serialized VEX document."""
