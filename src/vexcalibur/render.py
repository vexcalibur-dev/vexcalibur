"""Format-neutral VEX renderer contracts."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Protocol

import vexcalibur.errors as _errors
from vexcalibur.domain import ComponentIdentity, VulnerabilityFinding

VexRenderError = _errors.VexRenderError

if TYPE_CHECKING:
    from vexcalibur.document import VexDocument


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
        """Return a serialized VEX document."""


class VexDocumentRenderer(Protocol):
    """Render an immutable, format-neutral VEX document."""

    def render_document(
        self,
        *,
        document: VexDocument,
        timestamp: datetime | None = None,
    ) -> str:
        """Return a serialized VEX document."""
