"""Conservative input budgets shared by built-in VEX renderers."""

from __future__ import annotations

from vexcalibur.domain import ComponentIdentity, VulnerabilityFinding
from vexcalibur.limits import MAX_GENERATED_DOCUMENT_BYTES
from vexcalibur.render import VexRenderError

_BASE_BYTES = 4 * 1024
_COMPONENT_BYTES = 512
_FINDING_BYTES = 1024
_TEXT_COPIES = 4
_PURL_UNRESERVED_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
)


class RenderInputBudget:
    """Bound caller-controlled text before a built-in renderer allocates its graph."""

    def __init__(self, limit: int | None = None) -> None:
        self._limit = MAX_GENERATED_DOCUMENT_BYTES if limit is None else limit
        self._used = 0
        self.add_fixed(_BASE_BYTES)

    def add_component(self, component: ComponentIdentity, *, purl_copies: int) -> None:
        """Account for one component as emitted by a specific renderer."""
        self.add_fixed(_COMPONENT_BYTES)
        self.add_package_url(component, copies=purl_copies)
        for value in (
            component.ref,
            component.name,
            component.version,
            component.type,
        ):
            self.add_text(value)

    def add_finding(self, finding: VulnerabilityFinding) -> None:
        """Account for fields that a built-in renderer may emit for one finding."""
        self.add_fixed(_FINDING_BYTES)
        for value in (
            finding.id,
            finding.source_name,
            finding.source_url,
            finding.component_ref,
            finding.purl,
            finding.analysis_detail,
            finding.action_statement,
            finding.impact_statement,
            finding.fixed_version,
        ):
            self.add_text(value)

    def add_fixed(self, size: int) -> None:
        self._used += size
        if self._used > self._limit:
            raise VexRenderError(
                f"VEX input exceeds the conservative {self._limit} byte output limit estimate"
            )

    def add_text(self, value: str | None) -> None:
        if value is None:
            return
        self.add_fixed(2 * _TEXT_COPIES)
        for character in value:
            self.add_fixed(_json_escaped_character_size(character) * _TEXT_COPIES)

    def add_package_url(self, component: ComponentIdentity, *, copies: int) -> None:
        """Budget canonical and version-derived PURLs without constructing them."""
        purl = component.purl
        effective_version = purl.version if purl.version is not None else component.version
        qualifiers = purl.qualifiers
        self.add_fixed((16 + (4 * len(qualifiers))) * copies)
        for value in (
            purl.type,
            purl.namespace,
            purl.name,
            effective_version,
            purl.subpath,
        ):
            self._add_percent_encoded_text(value, copies=copies)
        for key, value in qualifiers.items():
            self._add_percent_encoded_text(key, copies=copies)
            self._add_percent_encoded_text(value, copies=copies)

    def _add_percent_encoded_text(self, value: str | None, *, copies: int) -> None:
        if value is None:
            return
        for character in value:
            self.add_fixed(_percent_encoded_character_size(character) * copies)


def _json_escaped_character_size(character: str) -> int:
    codepoint = ord(character)
    if character in {'"', "\\"}:
        return 2
    if codepoint <= 0x1F:
        return 6
    if codepoint <= 0x7F:
        return 1
    if codepoint <= 0xFFFF:
        return 6
    return 12


def _percent_encoded_character_size(character: str) -> int:
    if character in _PURL_UNRESERVED_CHARACTERS:
        return 1
    codepoint = ord(character)
    if codepoint <= 0x7F:
        return 3
    if codepoint <= 0x7FF:
        return 6
    if codepoint <= 0xFFFF:
        return 9
    return 12
