"""Native CSAF 2.0 VEX-profile JSON generation."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from urllib.parse import quote, urlparse
from uuid import NAMESPACE_URL, uuid5

from packageurl import PackageURL

from vexcalibur import __version__
from vexcalibur.document import (
    VexAssertion,
    VexDocument,
    VexProduct,
    analysis_state,
    validate_vex_document,
    versioned_product_purl,
    vex_document_from_findings,
)
from vexcalibur.domain import (
    ComponentIdentity,
    VexAnalysisState,
    VexRemediationCategory,
    VulnerabilityFinding,
)
from vexcalibur.errors import VexRenderError
from vexcalibur.url_policy import BaseUrlValidationError, validate_base_url

CSAF_VERSION = "2.0"
CSAF_DOCUMENT_CATEGORY = "csaf_vex"
CSAF_TOOL_NAME = "Vexcalibur"

_CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
_CSAF_FILENAME_UNSAFE_PATTERN = re.compile(r"[^+\-a-z0-9]+")
_INVALID_PERCENT_ESCAPE_PATTERN = re.compile(r"%(?![0-9A-Fa-f]{2})")
_RFC3986_QUOTE_SAFE = ":/?#[]@!$&'()*+,;=~-._%"
_TRACKING_ID_LINE_TERMINATORS = frozenset("\r\n\u2028\u2029")
_PRODUCT_STATUS_BY_STATE = {
    VexAnalysisState.RESOLVED: "fixed",
    VexAnalysisState.EXPLOITABLE: "known_affected",
    VexAnalysisState.IN_TRIAGE: "under_investigation",
    VexAnalysisState.FALSE_POSITIVE: "known_not_affected",
    VexAnalysisState.NOT_AFFECTED: "known_not_affected",
}


class CsafPublisherCategory(str, Enum):
    """Publisher categories supported for generated CSAF documents."""

    COORDINATOR = "coordinator"
    DISCOVERER = "discoverer"
    OTHER = "other"
    USER = "user"
    VENDOR = "vendor"


class CsafDocumentStatus(str, Enum):
    """Lifecycle statuses supported for an initial CSAF document revision."""

    DRAFT = "draft"
    FINAL = "final"
    INTERIM = "interim"


class CsafRenderError(VexRenderError):
    """Raised when findings cannot form a valid CSAF 2.0 VEX document."""


@dataclass(frozen=True)
class Csaf20DocumentMetadata:
    """Publisher-controlled metadata required by the CSAF 2.0 VEX profile."""

    document_id: str
    title: str
    publisher_name: str
    publisher_namespace: str
    publisher_category: CsafPublisherCategory
    status: CsafDocumentStatus = CsafDocumentStatus.DRAFT

    def __post_init__(self) -> None:
        for field_name in ("document_id", "title", "publisher_name"):
            value = getattr(self, field_name).strip()
            if not value:
                msg = f"CSAF {field_name} must not be empty"
                raise CsafRenderError(msg)
            object.__setattr__(self, field_name, value)
        if any(character in _TRACKING_ID_LINE_TERMINATORS for character in self.document_id):
            msg = "CSAF document_id must not contain line terminators"
            raise CsafRenderError(msg)

        try:
            publisher_category = CsafPublisherCategory(self.publisher_category)
        except (TypeError, ValueError) as exc:
            msg = "CSAF publisher_category is not supported"
            raise CsafRenderError(msg) from exc
        try:
            status = CsafDocumentStatus(self.status)
        except (TypeError, ValueError) as exc:
            msg = "CSAF status is not supported"
            raise CsafRenderError(msg) from exc

        try:
            namespace = validate_base_url(
                self.publisher_namespace,
                option_name="CSAF publisher_namespace",
                allowed_schemes={"http", "https"},
                scheme_message=(
                    "CSAF publisher_namespace must be an absolute HTTP(S) URL with a hostname"
                ),
            ).value
        except (AttributeError, BaseUrlValidationError) as exc:
            raise CsafRenderError(str(exc)) from exc
        _validate_uri_text(namespace, field_name="CSAF publisher_namespace")

        object.__setattr__(self, "publisher_category", publisher_category)
        object.__setattr__(self, "publisher_namespace", namespace)
        object.__setattr__(self, "status", status)


@dataclass(frozen=True)
class Csaf20VexJsonRenderer:
    """Render CSAF 2.0 JSON using the standard VEX profile."""

    metadata: Csaf20DocumentMetadata
    tool_version: str = field(default_factory=lambda: __version__)

    def __post_init__(self) -> None:
        normalized_tool_version = self.tool_version.strip()
        if not normalized_tool_version:
            msg = "CSAF generator tool version must not be empty"
            raise CsafRenderError(msg)
        object.__setattr__(self, "tool_version", normalized_tool_version)

    def render(
        self,
        *,
        components: tuple[ComponentIdentity, ...],
        findings: tuple[VulnerabilityFinding, ...],
        timestamp: datetime | None = None,
    ) -> str:
        """Adapt provider findings and return CSAF 2.0 VEX JSON."""
        try:
            document = vex_document_from_findings(components=components, findings=findings)
        except VexRenderError as exc:
            raise CsafRenderError(str(exc)) from exc
        return self.render_document(document=document, timestamp=timestamp)

    def render_document(
        self,
        *,
        document: VexDocument,
        timestamp: datetime | None = None,
    ) -> str:
        """Return deterministic CSAF 2.0 VEX JSON for a VEX document."""
        try:
            return _render_csaf_document(
                document=document,
                metadata=self.metadata,
                tool_version=self.tool_version,
                timestamp=_normalize_timestamp(timestamp or datetime.now(tz=timezone.utc)),
            )
        except CsafRenderError:
            raise
        except (AttributeError, TypeError, ValueError, VexRenderError) as exc:
            msg = f"CSAF findings cannot be rendered: {exc}"
            raise CsafRenderError(msg) from exc


def render_csaf20_vex_json(
    *,
    components: tuple[ComponentIdentity, ...],
    findings: tuple[VulnerabilityFinding, ...],
    metadata: Csaf20DocumentMetadata,
    timestamp: datetime | None = None,
    tool_version: str | None = None,
) -> str:
    """Render deterministic CSAF 2.0 VEX JSON."""
    renderer = (
        Csaf20VexJsonRenderer(metadata=metadata)
        if tool_version is None
        else Csaf20VexJsonRenderer(metadata=metadata, tool_version=tool_version)
    )
    return renderer.render(components=components, findings=findings, timestamp=timestamp)


def csaf_filename(document_id: str) -> str:
    """Return the CSAF filename derived from a document tracking ID."""
    return f"{_CSAF_FILENAME_UNSAFE_PATTERN.sub('_', document_id.lower())}.json"


@dataclass(frozen=True, order=True)
class _CanonicalProduct:
    purl: str
    product_id: str
    name: str


@dataclass(frozen=True, order=True)
class _NoteKey:
    detail: str
    state: str
    source_name: str
    source_url: str
    modified: str
    fixed_version: str


def _render_csaf_document(
    *,
    document: VexDocument,
    metadata: Csaf20DocumentMetadata,
    tool_version: str,
    timestamp: datetime,
) -> str:
    validate_vex_document(document)
    if not document.assertions:
        msg = "CSAF output requires at least one vulnerability finding"
        raise CsafRenderError(msg)

    canonical_products = _canonical_products(document.assertions)
    assertions = _canonical_assertions(document.assertions)
    _validate_assertions(assertions)
    _validate_no_conflicting_assertions(assertions)

    formatted_timestamp = _format_timestamp(timestamp)
    csaf_document: dict[str, object] = {
        "document": {
            "category": CSAF_DOCUMENT_CATEGORY,
            "csaf_version": CSAF_VERSION,
            "publisher": {
                "category": metadata.publisher_category.value,
                "name": metadata.publisher_name,
                "namespace": metadata.publisher_namespace,
            },
            "title": metadata.title,
            "tracking": {
                "current_release_date": formatted_timestamp,
                "generator": {
                    "date": formatted_timestamp,
                    "engine": {
                        "name": CSAF_TOOL_NAME,
                        "version": tool_version,
                    },
                },
                "id": metadata.document_id,
                "initial_release_date": formatted_timestamp,
                "revision_history": [
                    {
                        "date": formatted_timestamp,
                        "number": "1",
                        "summary": "Initial version.",
                    }
                ],
                "status": metadata.status.value,
                "version": "1",
            },
        },
        "product_tree": {
            "full_product_names": [
                {
                    "name": product.name,
                    "product_id": product.product_id,
                    "product_identification_helper": {"purl": product.purl},
                }
                for product in canonical_products
            ]
        },
        "vulnerabilities": _vulnerabilities(
            assertions=assertions,
            products_by_purl={product.purl: product for product in canonical_products},
        ),
    }
    return f"{json.dumps(csaf_document, indent=2, sort_keys=True)}\n"


def _canonical_products(assertions: tuple[VexAssertion, ...]) -> tuple[_CanonicalProduct, ...]:
    names_by_purl: dict[str, set[str]] = defaultdict(set)
    for assertion in assertions:
        purl = _canonical_versioned_purl(assertion.product)
        product_name = assertion.product.name.strip()
        if not product_name:
            msg = f"CSAF product {assertion.product.key!r} name must not be empty"
            raise CsafRenderError(msg)
        version = PackageURL.from_string(purl).version
        if version is None:
            raise AssertionError("canonical CSAF PURL validation did not require a version")
        names_by_purl[purl].add(f"{product_name} {version}")

    return tuple(
        _CanonicalProduct(
            purl=purl,
            product_id=f"CSAFPID-{uuid5(NAMESPACE_URL, purl)}",
            name=min(names_by_purl[purl]),
        )
        for purl in sorted(names_by_purl)
    )


def _canonical_assertions(assertions: tuple[VexAssertion, ...]) -> tuple[VexAssertion, ...]:
    canonical: dict[tuple[str, ...], VexAssertion] = {}
    for assertion in sorted(assertions, key=_assertion_sort_key):
        canonical.setdefault(_assertion_sort_key(assertion), assertion)
    return tuple(canonical.values())


def _assertion_sort_key(assertion: VexAssertion) -> tuple[str, ...]:
    state = analysis_state(assertion)
    return (
        assertion.vulnerability.id,
        _canonical_versioned_purl(assertion.product),
        state.value,
        assertion.vulnerability.source_name,
        assertion.vulnerability.source_url,
        assertion.analysis_detail,
        _format_timestamp(assertion.source_record_modified_at)
        if assertion.source_record_modified_at is not None
        else "",
        assertion.action_statement or "",
        assertion.impact_statement or "",
        assertion.fixed_version or "",
        assertion.remediation_category.value
        if isinstance(assertion.remediation_category, VexRemediationCategory)
        else "",
    )


def _canonical_versioned_purl(product: VexProduct) -> str:
    try:
        purl = versioned_product_purl(product)
        parsed = PackageURL.from_string(purl)
    except (TypeError, ValueError, VexRenderError) as exc:
        msg = f"CSAF product {product.key!r} contains an invalid package URL: {exc}"
        raise CsafRenderError(msg) from exc
    if parsed.version is None or not parsed.version.strip():
        msg = (
            f"CSAF product PURL {purl!r} must include a version to avoid applying "
            "an assertion to every package version"
        )
        raise CsafRenderError(msg)
    return parsed.to_string()


def _validate_assertions(assertions: tuple[VexAssertion, ...]) -> None:
    for assertion in assertions:
        vulnerability = assertion.vulnerability
        for field_name, value in (
            ("id", vulnerability.id),
            ("source_name", vulnerability.source_name),
            ("source_url", vulnerability.source_url),
            ("analysis_detail", assertion.analysis_detail),
        ):
            if not value.strip():
                msg = f"CSAF finding {field_name} must not be empty"
                raise CsafRenderError(msg)

        _validate_source_url(vulnerability.source_url)
        state = analysis_state(assertion)
        _validate_action_and_remediation(assertion, state=state)
        _validate_impact(assertion, state=state)
        _validate_fixed_version(assertion, state=state)


def _validate_action_and_remediation(
    assertion: VexAssertion,
    *,
    state: VexAnalysisState,
) -> None:
    action = assertion.action_statement
    category = assertion.remediation_category
    if action is not None and not action.strip():
        msg = "CSAF action_statement must not be empty"
        raise CsafRenderError(msg)

    if state is VexAnalysisState.EXPLOITABLE:
        if action is None:
            msg = "CSAF exploitable findings require an action_statement"
            raise CsafRenderError(msg)
        if category is None:
            msg = "CSAF exploitable findings require a remediation_category"
            raise CsafRenderError(msg)
        if not isinstance(category, VexRemediationCategory):
            msg = "CSAF remediation_category is not supported"
            raise CsafRenderError(msg)
        return

    if action is not None:
        msg = "CSAF action_statement is only valid for an exploitable finding"
        raise CsafRenderError(msg)
    if category is not None:
        msg = "CSAF remediation_category is only valid for an exploitable finding"
        raise CsafRenderError(msg)


def _validate_impact(assertion: VexAssertion, *, state: VexAnalysisState) -> None:
    impact = assertion.impact_statement
    if impact is not None and not impact.strip():
        msg = "CSAF impact_statement must not be empty"
        raise CsafRenderError(msg)
    if state in {VexAnalysisState.FALSE_POSITIVE, VexAnalysisState.NOT_AFFECTED}:
        if impact is None:
            msg = "CSAF false_positive and not_affected findings require an impact_statement"
            raise CsafRenderError(msg)
        return
    if impact is not None:
        msg = "CSAF impact_statement is only valid for false_positive or not_affected findings"
        raise CsafRenderError(msg)


def _validate_fixed_version(assertion: VexAssertion, *, state: VexAnalysisState) -> None:
    fixed_version = assertion.fixed_version
    if fixed_version is not None and not fixed_version.strip():
        msg = "CSAF fixed_version must not be empty"
        raise CsafRenderError(msg)
    if state is not VexAnalysisState.RESOLVED:
        if fixed_version is not None:
            msg = "CSAF fixed_version is only valid for a resolved finding"
            raise CsafRenderError(msg)
        return
    if fixed_version is None:
        msg = (
            "CSAF resolved findings require fixed_version to confirm that the identified "
            "product contains a fix"
        )
        raise CsafRenderError(msg)

    purl = _canonical_versioned_purl(assertion.product)
    product_version = PackageURL.from_string(purl).version
    if product_version != fixed_version:
        msg = (
            f"CSAF fixed_version {fixed_version!r} does not match product "
            f"{purl!r} version {product_version!r}"
        )
        raise CsafRenderError(msg)


def _validate_source_url(value: str) -> None:
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError as exc:
        msg = "CSAF finding source_url must be an HTTP(S) URL with a host"
        raise CsafRenderError(msg) from exc
    if parsed.scheme not in {"http", "https"} or hostname is None or parsed.netloc.count("@") > 1:
        msg = "CSAF finding source_url must be an HTTP(S) URL with a host"
        raise CsafRenderError(msg)
    _validate_uri_text(value, field_name="CSAF finding source_url")


def _validate_uri_text(value: str, *, field_name: str) -> None:
    if any(not 0x21 <= ord(character) <= 0x7E for character in value):
        msg = f"{field_name} must contain only printable ASCII URI characters"
        raise CsafRenderError(msg)
    if _INVALID_PERCENT_ESCAPE_PATTERN.search(value):
        msg = f"{field_name} contains an invalid percent escape"
        raise CsafRenderError(msg)
    if quote(value, safe=_RFC3986_QUOTE_SAFE) != value:
        msg = f"{field_name} contains a character that is not valid in an RFC 3986 URI"
        raise CsafRenderError(msg)
    if value.count("#") > 1:
        msg = f"{field_name} contains more than one fragment delimiter"
        raise CsafRenderError(msg)

    parsed = urlparse(value)
    if any(
        "[" in component or "]" in component
        for component in (parsed.path, parsed.params, parsed.query, parsed.fragment)
    ) or not _authority_brackets_are_valid(parsed.netloc):
        msg = f"{field_name} contains brackets outside a valid IP-literal host"
        raise CsafRenderError(msg)


def _authority_brackets_are_valid(authority: str) -> bool:
    userinfo, separator, host_and_port = authority.rpartition("@")
    if separator and ("[" in userinfo or "]" in userinfo):
        return False
    if "[" not in host_and_port and "]" not in host_and_port:
        return True
    if host_and_port.count("[") != 1 or host_and_port.count("]") != 1:
        return False
    if not host_and_port.startswith("["):
        return False
    closing_bracket = host_and_port.index("]")
    suffix = host_and_port[closing_bracket + 1 :]
    return bool(closing_bracket > 1 and (not suffix or suffix.startswith(":")))


def _validate_no_conflicting_assertions(assertions: tuple[VexAssertion, ...]) -> None:
    statuses: dict[tuple[str, str], str] = {}
    for assertion in assertions:
        state = analysis_state(assertion)
        key = (
            assertion.vulnerability.id,
            _canonical_versioned_purl(assertion.product),
        )
        status = _PRODUCT_STATUS_BY_STATE[state]
        previous = statuses.setdefault(key, status)
        if previous != status:
            msg = (
                "CSAF findings contain conflicting assertions for vulnerability "
                f"{key[0]!r} and product {key[1]!r}"
            )
            raise CsafRenderError(msg)


def _vulnerabilities(
    *,
    assertions: tuple[VexAssertion, ...],
    products_by_purl: dict[str, _CanonicalProduct],
) -> list[dict[str, object]]:
    assertions_by_vulnerability: dict[str, list[VexAssertion]] = defaultdict(list)
    for assertion in assertions:
        assertions_by_vulnerability[assertion.vulnerability.id].append(assertion)
    return [
        _vulnerability(
            vulnerability_id=vulnerability_id,
            assertions=tuple(assertions_by_vulnerability[vulnerability_id]),
            products_by_purl=products_by_purl,
        )
        for vulnerability_id in sorted(assertions_by_vulnerability)
    ]


def _vulnerability(
    *,
    vulnerability_id: str,
    assertions: tuple[VexAssertion, ...],
    products_by_purl: dict[str, _CanonicalProduct],
) -> dict[str, object]:
    product_status: dict[str, set[str]] = defaultdict(set)
    notes: dict[_NoteKey, set[str]] = defaultdict(set)
    remediations: dict[tuple[str, str], set[str]] = defaultdict(set)
    impacts: dict[str, set[str]] = defaultdict(set)
    names_by_source_url: dict[str, set[str]] = defaultdict(set)

    for assertion in assertions:
        product = products_by_purl[_canonical_versioned_purl(assertion.product)]
        state = analysis_state(assertion)
        product_status[_PRODUCT_STATUS_BY_STATE[state]].add(product.product_id)
        names_by_source_url[assertion.vulnerability.source_url].add(
            assertion.vulnerability.source_name
        )
        note_key = _note_key(assertion, state=state)
        notes[note_key].add(product.product_id)
        if state is VexAnalysisState.EXPLOITABLE:
            category = assertion.remediation_category
            action = assertion.action_statement
            if not isinstance(category, VexRemediationCategory) or action is None:
                raise AssertionError("validated exploitable assertion lacks remediation evidence")
            remediations[(category.value, action)].add(product.product_id)
        elif state in {VexAnalysisState.FALSE_POSITIVE, VexAnalysisState.NOT_AFFECTED}:
            impact = assertion.impact_statement
            if impact is None:
                raise AssertionError("validated not-affected assertion lacks impact evidence")
            impacts[impact].add(product.product_id)

    vulnerability: dict[str, object] = {
        "notes": [
            {
                "category": "details",
                "text": _note_text(note_key=note_key, product_ids=notes[note_key]),
            }
            for note_key in sorted(notes)
        ],
        "product_status": {
            status: sorted(product_status[status]) for status in sorted(product_status)
        },
        "references": [
            {
                "category": "external",
                "summary": (
                    f"Vulnerability source: {', '.join(sorted(names_by_source_url[source_url]))}"
                ),
                "url": source_url,
            }
            for source_url in sorted(names_by_source_url)
        ],
    }
    if _CVE_PATTERN.fullmatch(vulnerability_id):
        vulnerability["cve"] = vulnerability_id
    else:
        vulnerability["ids"] = [
            {
                "system_name": source_name,
                "text": vulnerability_id,
            }
            for source_name in sorted(
                {assertion.vulnerability.source_name for assertion in assertions}
            )
        ]
    if remediations:
        vulnerability["remediations"] = [
            {
                "category": category,
                "details": details,
                "product_ids": sorted(remediations[(category, details)]),
            }
            for category, details in sorted(remediations)
        ]
    if impacts:
        vulnerability["threats"] = [
            {
                "category": "impact",
                "details": details,
                "product_ids": sorted(impacts[details]),
            }
            for details in sorted(impacts)
        ]
    return vulnerability


def _note_key(assertion: VexAssertion, *, state: VexAnalysisState) -> _NoteKey:
    return _NoteKey(
        detail=assertion.analysis_detail,
        state=state.value,
        source_name=assertion.vulnerability.source_name,
        source_url=assertion.vulnerability.source_url,
        modified=(
            _format_timestamp(assertion.source_record_modified_at)
            if assertion.source_record_modified_at is not None
            else ""
        ),
        fixed_version=assertion.fixed_version or "",
    )


def _note_text(*, note_key: _NoteKey, product_ids: set[str]) -> str:
    lines = [
        f"Applicable product IDs: {', '.join(sorted(product_ids))}",
        f"Analysis detail: {note_key.detail}",
        f"Original Vexcalibur analysis state: {note_key.state}",
        f"Source: {note_key.source_name} ({note_key.source_url})",
    ]
    if note_key.modified:
        lines.append(f"Source record modified: {note_key.modified}")
    if note_key.fixed_version:
        lines.append(f"Confirmed fixed product version: {note_key.fixed_version}")
    return "\n".join(lines)


def _normalize_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return _normalize_timestamp(value).isoformat().replace("+00:00", "Z")
