"""Immutable, format-neutral VEX document values for built-in renderers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from packageurl import PackageURL

from vexcalibur.domain import (
    ComponentIdentity,
    ComponentVersionError,
    VexAnalysisState,
    VexRemediationCategory,
    VulnerabilityFinding,
    canonical_component_version,
)
from vexcalibur.errors import VexRenderError
from vexcalibur.url_policy import UrlUserinfoError, reject_url_userinfo


class VexDisposition(str, Enum):
    """Broad VEX dispositions shared by supported output formats."""

    FIXED = "fixed"
    AFFECTED = "affected"
    UNDER_INVESTIGATION = "under_investigation"
    NOT_AFFECTED = "not_affected"


class VexAnalysisQualifier(str, Enum):
    """Source semantics that are narrower than a shared disposition."""

    EXPLOITABLE = "exploitable"
    FALSE_POSITIVE = "false_positive"


class VexProductIdentifierType(str, Enum):
    """Typed product identifiers represented by the document model."""

    PURL = "purl"


@dataclass(frozen=True)
class VexProductIdentifier:
    """One typed identifier for a product."""

    type: VexProductIdentifierType
    value: str


@dataclass(frozen=True)
class VexProduct:
    """A product named by a stable source-local key."""

    key: str
    name: str
    version: str | None
    identifiers: tuple[VexProductIdentifier, ...]
    component_type: str = "library"


@dataclass(frozen=True)
class VexVulnerability:
    """A vulnerability identifier and its assessment source."""

    id: str
    source_name: str
    source_url: str


@dataclass(frozen=True)
class VexAssertion:
    """One vulnerability assessment for one product."""

    vulnerability: VexVulnerability
    product: VexProduct
    disposition: VexDisposition
    qualifier: VexAnalysisQualifier | None
    analysis_detail: str
    source_record_modified_at: datetime | None = None
    action_statement: str | None = None
    impact_statement: str | None = None
    fixed_version: str | None = None
    remediation_category: VexRemediationCategory | None = None


@dataclass(frozen=True)
class VexDocument:
    """A deterministic generated VEX snapshot of atomic assertions."""

    products: tuple[VexProduct, ...]
    vulnerabilities: tuple[VexVulnerability, ...]
    assertions: tuple[VexAssertion, ...]


_DISPOSITION_AND_QUALIFIER_BY_STATE = {
    VexAnalysisState.RESOLVED: (VexDisposition.FIXED, None),
    VexAnalysisState.EXPLOITABLE: (
        VexDisposition.AFFECTED,
        VexAnalysisQualifier.EXPLOITABLE,
    ),
    VexAnalysisState.IN_TRIAGE: (VexDisposition.UNDER_INVESTIGATION, None),
    VexAnalysisState.FALSE_POSITIVE: (
        VexDisposition.NOT_AFFECTED,
        VexAnalysisQualifier.FALSE_POSITIVE,
    ),
    VexAnalysisState.NOT_AFFECTED: (VexDisposition.NOT_AFFECTED, None),
}


def vex_document_from_findings(
    *,
    components: tuple[ComponentIdentity, ...],
    findings: tuple[VulnerabilityFinding, ...],
) -> VexDocument:
    """Adapt provider components and findings into a deterministic VEX snapshot."""
    components_by_ref = _components_by_ref(components)
    products_by_ref = {
        ref: _product_from_component(component) for ref, component in components_by_ref.items()
    }
    assertions = tuple(
        dict.fromkeys(
            sorted(
                (
                    _assertion_from_finding(
                        finding,
                        components_by_ref=components_by_ref,
                        products_by_ref=products_by_ref,
                    )
                    for finding in findings
                ),
                key=_assertion_sort_key,
            )
        )
    )
    referenced_product_keys = {assertion.product.key for assertion in assertions}
    products = tuple(
        sorted(
            (product for key, product in products_by_ref.items() if key in referenced_product_keys),
            key=_product_sort_key,
        )
    )
    vulnerabilities = tuple(
        sorted(
            {assertion.vulnerability for assertion in assertions},
            key=_vulnerability_sort_key,
        )
    )
    return VexDocument(
        products=products,
        vulnerabilities=vulnerabilities,
        assertions=assertions,
    )


def product_purl(product: VexProduct) -> PackageURL:
    """Return the package URL carried by a generated product."""
    purls = tuple(
        identifier.value
        for identifier in product.identifiers
        if identifier.type is VexProductIdentifierType.PURL
    )
    if len(purls) != 1:
        msg = f"product {product.key!r} must contain exactly one package URL identifier"
        raise VexRenderError(msg)
    try:
        purl = PackageURL.from_string(purls[0])
    except ValueError as exc:
        msg = f"product {product.key!r} contains an invalid package URL: {exc}"
        raise VexRenderError(msg) from exc
    try:
        canonical_component_version(version=product.version, purl=purl)
    except ComponentVersionError as exc:
        msg = f"product {product.key!r} has conflicting version identity: {exc}"
        raise VexRenderError(msg) from exc
    return purl


def versioned_product_purl(product: VexProduct) -> str:
    """Return a canonical product PURL, adding its separate version when needed."""
    purl = product_purl(product)
    if purl.version is not None or not product.version:
        return purl.to_string()
    return PackageURL(
        type=purl.type,
        namespace=purl.namespace,
        name=purl.name,
        version=product.version,
        qualifiers=purl.qualifiers,
        subpath=purl.subpath,
    ).to_string()


def validate_vex_document(document: VexDocument) -> None:
    """Validate shared product identity and source-URL boundaries."""
    for product in document.products:
        product_purl(product)
    for vulnerability in document.vulnerabilities:
        _validate_source_url(vulnerability.source_url)
    for assertion in document.assertions:
        product_purl(assertion.product)
        _validate_source_url(assertion.vulnerability.source_url)


def analysis_state(assertion: VexAssertion) -> VexAnalysisState:
    """Recover the provider analysis state retained by an adapted assertion."""
    if assertion.disposition is VexDisposition.FIXED and assertion.qualifier is None:
        return VexAnalysisState.RESOLVED
    if (
        assertion.disposition is VexDisposition.AFFECTED
        and assertion.qualifier is VexAnalysisQualifier.EXPLOITABLE
    ):
        return VexAnalysisState.EXPLOITABLE
    if assertion.disposition is VexDisposition.UNDER_INVESTIGATION and assertion.qualifier is None:
        return VexAnalysisState.IN_TRIAGE
    if (
        assertion.disposition is VexDisposition.NOT_AFFECTED
        and assertion.qualifier is VexAnalysisQualifier.FALSE_POSITIVE
    ):
        return VexAnalysisState.FALSE_POSITIVE
    if assertion.disposition is VexDisposition.NOT_AFFECTED and assertion.qualifier is None:
        return VexAnalysisState.NOT_AFFECTED
    msg = (
        f"assertion for {assertion.vulnerability.id!r} and {assertion.product.key!r} "
        "has an unsupported disposition and qualifier"
    )
    raise VexRenderError(msg)


def _components_by_ref(
    components: tuple[ComponentIdentity, ...],
) -> dict[str, ComponentIdentity]:
    components_by_ref: dict[str, ComponentIdentity] = {}
    duplicate_refs: set[str] = set()
    for component in components:
        try:
            canonical_component_version(version=component.version, purl=component.purl)
        except ComponentVersionError as exc:
            msg = f"component {component.ref!r} has conflicting version identity: {exc}"
            raise VexRenderError(msg) from exc
        if component.ref in components_by_ref:
            duplicate_refs.add(component.ref)
        components_by_ref[component.ref] = component
    if duplicate_refs:
        msg = f"components contain duplicate refs: {', '.join(sorted(duplicate_refs))}"
        raise VexRenderError(msg)
    return components_by_ref


def _product_from_component(component: ComponentIdentity) -> VexProduct:
    return VexProduct(
        key=component.ref,
        name=component.name,
        version=component.version,
        identifiers=(
            VexProductIdentifier(
                type=VexProductIdentifierType.PURL,
                value=component.purl.to_string(),
            ),
        ),
        component_type=component.type,
    )


def _assertion_from_finding(
    finding: VulnerabilityFinding,
    *,
    components_by_ref: dict[str, ComponentIdentity],
    products_by_ref: dict[str, VexProduct],
) -> VexAssertion:
    component = components_by_ref.get(finding.component_ref)
    if component is None:
        msg = f"finding references unknown component {finding.component_ref!r}"
        raise VexRenderError(msg)
    component_purl = component.purl.to_string()
    if finding.purl != component_purl:
        msg = (
            f"finding PURL {finding.purl!r} does not match component "
            f"{finding.component_ref!r} PURL {component_purl!r}"
        )
        raise VexRenderError(msg)
    _validate_source_url(finding.source_url)
    try:
        disposition, qualifier = _DISPOSITION_AND_QUALIFIER_BY_STATE[finding.analysis_state]
    except (KeyError, TypeError) as exc:
        msg = f"finding {finding.id!r} contains an unsupported analysis state"
        raise VexRenderError(msg) from exc
    return VexAssertion(
        vulnerability=VexVulnerability(
            id=finding.id,
            source_name=finding.source_name,
            source_url=finding.source_url,
        ),
        product=products_by_ref[finding.component_ref],
        disposition=disposition,
        qualifier=qualifier,
        analysis_detail=finding.analysis_detail,
        source_record_modified_at=finding.modified,
        action_statement=finding.action_statement,
        impact_statement=finding.impact_statement,
        fixed_version=finding.fixed_version,
        remediation_category=finding.remediation_category,
    )


def _validate_source_url(value: str) -> None:
    try:
        reject_url_userinfo(value, field_name="vulnerability source_url")
    except UrlUserinfoError as exc:
        raise VexRenderError(str(exc)) from exc


def _assertion_sort_key(assertion: VexAssertion) -> tuple[str, ...]:
    return (
        assertion.vulnerability.id,
        assertion.vulnerability.source_name,
        assertion.vulnerability.source_url,
        assertion.disposition.value,
        assertion.qualifier.value if assertion.qualifier is not None else "",
        assertion.analysis_detail,
        assertion.product.key,
        product_purl(assertion.product).to_string(),
        (
            assertion.source_record_modified_at.isoformat()
            if assertion.source_record_modified_at is not None
            else ""
        ),
        assertion.action_statement or "",
        assertion.impact_statement or "",
        assertion.fixed_version or "",
        (
            assertion.remediation_category.value
            if assertion.remediation_category is not None
            else ""
        ),
    )


def _product_sort_key(product: VexProduct) -> tuple[str, str]:
    return (product.key, product_purl(product).to_string())


def _vulnerability_sort_key(vulnerability: VexVulnerability) -> tuple[str, str, str]:
    return (vulnerability.id, vulnerability.source_name, vulnerability.source_url)
