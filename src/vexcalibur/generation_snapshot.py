"""Immutable snapshots of normalized VEX generation inputs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from packageurl import PackageURL

from vexcalibur.domain import (
    ComponentIdentity,
    VexAnalysisState,
    VexRemediationCategory,
    VulnerabilityFinding,
)


@dataclass(frozen=True)
class GenerationComponentSnapshot:
    """Primitive retained representation of one normalized component."""

    ref: str
    name: str
    version: str | None
    purl_type: str
    purl_namespace: str | None
    purl_name: str
    purl_version: str | None
    purl_qualifiers: tuple[tuple[str, str], ...]
    purl_subpath: str | None
    component_type: str

    @classmethod
    def from_component(cls, component: ComponentIdentity) -> GenerationComponentSnapshot:
        """Copy a component into primitive, independently owned values."""
        if not isinstance(component, ComponentIdentity):
            raise TypeError("components must contain ComponentIdentity values")
        return cls(
            ref=_snapshot_text(component.ref, field="component ref"),
            name=_snapshot_text(component.name, field="component name"),
            version=_snapshot_optional_text(component.version, field="component version"),
            purl_type=_snapshot_text(component.purl.type, field="PURL type"),
            purl_namespace=_snapshot_optional_text(
                component.purl.namespace,
                field="PURL namespace",
            ),
            purl_name=_snapshot_text(component.purl.name, field="PURL name"),
            purl_version=_snapshot_optional_text(component.purl.version, field="PURL version"),
            purl_qualifiers=tuple(
                sorted(
                    (
                        _snapshot_text(key, field="PURL qualifier key"),
                        _snapshot_text(value, field="PURL qualifier value"),
                    )
                    for key, value in component.purl.qualifiers.items()
                )
            ),
            purl_subpath=_snapshot_optional_text(component.purl.subpath, field="PURL subpath"),
            component_type=_snapshot_text(component.type, field="component type"),
        )

    def materialize(self) -> ComponentIdentity:
        """Build an independent domain value from this snapshot."""
        return ComponentIdentity(
            ref=self.ref,
            name=self.name,
            version=self.version,
            purl=PackageURL(
                type=self.purl_type,
                namespace=self.purl_namespace,
                name=self.purl_name,
                version=self.purl_version,
                qualifiers=dict(self.purl_qualifiers),
                subpath=self.purl_subpath,
            ),
            type=self.component_type,
        )


@dataclass(frozen=True)
class GenerationFindingSnapshot:
    """Primitive retained representation of one normalized finding."""

    id: str
    source_name: str
    source_url: str
    component_ref: str
    purl: str
    modified: datetime | None
    analysis_state: VexAnalysisState
    analysis_detail: str
    action_statement: str | None
    impact_statement: str | None
    fixed_version: str | None
    remediation_category: VexRemediationCategory | None

    @classmethod
    def from_finding(cls, finding: VulnerabilityFinding) -> GenerationFindingSnapshot:
        """Copy a finding into primitive, independently owned values."""
        if not isinstance(finding, VulnerabilityFinding):
            raise TypeError("findings must contain VulnerabilityFinding values")
        return cls(
            id=_snapshot_text(finding.id, field="finding id"),
            source_name=_snapshot_text(finding.source_name, field="finding source name"),
            source_url=_snapshot_text(finding.source_url, field="finding source URL"),
            component_ref=_snapshot_text(finding.component_ref, field="finding component ref"),
            purl=_snapshot_text(finding.purl, field="finding PURL"),
            modified=_snapshot_datetime(finding.modified),
            analysis_state=VexAnalysisState(finding.analysis_state),
            analysis_detail=_snapshot_text(
                finding.analysis_detail,
                field="finding analysis detail",
            ),
            action_statement=_snapshot_optional_text(
                finding.action_statement,
                field="finding action statement",
            ),
            impact_statement=_snapshot_optional_text(
                finding.impact_statement,
                field="finding impact statement",
            ),
            fixed_version=_snapshot_optional_text(
                finding.fixed_version,
                field="finding fixed version",
            ),
            remediation_category=(
                None
                if finding.remediation_category is None
                else VexRemediationCategory(finding.remediation_category)
            ),
        )

    def materialize(self) -> VulnerabilityFinding:
        """Build an independent domain value from this snapshot."""
        return VulnerabilityFinding(
            id=self.id,
            source_name=self.source_name,
            source_url=self.source_url,
            component_ref=self.component_ref,
            purl=self.purl,
            modified=self.modified,
            analysis_state=self.analysis_state,
            analysis_detail=self.analysis_detail,
            action_statement=self.action_statement,
            impact_statement=self.impact_statement,
            fixed_version=self.fixed_version,
            remediation_category=self.remediation_category,
        )


@dataclass(frozen=True)
class GenerationInputSnapshot:
    """Canonical primitive snapshot shared by generation and its result."""

    components: tuple[GenerationComponentSnapshot, ...]
    findings: tuple[GenerationFindingSnapshot, ...]

    @classmethod
    def capture_components(
        cls,
        components: tuple[ComponentIdentity, ...],
    ) -> GenerationInputSnapshot:
        """Capture component values before invoking an extension boundary."""
        return cls(
            components=tuple(
                GenerationComponentSnapshot.from_component(component) for component in components
            ),
            findings=(),
        )

    def capture_findings(
        self,
        findings: tuple[VulnerabilityFinding, ...],
    ) -> GenerationInputSnapshot:
        """Return a snapshot that also owns the provider's finding values."""
        return type(self)(
            components=self.components,
            findings=tuple(GenerationFindingSnapshot.from_finding(finding) for finding in findings),
        )

    def materialize_components(self) -> tuple[ComponentIdentity, ...]:
        """Return independent domain values for the captured components."""
        return tuple(snapshot.materialize() for snapshot in self.components)

    def materialize_findings(self) -> tuple[VulnerabilityFinding, ...]:
        """Return independent domain values for the captured findings."""
        return tuple(snapshot.materialize() for snapshot in self.findings)


def _snapshot_text(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be text")
    return value if type(value) is str else str.__str__(value)


def _snapshot_optional_text(value: object, *, field: str) -> str | None:
    if value is None:
        return None
    return _snapshot_text(value, field=field)


def _snapshot_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, datetime):
        raise TypeError("finding modified timestamp must be a datetime")
    offset = value.utcoffset()
    fixed_timezone = None if offset is None else timezone(offset)
    return datetime(
        value.year,
        value.month,
        value.day,
        value.hour,
        value.minute,
        value.second,
        value.microsecond,
        tzinfo=fixed_timezone,
        fold=value.fold,
    )
