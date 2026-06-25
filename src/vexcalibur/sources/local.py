"""Local finding source for offline VEX generation."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from packageurl import PackageURL
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from vexcalibur.domain import ComponentIdentity, VexAnalysisState, VulnerabilityFinding

MAX_LOCAL_FINDINGS_BYTES = 5 * 1024 * 1024
MAX_LOCAL_FINDINGS = 10_000
LOCAL_SOURCE_NAME = "Local"
LOCAL_SOURCE_URL = "https://vexcalibur.dev/sources/local"
LOCAL_ANALYSIS_DETAIL = "Provided by local findings file; manual exploitability analysis required."


class LocalFindingsError(ValueError):
    """Raised when a local findings document cannot be converted into VEX findings."""


class _LocalFindingModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    component_ref: str | None = Field(default=None, min_length=1)
    purl: str | None = Field(default=None, min_length=1)
    source_name: str = Field(default=LOCAL_SOURCE_NAME, min_length=1)
    source_url: str = Field(default=LOCAL_SOURCE_URL, min_length=1)
    modified: datetime | None = None
    analysis_state: VexAnalysisState = VexAnalysisState.IN_TRIAGE
    analysis_detail: str = Field(default=LOCAL_ANALYSIS_DETAIL, min_length=1)

    @field_validator("purl")
    @classmethod
    def _validate_purl(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return PackageURL.from_string(value).to_string()
        except ValueError as exc:
            msg = f"not a valid package URL: {exc}"
            raise ValueError(msg) from exc

    @field_validator("source_url")
    @classmethod
    def _validate_source_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            msg = "source_url must be an HTTP(S) URL with a host"
            raise ValueError(msg)
        return value

    @field_validator("modified", mode="before")
    @classmethod
    def _validate_modified_input(cls, value: Any) -> Any:
        if value is None:
            return value
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                msg = "modified must be an ISO-8601 timestamp string"
                raise ValueError(msg) from exc
        msg = "modified must be an ISO-8601 timestamp string"
        raise ValueError(msg)

    @field_validator("modified")
    @classmethod
    def _normalize_modified(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def _require_component_selector(self) -> _LocalFindingModel:
        if self.component_ref is None and self.purl is None:
            msg = "finding must include component_ref or purl"
            raise ValueError(msg)
        return self


class _LocalFindingsDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    findings: tuple[_LocalFindingModel, ...] = Field(max_length=MAX_LOCAL_FINDINGS)


def load_local_findings(
    path: Path,
    *,
    components: tuple[ComponentIdentity, ...],
) -> tuple[VulnerabilityFinding, ...]:
    """Load provider-neutral vulnerability findings from a local JSON document."""
    document = _parse_local_findings_document(path)
    components_by_ref = {component.ref: component for component in components}
    components_by_purl: dict[str, list[ComponentIdentity]] = defaultdict(list)
    for component in components:
        components_by_purl[component.purl.to_string()].append(component)

    return tuple(
        _finding_from_model(
            model,
            path=path,
            components_by_ref=components_by_ref,
            components_by_purl=components_by_purl,
        )
        for model in document.findings
    )


def _parse_local_findings_document(path: Path) -> _LocalFindingsDocument:
    try:
        if path.stat().st_size > MAX_LOCAL_FINDINGS_BYTES:
            msg = f"local findings {path} exceeds the {MAX_LOCAL_FINDINGS_BYTES} byte limit"
            raise LocalFindingsError(msg)
        with path.open(encoding="utf-8") as stream:
            raw_document = json.load(stream)
    except OSError as exc:
        msg = f"Could not read local findings {path}: {exc}"
        raise LocalFindingsError(msg) from exc
    except UnicodeDecodeError as exc:
        msg = f"Local findings {path} is not valid UTF-8 JSON"
        raise LocalFindingsError(msg) from exc
    except json.JSONDecodeError as exc:
        msg = f"Local findings {path} is not valid JSON: {exc.msg}"
        raise LocalFindingsError(msg) from exc
    except RecursionError as exc:
        msg = f"Local findings {path} is too deeply nested"
        raise LocalFindingsError(msg) from exc

    if not isinstance(raw_document, dict):
        msg = f"Local findings {path} must be a JSON object"
        raise LocalFindingsError(msg)

    return _validate_local_findings_document(raw_document, path=path)


def _validate_local_findings_document(
    raw_document: dict[str, Any],
    *,
    path: Path,
) -> _LocalFindingsDocument:
    try:
        return _LocalFindingsDocument.model_validate(raw_document)
    except ValidationError as exc:
        msg = f"Local findings {path} is invalid: {exc.errors()[0]['msg']}"
        raise LocalFindingsError(msg) from exc


def _finding_from_model(
    model: _LocalFindingModel,
    *,
    path: Path,
    components_by_ref: dict[str, ComponentIdentity],
    components_by_purl: dict[str, list[ComponentIdentity]],
) -> VulnerabilityFinding:
    component = _component_for_model(
        model,
        path=path,
        components_by_ref=components_by_ref,
        components_by_purl=components_by_purl,
    )
    return VulnerabilityFinding(
        id=model.id,
        source_name=model.source_name,
        source_url=model.source_url,
        component_ref=component.ref,
        purl=component.purl.to_string(),
        modified=model.modified,
        analysis_state=model.analysis_state,
        analysis_detail=model.analysis_detail,
    )


def _component_for_model(
    model: _LocalFindingModel,
    *,
    path: Path,
    components_by_ref: dict[str, ComponentIdentity],
    components_by_purl: dict[str, list[ComponentIdentity]],
) -> ComponentIdentity:
    if model.component_ref is not None:
        component = components_by_ref.get(model.component_ref)
        if component is None:
            msg = f"Local findings {path} references unknown component_ref {model.component_ref!r}"
            raise LocalFindingsError(msg)
        if model.purl is not None and model.purl != component.purl.to_string():
            msg = (
                f"Local findings {path} purl {model.purl!r} does not match "
                f"component_ref {model.component_ref!r}"
            )
            raise LocalFindingsError(msg)
        return component

    if model.purl is None:
        msg = f"Local findings {path} must include component_ref or purl"
        raise LocalFindingsError(msg)

    matching_components = components_by_purl.get(model.purl, [])
    if not matching_components:
        msg = f"Local findings {path} references unknown purl {model.purl!r}"
        raise LocalFindingsError(msg)
    if len(matching_components) > 1:
        refs = ", ".join(sorted(component.ref for component in matching_components))
        msg = (
            f"Local findings {path} purl {model.purl!r} matches multiple components; "
            f"use component_ref. Matching refs: {refs}"
        )
        raise LocalFindingsError(msg)
    return matching_components[0]
