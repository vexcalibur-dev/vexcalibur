"""CycloneDX SBOM ingestion."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cyclonedx.exception import CycloneDxException
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component

from vexcalibur.domain import ComponentIdentity

SUPPORTED_CYCLONEDX_JSON_VERSIONS = {"1.4", "1.5", "1.6"}
CYCLONEDX_XML_TRACKING_URL = "https://github.com/vexcalibur-dev/vexcalibur/issues/43"
MAX_SBOM_BYTES = 10 * 1024 * 1024
MAX_COMPONENTS = 10_000
MAX_COMPONENT_DEPTH = 50


class SbomError(ValueError):
    """Raised when an SBOM cannot be parsed into supported component data."""


def load_cyclonedx_json(path: Path) -> tuple[ComponentIdentity, ...]:
    """Load supported component identities from a CycloneDX JSON SBOM."""
    try:
        if path.stat().st_size > MAX_SBOM_BYTES:
            msg = f"SBOM {path} exceeds the {MAX_SBOM_BYTES} byte limit"
            raise SbomError(msg)
        raw_content = path.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"Could not read SBOM {path}: {exc}"
        raise SbomError(msg) from exc
    except UnicodeDecodeError as exc:
        msg = f"SBOM {path} is not valid UTF-8 JSON"
        raise SbomError(msg) from exc

    if _looks_like_xml(raw_content):
        msg = (
            f"SBOM {path} appears to be CycloneDX XML, which is not supported yet; "
            f"track XML support at {CYCLONEDX_XML_TRACKING_URL}"
        )
        raise SbomError(msg)

    try:
        raw_bom = json.loads(raw_content)
    except json.JSONDecodeError as exc:
        msg = f"SBOM {path} is not valid JSON: {exc.msg}"
        raise SbomError(msg) from exc

    _validate_cyclonedx_json_shape(raw_bom, path=path)

    try:
        bom = Bom.from_json(data=raw_bom)  # type: ignore[attr-defined]
    except (CycloneDxException, KeyError, RecursionError, TypeError, ValueError) as exc:
        msg = f"SBOM {path} is not a supported CycloneDX JSON document: {exc}"
        raise SbomError(msg) from exc

    components = _component_tree(bom)
    identities = tuple(_component_identity(component) for component in components if component.purl)
    _validate_unique_component_refs(identities)
    return tuple(
        sorted(
            _dedupe_components(identities),
            key=lambda component: (component.purl.to_string(), component.ref),
        )
    )


def _validate_cyclonedx_json_shape(raw_bom: Any, *, path: Path) -> None:
    if not isinstance(raw_bom, dict):
        msg = f"SBOM {path} must be a JSON object"
        raise SbomError(msg)
    if raw_bom.get("bomFormat") != "CycloneDX":
        msg = f"SBOM {path} must have bomFormat 'CycloneDX'"
        raise SbomError(msg)
    spec_version = raw_bom.get("specVersion")
    if spec_version not in SUPPORTED_CYCLONEDX_JSON_VERSIONS:
        supported_versions = ", ".join(sorted(SUPPORTED_CYCLONEDX_JSON_VERSIONS))
        msg = (
            f"SBOM {path} has unsupported CycloneDX specVersion {spec_version!r}; "
            f"supported: {supported_versions}"
        )
        raise SbomError(msg)
    if "version" in raw_bom and not isinstance(raw_bom["version"], int):
        msg = f"SBOM {path} field 'version' must be an integer when present"
        raise SbomError(msg)
    metadata = raw_bom.get("metadata", {})
    if not isinstance(metadata, dict):
        msg = f"SBOM {path} field 'metadata' must be an object when present"
        raise SbomError(msg)
    if metadata.get("component") is not None:
        _validate_raw_component_tree(metadata["component"], path=path, depth=0)
    components = raw_bom.get("components", [])
    if not isinstance(components, list):
        msg = f"SBOM {path} field 'components' must be a list when present"
        raise SbomError(msg)
    for component in components:
        _validate_raw_component_tree(component, path=path, depth=0)


def _validate_raw_component_tree(component: Any, *, path: Path, depth: int) -> None:
    if depth > MAX_COMPONENT_DEPTH:
        msg = f"SBOM {path} exceeds the component nesting limit of {MAX_COMPONENT_DEPTH}"
        raise SbomError(msg)
    _validate_raw_component(component, path=path)
    child_components = component.get("components", []) if isinstance(component, dict) else []
    if not isinstance(child_components, list):
        msg = f"SBOM {path} component field 'components' must be a list when present"
        raise SbomError(msg)
    for child_component in child_components:
        _validate_raw_component_tree(child_component, path=path, depth=depth + 1)


def _validate_raw_component(component: Any, *, path: Path) -> None:
    if component is None:
        return
    if not isinstance(component, dict):
        msg = f"SBOM {path} components must be objects"
        raise SbomError(msg)
    if "purl" in component and not isinstance(component["purl"], str):
        msg = f"SBOM {path} component package URLs must be strings"
        raise SbomError(msg)
    if "name" in component and not isinstance(component["name"], str):
        msg = f"SBOM {path} component names must be strings"
        raise SbomError(msg)
    if "version" in component and not isinstance(component["version"], str):
        msg = f"SBOM {path} component versions must be strings"
        raise SbomError(msg)


def _looks_like_xml(raw_content: str) -> bool:
    return raw_content.lstrip("\ufeff \t\r\n").startswith("<")


def _component_tree(bom: Bom) -> tuple[Component, ...]:
    collected: list[Component] = []
    if bom.metadata and bom.metadata.component:
        collected.extend(_iter_components((bom.metadata.component,)))
    collected.extend(_iter_components(bom.components))
    if len(collected) > MAX_COMPONENTS:
        msg = f"SBOM contains more than {MAX_COMPONENTS} components"
        raise SbomError(msg)
    return tuple(collected)


def _iter_components(components: Any) -> tuple[Component, ...]:
    collected: list[Component] = []
    stack: list[tuple[Component, int]] = [
        (component, 0) for component in components or () if isinstance(component, Component)
    ]
    while stack:
        component, depth = stack.pop()
        if depth > MAX_COMPONENT_DEPTH:
            msg = f"SBOM exceeds the component nesting limit of {MAX_COMPONENT_DEPTH}"
            raise SbomError(msg)
        if isinstance(component, Component):
            collected.append(component)
            stack.extend(
                (child_component, depth + 1)
                for child_component in component.components or ()
                if isinstance(child_component, Component)
            )
        if len(collected) > MAX_COMPONENTS:
            msg = f"SBOM contains more than {MAX_COMPONENTS} components"
            raise SbomError(msg)
    return tuple(collected)


def _component_identity(component: Component) -> ComponentIdentity:
    if component.purl is None:
        msg = "component must have a package URL"
        raise SbomError(msg)

    ref = component.bom_ref.value or component.purl.to_string()
    return ComponentIdentity(
        ref=ref,
        name=component.name,
        version=component.version,
        purl=component.purl,
        type=component.type.value,
    )


def _validate_unique_component_refs(components: tuple[ComponentIdentity, ...]) -> None:
    seen_refs: set[str] = set()
    duplicate_refs: set[str] = set()
    for component in components:
        if component.ref in seen_refs:
            duplicate_refs.add(component.ref)
        seen_refs.add(component.ref)
    if duplicate_refs:
        duplicate_list = ", ".join(sorted(duplicate_refs))
        msg = f"SBOM contains duplicate component bom-ref values: {duplicate_list}"
        raise SbomError(msg)


def _dedupe_components(components: tuple[ComponentIdentity, ...]) -> tuple[ComponentIdentity, ...]:
    deduped: dict[tuple[str, str], ComponentIdentity] = {}
    for component in components:
        deduped[(component.ref, component.purl.to_string())] = component
    return tuple(deduped.values())
