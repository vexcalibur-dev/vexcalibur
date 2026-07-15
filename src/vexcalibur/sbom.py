"""CycloneDX SBOM ingestion."""

from __future__ import annotations

import codecs
from pathlib import Path
from typing import Any, cast

from cyclonedx.exception import CycloneDxException
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from defusedxml import ElementTree as DefusedElementTree  # type: ignore[import-untyped]
from defusedxml.common import DefusedXmlException  # type: ignore[import-untyped]

from vexcalibur.domain import ComponentIdentity, ComponentVersionError
from vexcalibur.input_file import BoundedFileReadError, read_bounded_regular_file
from vexcalibur.json_boundary import JsonFailureKind, StrictJsonError, strict_json_loads

SUPPORTED_CYCLONEDX_VERSIONS = frozenset(("1.4", "1.5", "1.6"))
SUPPORTED_CYCLONEDX_JSON_VERSIONS = SUPPORTED_CYCLONEDX_VERSIONS
SUPPORTED_CYCLONEDX_XML_VERSIONS = SUPPORTED_CYCLONEDX_VERSIONS
MAX_SBOM_BYTES = 10 * 1024 * 1024
MAX_COMPONENTS = 10_000
MAX_COMPONENT_DEPTH = 50
CYCLONEDX_XML_NAMESPACE_PREFIX = "http://cyclonedx.org/schema/bom/"
# cyclonedx-python-lib models the latest component enum; XML preflight keeps older
# schema namespaces strict before handing the tree to the canonical deserializer.
CYCLONEDX_COMPONENT_TYPES_BY_VERSION = {
    "1.4": frozenset(
        (
            "application",
            "container",
            "device",
            "file",
            "firmware",
            "framework",
            "library",
            "operating-system",
        )
    ),
    "1.5": frozenset(
        (
            "application",
            "container",
            "data",
            "device",
            "device-driver",
            "file",
            "firmware",
            "framework",
            "library",
            "machine-learning-model",
            "operating-system",
            "platform",
        )
    ),
    "1.6": frozenset(
        (
            "application",
            "container",
            "cryptographic-asset",
            "data",
            "device",
            "device-driver",
            "file",
            "firmware",
            "framework",
            "library",
            "machine-learning-model",
            "operating-system",
            "platform",
        )
    ),
}


class SbomError(ValueError):
    """Raised when an SBOM cannot be parsed into supported component data."""


def load_cyclonedx_sbom(path: Path) -> tuple[ComponentIdentity, ...]:
    """Load supported component identities from a CycloneDX JSON or XML SBOM."""
    raw_content = _read_sbom_bytes(path)
    if _looks_like_xml(raw_content):
        return _component_identities_from_bom(
            _parse_cyclonedx_xml(raw_content, path=path),
            path=path,
        )

    return _component_identities_from_bom(
        _parse_cyclonedx_json(raw_content, path=path),
        path=path,
    )


def load_cyclonedx_json(path: Path) -> tuple[ComponentIdentity, ...]:
    """Load supported component identities from a CycloneDX JSON SBOM."""
    raw_content = _read_sbom_bytes(path)
    if _looks_like_xml(raw_content):
        msg = f"SBOM {path} appears to be XML; use load_cyclonedx_sbom for XML input"
        raise SbomError(msg)

    return _component_identities_from_bom(
        _parse_cyclonedx_json(raw_content, path=path),
        path=path,
    )


def _read_sbom_bytes(path: Path) -> bytes:
    try:
        return read_bounded_regular_file(
            path,
            max_bytes=MAX_SBOM_BYTES,
            description=f"SBOM {path}",
        )
    except BoundedFileReadError as exc:
        raise SbomError(str(exc)) from exc


def _parse_cyclonedx_json(raw_content: bytes, *, path: Path) -> Bom:
    try:
        raw_bom = strict_json_loads(raw_content)
    except StrictJsonError as exc:
        msg = _sbom_json_error_message(path=path, error=exc)
        raise SbomError(msg) from exc

    _validate_cyclonedx_json_shape(raw_bom, path=path)

    try:
        bom = Bom.from_json(data=raw_bom)  # type: ignore[attr-defined]
    except (CycloneDxException, KeyError, RecursionError, TypeError, ValueError) as exc:
        msg = f"SBOM {path} is not a supported CycloneDX JSON document: {exc}"
        raise SbomError(msg) from exc
    return cast(Bom, bom)


def _parse_cyclonedx_xml(raw_content: bytes, *, path: Path) -> Bom:
    root, namespace, spec_version = _validate_cyclonedx_xml_shape(raw_content, path=path)
    _validate_cyclonedx_xml_components(
        root,
        namespace=namespace,
        spec_version=spec_version,
        path=path,
    )
    _prune_foreign_xml_elements(root, namespace=namespace)

    try:
        bom = Bom.from_xml(data=root, default_namespace=namespace)  # type: ignore[attr-defined]
    except (
        AttributeError,
        CycloneDxException,
        KeyError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exc:
        msg = f"SBOM {path} is not a supported CycloneDX XML document: {exc}"
        raise SbomError(msg) from exc
    if bom is None:
        return Bom()
    return cast(Bom, bom)


def _component_identities_from_bom(
    bom: Bom,
    *,
    path: Path,
) -> tuple[ComponentIdentity, ...]:
    components = _component_tree(bom)
    try:
        identities = tuple(
            _component_identity(component) for component in components if component.purl
        )
    except ComponentVersionError as exc:
        msg = f"SBOM {path} contains a component with conflicting version identity: {exc}"
        raise SbomError(msg) from exc
    _validate_unique_component_refs(identities)
    return tuple(
        sorted(
            _dedupe_components(identities),
            key=lambda component: (component.purl.to_string(), component.ref),
        )
    )


def _sbom_json_error_message(*, path: Path, error: StrictJsonError) -> str:
    if error.kind is JsonFailureKind.ENCODING:
        return f"SBOM {path} is not valid UTF-8 JSON"
    if error.kind is JsonFailureKind.DUPLICATE_KEY:
        return f"SBOM {path} must not contain duplicate JSON object keys"
    if error.kind is JsonFailureKind.NESTING:
        return f"SBOM {path} is too deeply nested"
    if error.kind is JsonFailureKind.INTEGER:
        return f"SBOM {path} contains an oversized JSON integer"
    return f"SBOM {path} is not valid JSON: {error}"


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


def _validate_cyclonedx_xml_shape(raw_content: bytes, *, path: Path) -> tuple[Any, str, str]:
    try:
        root = DefusedElementTree.fromstring(
            raw_content,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except DefusedXmlException as exc:
        msg = f"SBOM {path} XML must not contain DTD, entity, or external reference declarations"
        raise SbomError(msg) from exc
    except DefusedElementTree.ParseError as exc:
        msg = f"SBOM {path} is not valid XML: {exc}"
        raise SbomError(msg) from exc
    except (LookupError, UnicodeError) as exc:
        msg = f"SBOM {path} uses an unsupported or invalid XML encoding"
        raise SbomError(msg) from exc

    namespace, spec_version = _cyclonedx_xml_namespace_and_version(root.tag, path=path)
    if spec_version not in SUPPORTED_CYCLONEDX_XML_VERSIONS:
        supported_versions = ", ".join(sorted(SUPPORTED_CYCLONEDX_XML_VERSIONS))
        msg = (
            f"SBOM {path} has unsupported CycloneDX XML schema version {spec_version!r}; "
            f"supported: {supported_versions}"
        )
        raise SbomError(msg)
    bom_version = root.get("version")
    if bom_version is not None and not _is_positive_integer_text(bom_version):
        msg = f"SBOM {path} XML attribute 'version' must be a positive integer when present"
        raise SbomError(msg)
    return root, namespace, spec_version


def _is_positive_integer_text(value: str) -> bool:
    return value.isdecimal() and any(character != "0" for character in value)


def _validate_cyclonedx_xml_components(
    root: Any,
    *,
    namespace: str,
    spec_version: str,
    path: Path,
) -> None:
    component_count = 0
    seen_refs: set[str] = set()
    stack: list[tuple[Any, int]] = [
        (component, 0) for component in _cyclonedx_xml_component_roots(root, namespace=namespace)
    ]
    while stack:
        component, depth = stack.pop()
        component_count += 1
        if depth > MAX_COMPONENT_DEPTH:
            msg = f"SBOM {path} exceeds the component nesting limit of {MAX_COMPONENT_DEPTH}"
            raise SbomError(msg)
        if component_count > MAX_COMPONENTS:
            msg = f"SBOM {path} contains more than {MAX_COMPONENTS} components"
            raise SbomError(msg)
        _validate_unique_xml_component_ref(component, seen_refs=seen_refs, path=path)
        _validate_xml_component_type(component.get("type"), spec_version=spec_version, path=path)
        stack.extend(
            (child_component, depth + 1)
            for child_component in _cyclonedx_xml_child_components(
                component,
                namespace=namespace,
            )
        )


def _validate_unique_xml_component_ref(component: Any, *, seen_refs: set[str], path: Path) -> None:
    component_ref = component.get("bom-ref")
    if not isinstance(component_ref, str) or component_ref.strip() == "":
        return
    if component_ref in seen_refs:
        msg = f"SBOM {path} contains duplicate component bom-ref values: {component_ref}"
        raise SbomError(msg)
    seen_refs.add(component_ref)


def _validate_xml_component_type(component_type: Any, *, spec_version: str, path: Path) -> None:
    if not isinstance(component_type, str) or component_type.strip() == "":
        msg = f"SBOM {path} XML components must include a type"
        raise SbomError(msg)
    component_type = component_type.strip()
    supported_types = CYCLONEDX_COMPONENT_TYPES_BY_VERSION[spec_version]
    if component_type not in supported_types:
        supported_type_list = ", ".join(sorted(supported_types))
        msg = (
            f"SBOM {path} XML component type {component_type!r} is not supported "
            f"for CycloneDX {spec_version}; supported: {supported_type_list}"
        )
        raise SbomError(msg)


def _cyclonedx_xml_component_roots(root: Any, *, namespace: str) -> tuple[Any, ...]:
    components: list[Any] = []
    for child in root:
        if _is_cyclonedx_xml_element(child, namespace=namespace, local_name="metadata"):
            components.extend(
                metadata_child
                for metadata_child in child
                if _is_cyclonedx_xml_element(
                    metadata_child,
                    namespace=namespace,
                    local_name="component",
                )
            )
        elif _is_cyclonedx_xml_element(child, namespace=namespace, local_name="components"):
            components.extend(
                component_child
                for component_child in child
                if _is_cyclonedx_xml_element(
                    component_child,
                    namespace=namespace,
                    local_name="component",
                )
            )
    return tuple(components)


def _prune_foreign_xml_elements(element: Any, *, namespace: str) -> None:
    stack = [element]
    while stack:
        current = stack.pop()
        for child in tuple(current):
            if _is_cyclonedx_xml_namespace(child, namespace=namespace):
                stack.append(child)
                continue
            current.remove(child)


def _cyclonedx_xml_child_components(component: Any, *, namespace: str) -> tuple[Any, ...]:
    components: list[Any] = []
    for child in component:
        if not _is_cyclonedx_xml_element(child, namespace=namespace, local_name="components"):
            continue
        components.extend(
            component_child
            for component_child in child
            if _is_cyclonedx_xml_element(
                component_child, namespace=namespace, local_name="component"
            )
        )
    return tuple(components)


def _cyclonedx_xml_namespace_and_version(tag: str, *, path: Path) -> tuple[str, str]:
    namespace, local_name = _split_xml_tag(tag)
    if local_name != "bom" or namespace is None:
        msg = f"SBOM {path} must be a CycloneDX XML document"
        raise SbomError(msg)
    if not namespace.startswith(CYCLONEDX_XML_NAMESPACE_PREFIX):
        msg = f"SBOM {path} must use a CycloneDX XML namespace"
        raise SbomError(msg)
    return namespace, namespace.removeprefix(CYCLONEDX_XML_NAMESPACE_PREFIX)


def _is_cyclonedx_xml_element(element: Any, *, namespace: str, local_name: str) -> bool:
    element_namespace, element_local_name = _split_xml_tag(element.tag)
    return element_namespace == namespace and element_local_name == local_name


def _is_cyclonedx_xml_namespace(element: Any, *, namespace: str) -> bool:
    element_namespace, _ = _split_xml_tag(element.tag)
    return element_namespace == namespace


def _split_xml_tag(tag: str) -> tuple[str | None, str]:
    if tag.startswith("{") and "}" in tag:
        namespace, local_name = tag[1:].split("}", maxsplit=1)
        return namespace, local_name
    return None, tag


def _looks_like_xml(raw_content: bytes) -> bool:
    if _looks_like_ascii_compatible_xml(raw_content):
        return True
    for encoding in _candidate_xml_encodings(raw_content):
        try:
            if raw_content.decode(encoding).lstrip("\ufeff \t\r\n").startswith("<"):
                return True
        except UnicodeDecodeError:
            continue
    return False


def _looks_like_ascii_compatible_xml(raw_content: bytes) -> bool:
    if raw_content.startswith(codecs.BOM_UTF8):
        raw_content = raw_content[len(codecs.BOM_UTF8) :]
    return raw_content.lstrip(b" \t\r\n").startswith(b"<")


def _candidate_xml_encodings(raw_content: bytes) -> tuple[str, ...]:
    if raw_content.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        return ("utf-32",)
    if raw_content.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return ("utf-16",)
    return ("utf-32-le", "utf-32-be", "utf-16-le", "utf-16-be")


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
