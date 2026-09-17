"""Local SPDX 3 JSON-LD SBOM ingestion."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from packageurl import PackageURL

from vexcalibur.domain import ComponentIdentity, ComponentVersionError
from vexcalibur.json_boundary import StrictJsonError, strict_json_loads
from vexcalibur.sbom import (
    MAX_COMPONENTS,
    SbomError,
    _read_sbom_bytes,
    _sbom_json_error_message,
)

SUPPORTED_SPDX3_CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
_PACKAGE_TYPES = frozenset(("ai_AIPackage", "dataset_DatasetPackage", "software_Package"))
_EXTERNAL_IDENTIFIER_TYPE = "ExternalIdentifier"
_PACKAGE_URL_IDENTIFIER_TYPE = "packageUrl"


def load_spdx3_sbom(path: Path) -> tuple[ComponentIdentity, ...]:
    """Load supported component identities from an SPDX 3.0.1 JSON-LD SBOM.

    Args:
        path: Regular file containing an SPDX 3.0.1 JSON-LD document.

    Returns:
        Immutable component identities sorted by package URL and reference.
        Packages without package URLs are omitted.

    Raises:
        SbomError: The file is unreadable, oversized, malformed, unsupported,
            or contains unsafe or contradictory package data.
    """
    raw_content = _read_sbom_bytes(path)
    try:
        raw_document = strict_json_loads(raw_content)
    except StrictJsonError as exc:
        msg = _sbom_json_error_message(path=path, error=exc)
        raise SbomError(msg) from exc
    return component_identities_from_spdx3_document(raw_document, path=path)


def component_identities_from_spdx3_document(
    raw_document: Any,
    *,
    path: Path,
) -> tuple[ComponentIdentity, ...]:
    """Extract component identities from decoded SPDX 3 JSON-LD."""
    graph = _spdx3_graph(raw_document, path=path)
    packages = tuple(
        element
        for element in graph
        if isinstance(element, dict) and element.get("type") in _PACKAGE_TYPES
    )
    if len(packages) > MAX_COMPONENTS:
        msg = f"SBOM {path} contains more than {MAX_COMPONENTS} packages"
        raise SbomError(msg)
    identifiers_by_id = _spdx3_identifiers_by_id(graph)

    components = tuple(
        component
        for package in packages
        for component in (
            _spdx3_package_identity(
                package,
                path=path,
                identifiers_by_id=identifiers_by_id,
            ),
        )
        if component is not None
    )
    _validate_unique_component_refs(components, path=path)
    return tuple(
        sorted(
            _dedupe_components(components),
            key=lambda component: (component.purl.to_string(), component.ref),
        )
    )


def _spdx3_identifiers_by_id(graph: list[Any]) -> dict[str, dict[str, Any]]:
    identifiers: dict[str, dict[str, Any]] = {}
    for element in graph:
        if not isinstance(element, dict):
            continue
        if element.get("type") != _EXTERNAL_IDENTIFIER_TYPE:
            continue
        identifier_id = element.get("@id")
        if isinstance(identifier_id, str) and identifier_id.strip():
            identifiers[identifier_id] = element
    return identifiers


def _spdx3_graph(raw_document: Any, *, path: Path) -> list[Any]:
    if not isinstance(raw_document, dict):
        msg = f"SBOM {path} must be a JSON object"
        raise SbomError(msg)
    context = raw_document.get("@context")
    if context != SUPPORTED_SPDX3_CONTEXT:
        msg = (
            f"SBOM {path} must declare the SPDX 3.0.1 JSON-LD context "
            f"{SUPPORTED_SPDX3_CONTEXT!r} as its '@context' string"
        )
        raise SbomError(msg)
    graph = raw_document.get("@graph")
    if not isinstance(graph, list):
        msg = f"SBOM {path} field '@graph' must be a list"
        raise SbomError(msg)
    for element in graph:
        if not isinstance(element, dict):
            msg = f"SBOM {path} '@graph' entries must be objects"
            raise SbomError(msg)
    return graph


def _spdx3_package_identity(
    package: dict[str, Any],
    *,
    path: Path,
    identifiers_by_id: dict[str, dict[str, Any]],
) -> ComponentIdentity | None:
    purl = _spdx3_package_purl(package, path=path, identifiers_by_id=identifiers_by_id)
    if purl is None:
        return None

    spdx_id = package.get("spdxId")
    if spdx_id is not None and not isinstance(spdx_id, str):
        msg = f"SBOM {path} package spdxId values must be strings"
        raise SbomError(msg)

    name = package.get("name")
    if name is not None and not isinstance(name, str):
        msg = f"SBOM {path} package names must be strings"
        raise SbomError(msg)

    version = package.get("software_packageVersion")
    if version is not None and not isinstance(version, str):
        msg = f"SBOM {path} package software_packageVersion values must be strings"
        raise SbomError(msg)

    ref = spdx_id.strip() if isinstance(spdx_id, str) and spdx_id.strip() else purl.to_string()
    try:
        return ComponentIdentity(
            ref=ref,
            name=name or purl.name,
            version=version,
            purl=purl,
        )
    except ComponentVersionError as exc:
        msg = f"SBOM {path} package has conflicting version identity: {exc}"
        raise SbomError(msg) from exc


def _spdx3_package_purl(
    package: dict[str, Any],
    *,
    path: Path,
    identifiers_by_id: dict[str, dict[str, Any]],
) -> PackageURL | None:
    package_urls: dict[str, PackageURL] = {}

    raw_package_url = package.get("software_packageUrl")
    if raw_package_url is not None:
        if not isinstance(raw_package_url, str) or raw_package_url.strip() == "":
            msg = f"SBOM {path} package software_packageUrl values must be strings"
            raise SbomError(msg)
        package_url = _parse_package_url(raw_package_url, path=path)
        package_urls[package_url.to_string()] = package_url

    external_identifiers = package.get("externalIdentifier", [])
    if not isinstance(external_identifiers, list):
        msg = f"SBOM {path} package externalIdentifier values must be lists"
        raise SbomError(msg)
    for entry in external_identifiers:
        external_identifier = _resolve_external_identifier(
            entry,
            path=path,
            identifiers_by_id=identifiers_by_id,
        )
        if external_identifier.get("externalIdentifierType") != _PACKAGE_URL_IDENTIFIER_TYPE:
            continue
        identifier = external_identifier.get("identifier")
        if not isinstance(identifier, str) or identifier.strip() == "":
            msg = f"SBOM {path} package packageUrl identifier values must be strings"
            raise SbomError(msg)
        package_url = _parse_package_url(identifier, path=path)
        package_urls[package_url.to_string()] = package_url

    if len(package_urls) > 1:
        msg = f"SBOM {path} package has multiple distinct package URL identities"
        raise SbomError(msg)
    return next(iter(package_urls.values()), None)


def _resolve_external_identifier(
    entry: Any,
    *,
    path: Path,
    identifiers_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    if isinstance(entry, dict):
        return entry
    if isinstance(entry, str):
        resolved = identifiers_by_id.get(entry)
        if resolved is None:
            msg = (
                f"SBOM {path} package externalIdentifier reference {entry!r} does not "
                "resolve to an ExternalIdentifier in '@graph'"
            )
            raise SbomError(msg)
        return resolved
    msg = f"SBOM {path} package externalIdentifier entries must be objects or references"
    raise SbomError(msg)


def _parse_package_url(value: str, *, path: Path) -> PackageURL:
    try:
        return PackageURL.from_string(value)
    except ValueError as exc:
        msg = f"SBOM {path} package purl is invalid: {exc}"
        raise SbomError(msg) from exc


def _validate_unique_component_refs(
    components: tuple[ComponentIdentity, ...],
    *,
    path: Path,
) -> None:
    seen_refs: set[str] = set()
    duplicate_refs: set[str] = set()
    for component in components:
        if component.ref in seen_refs:
            duplicate_refs.add(component.ref)
        seen_refs.add(component.ref)
    if duplicate_refs:
        duplicate_list = ", ".join(sorted(duplicate_refs))
        msg = f"SBOM {path} contains duplicate package spdxId values: {duplicate_list}"
        raise SbomError(msg)


def _dedupe_components(components: tuple[ComponentIdentity, ...]) -> tuple[ComponentIdentity, ...]:
    deduped: dict[tuple[str, str], ComponentIdentity] = {}
    for component in components:
        deduped[(component.ref, component.purl.to_string())] = component
    return tuple(deduped.values())
