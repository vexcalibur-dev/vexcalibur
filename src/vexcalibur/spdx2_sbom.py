"""SPDX 2.3 JSON inventory extraction shared by files and GitHub."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from packageurl import PackageURL

from vexcalibur.domain import ComponentIdentity, ComponentVersionError
from vexcalibur.json_boundary import StrictJsonError, strict_json_loads
from vexcalibur.sbom import MAX_COMPONENTS, SbomError, _read_sbom_bytes, _sbom_json_error_message

SUPPORTED_SPDX2_VERSION = "SPDX-2.3"


def load_spdx2_sbom(path: Path) -> tuple[ComponentIdentity, ...]:
    """Load package identities from a local SPDX 2.3 JSON SBOM.

    Args:
        path: Regular file containing a bare SPDX 2.3 JSON document.

    Returns:
        Immutable component identities sorted by package URL and reference.
        Packages without package-manager purl references are omitted.

    Raises:
        SbomError: The file is unreadable, oversized, malformed, unsupported,
            or contains ambiguous or contradictory package identities.
    """
    raw_content = _read_sbom_bytes(path)
    try:
        raw_document = strict_json_loads(raw_content)
    except StrictJsonError as exc:
        raise SbomError(_sbom_json_error_message(path=path, error=exc)) from exc
    return component_identities_from_spdx2_document(raw_document, source=f"SBOM {path}")


def component_identities_from_spdx2_document(
    raw_document: Any,
    *,
    source: str,
    skip_package: Callable[[str | None, PackageURL], bool] | None = None,
) -> tuple[ComponentIdentity, ...]:
    """Extract inventory, optionally applying a source-specific package filter."""
    if not isinstance(raw_document, dict):
        raise SbomError(f"{source} must be a JSON object")
    version = raw_document.get("spdxVersion")
    if version != SUPPORTED_SPDX2_VERSION:
        raise SbomError(
            f"{source} has unsupported spdxVersion {version!r}; "
            f"supported: {SUPPORTED_SPDX2_VERSION}"
        )
    packages = raw_document.get("packages")
    if not isinstance(packages, list):
        raise SbomError(f"{source} field 'packages' must be a list")
    if len(packages) > MAX_COMPONENTS:
        raise SbomError(f"{source} contains more than {MAX_COMPONENTS} packages")
    components = tuple(
        component
        for package in packages
        for component in (
            _spdx2_package_identity(package, source=source, skip_package=skip_package),
        )
        if component is not None
    )
    _validate_unique_component_refs(components, source=source)
    return tuple(
        sorted(
            _dedupe_components(components),
            key=lambda component: (component.purl.to_string(), component.ref),
        )
    )


def _spdx2_package_identity(
    package: Any,
    *,
    source: str,
    skip_package: Callable[[str | None, PackageURL], bool] | None,
) -> ComponentIdentity | None:
    if not isinstance(package, dict):
        msg = f"{source} packages must be objects"
        raise SbomError(msg)

    purl = _spdx2_package_purl(package, source=source)
    if purl is None:
        return None

    spdx_id = package.get("SPDXID")
    if spdx_id is not None and not isinstance(spdx_id, str):
        msg = f"{source} package SPDXID values must be strings"
        raise SbomError(msg)
    if skip_package is not None and skip_package(spdx_id, purl):
        return None

    name = package.get("name")
    if name is not None and not isinstance(name, str):
        msg = f"{source} package names must be strings"
        raise SbomError(msg)

    version = package.get("versionInfo")
    if version is not None and not isinstance(version, str):
        msg = f"{source} package versionInfo values must be strings"
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
        msg = f"{source} package has conflicting version identity: {exc}"
        raise SbomError(msg) from exc


def _spdx2_package_purl(package: dict[str, Any], *, source: str) -> PackageURL | None:
    external_refs = package.get("externalRefs", [])
    if not isinstance(external_refs, list):
        msg = f"{source} package externalRefs values must be lists"
        raise SbomError(msg)
    package_urls: dict[str, PackageURL] = {}
    for external_ref in external_refs:
        if not isinstance(external_ref, dict):
            msg = f"{source} package externalRefs entries must be objects"
            raise SbomError(msg)
        if external_ref.get("referenceCategory") != "PACKAGE-MANAGER":
            continue
        if external_ref.get("referenceType") != "purl":
            continue
        reference_locator = external_ref.get("referenceLocator")
        if not isinstance(reference_locator, str) or reference_locator.strip() == "":
            msg = f"{source} package purl referenceLocator values must be strings"
            raise SbomError(msg)
        try:
            package_url = PackageURL.from_string(reference_locator)
            canonical_purl = package_url.to_string()
        except ValueError as exc:
            msg = f"{source} package purl is invalid: {exc}"
            raise SbomError(msg) from exc
        package_urls[canonical_purl] = package_url
    if len(package_urls) > 1:
        msg = f"{source} package has multiple distinct package URL references"
        raise SbomError(msg)
    return next(iter(package_urls.values()), None)


def _validate_unique_component_refs(
    components: tuple[ComponentIdentity, ...], *, source: str
) -> None:
    seen_refs: set[str] = set()
    duplicate_refs: set[str] = set()
    for component in components:
        if component.ref in seen_refs:
            duplicate_refs.add(component.ref)
        seen_refs.add(component.ref)
    if duplicate_refs:
        duplicate_list = ", ".join(sorted(duplicate_refs))
        msg = f"{source} contains duplicate component bom-ref values: {duplicate_list}"
        raise SbomError(msg)


def _dedupe_components(components: tuple[ComponentIdentity, ...]) -> tuple[ComponentIdentity, ...]:
    deduped: dict[tuple[str, str], ComponentIdentity] = {}
    for component in components:
        deduped[(component.ref, component.purl.to_string())] = component
    return tuple(deduped.values())
