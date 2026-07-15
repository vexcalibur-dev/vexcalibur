"""Shared validation for generation source options."""

from dataclasses import dataclass
from pathlib import Path


class GenerateSourceOptionError(Exception):
    """Raised when generate source options are mutually incompatible."""


@dataclass(frozen=True)
class GenerateSourceOptions:
    """Validated source-mode options for VEX generation."""

    findings_file: Path | None
    offline: bool
    osv_url: str | None
    allow_public_osv: bool
    osv_source_name: str | None = None
    osv_source_url: str | None = None


def resolve_generate_source_options(
    *,
    findings_file: Path | None,
    offline: bool,
    osv_url: str | None,
    allow_public_osv: bool,
    osv_source_name: str | None = None,
    osv_source_url: str | None = None,
) -> GenerateSourceOptions:
    """Validate and normalize mutually exclusive VEX generation source options."""
    normalized_osv_url = None if osv_url is None else osv_url.strip()
    normalized_source_name = None if osv_source_name is None else osv_source_name.strip()
    normalized_source_url = None if osv_source_url is None else osv_source_url.strip()

    if offline and findings_file is None:
        msg = "--offline requires --findings-file in this release"
        raise GenerateSourceOptionError(msg)
    if normalized_osv_url is not None and not normalized_osv_url:
        msg = "--osv-url must not be empty"
        raise GenerateSourceOptionError(msg)
    if normalized_source_name is not None and not normalized_source_name:
        msg = "--osv-source-name must not be empty"
        raise GenerateSourceOptionError(msg)
    if normalized_source_url is not None and not normalized_source_url:
        msg = "--osv-source-url must not be empty"
        raise GenerateSourceOptionError(msg)
    if (normalized_source_name is None) != (normalized_source_url is None):
        msg = "--osv-source-name and --osv-source-url must be provided together"
        raise GenerateSourceOptionError(msg)
    if findings_file is None:
        return GenerateSourceOptions(
            findings_file=findings_file,
            offline=offline,
            osv_url=normalized_osv_url,
            allow_public_osv=allow_public_osv,
            osv_source_name=normalized_source_name,
            osv_source_url=normalized_source_url,
        )
    if allow_public_osv:
        msg = "--allow-public-osv cannot be combined with --findings-file"
        raise GenerateSourceOptionError(msg)
    if normalized_osv_url is not None:
        msg = "--osv-url cannot be combined with --findings-file"
        raise GenerateSourceOptionError(msg)
    if normalized_source_name is not None:
        msg = "--osv-source-name and --osv-source-url cannot be combined with --findings-file"
        raise GenerateSourceOptionError(msg)

    return GenerateSourceOptions(
        findings_file=findings_file,
        offline=offline,
        osv_url=normalized_osv_url,
        allow_public_osv=allow_public_osv,
        osv_source_name=normalized_source_name,
        osv_source_url=normalized_source_url,
    )
