"""Shared URL boundary validation helpers."""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from urllib.parse import ParseResult, urlparse


class BaseUrlValidationError(ValueError):
    """Raised when a user-provided service base URL is unsafe or malformed."""


@dataclass(frozen=True)
class ValidatedBaseUrl:
    """A normalized base URL and its parsed representation."""

    value: str
    parsed: ParseResult


def validate_base_url(
    value: str,
    *,
    option_name: str,
    allowed_schemes: Collection[str],
    scheme_message: str,
) -> ValidatedBaseUrl:
    """Normalize and validate a service base URL."""
    normalized = value.strip().rstrip("/")
    try:
        parsed = urlparse(normalized)
        hostname = parsed.hostname
    except ValueError as exc:
        raise BaseUrlValidationError(scheme_message) from exc

    if parsed.scheme not in allowed_schemes or hostname is None:
        raise BaseUrlValidationError(scheme_message)

    try:
        _ = parsed.port
    except ValueError as exc:
        msg = f"{option_name} port is invalid"
        raise BaseUrlValidationError(msg) from exc

    if parsed.username is not None or parsed.password is not None:
        msg = f"{option_name} must not include userinfo"
        raise BaseUrlValidationError(msg)

    if parsed.params or parsed.query or parsed.fragment:
        msg = f"{option_name} must not include params, query, or fragment"
        raise BaseUrlValidationError(msg)

    return ValidatedBaseUrl(value=normalized, parsed=parsed)
