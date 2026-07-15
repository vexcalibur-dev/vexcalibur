"""Strict JSON decoding for untrusted input boundaries."""

from __future__ import annotations

import json
import math
from collections.abc import Iterable
from enum import Enum
from typing import Any

MAX_JSON_INTEGER_DIGITS = 1_000
MAX_JSON_NESTING = 100


class JsonFailureKind(str, Enum):
    """Stable categories for strict JSON failures."""

    DUPLICATE_KEY = "duplicate_key"
    ENCODING = "encoding"
    INTEGER = "integer"
    NESTING = "nesting"
    SYNTAX = "syntax"


class StrictJsonError(ValueError):
    """Raised when bytes cannot be decoded as strict UTF-8 JSON."""

    def __init__(self, kind: JsonFailureKind, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind


def strict_json_loads(raw_content: bytes) -> Any:
    """Decode UTF-8 JSON while rejecting ambiguous or pathological values."""
    try:
        text = raw_content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StrictJsonError(JsonFailureKind.ENCODING, "input is not valid UTF-8") from exc

    _validate_nesting(text)

    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonstandard_number,
            parse_float=_finite_float,
            parse_int=_bounded_integer,
        )
    except StrictJsonError:
        raise
    except RecursionError as exc:
        raise StrictJsonError(JsonFailureKind.NESTING, "JSON is too deeply nested") from exc
    except json.JSONDecodeError as exc:
        raise StrictJsonError(JsonFailureKind.SYNTAX, exc.msg) from exc
    except ValueError as exc:
        # Keep interpreter-specific integer and decoder limits behind the
        # shared error contract.
        raise StrictJsonError(JsonFailureKind.SYNTAX, "JSON value is invalid") from exc


def _validate_nesting(value: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in value:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_NESTING:
                raise StrictJsonError(
                    JsonFailureKind.NESTING,
                    f"JSON must not exceed {MAX_JSON_NESTING} nested arrays or objects",
                )
        elif character in "]}":
            depth = max(0, depth - 1)


def _unique_object(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJsonError(
                JsonFailureKind.DUPLICATE_KEY,
                "JSON objects must not contain duplicate keys",
            )
        result[key] = value
    return result


def _bounded_integer(value: str) -> int:
    digits = value.removeprefix("-")
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise StrictJsonError(
            JsonFailureKind.INTEGER,
            f"JSON integers must not exceed {MAX_JSON_INTEGER_DIGITS} decimal digits",
        )
    return int(value)


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise StrictJsonError(
            JsonFailureKind.SYNTAX,
            "JSON numbers must have a finite floating-point representation",
        )
    return parsed


def _reject_nonstandard_number(value: str) -> None:
    raise StrictJsonError(
        JsonFailureKind.SYNTAX,
        "JSON must not contain NaN or infinite numeric values",
    )
