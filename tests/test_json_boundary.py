import pytest

from vexcalibur.json_boundary import JsonFailureKind, StrictJsonError, strict_json_loads


@pytest.mark.parametrize(
    "document",
    (
        b'{"value": 1, "value": 2}',
        b'{"outer": {"value": 1, "value": 2}}',
    ),
)
def test_strict_json_rejects_duplicate_object_keys(document: bytes) -> None:
    with pytest.raises(StrictJsonError) as captured:
        strict_json_loads(document)

    assert captured.value.kind is JsonFailureKind.DUPLICATE_KEY


def test_strict_json_rejects_excessive_nesting() -> None:
    document = ("[" * 2_000 + "]" * 2_000).encode()

    with pytest.raises(StrictJsonError) as captured:
        strict_json_loads(document)

    assert captured.value.kind is JsonFailureKind.NESTING


def test_strict_json_rejects_oversized_integer() -> None:
    document = ('{"value":' + "1" * 1_001 + "}").encode()

    with pytest.raises(StrictJsonError) as captured:
        strict_json_loads(document)

    assert captured.value.kind is JsonFailureKind.INTEGER


@pytest.mark.parametrize("value", (b"NaN", b"Infinity", b"-Infinity"))
def test_strict_json_rejects_nonstandard_numeric_values(value: bytes) -> None:
    with pytest.raises(StrictJsonError) as captured:
        strict_json_loads(value)

    assert captured.value.kind is JsonFailureKind.SYNTAX


def test_strict_json_rejects_finite_syntax_that_overflows_to_infinity() -> None:
    with pytest.raises(StrictJsonError) as captured:
        strict_json_loads(b"1e9999")

    assert captured.value.kind is JsonFailureKind.SYNTAX


def test_strict_json_normalizes_encoding_and_syntax_errors() -> None:
    with pytest.raises(StrictJsonError) as encoding_error:
        strict_json_loads(b"\xff")
    with pytest.raises(StrictJsonError) as syntax_error:
        strict_json_loads(b"{")

    assert encoding_error.value.kind is JsonFailureKind.ENCODING
    assert syntax_error.value.kind is JsonFailureKind.SYNTAX


def test_strict_json_accepts_unique_objects_and_bounded_integers() -> None:
    assert strict_json_loads(b'{"outer":{"value":1000,"brackets":"[[{{"}}') == {
        "outer": {"value": 1000, "brackets": "[[{{"}
    }
