"""Deterministic property tests for every untrusted parser boundary."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests.fuzz.boundaries import (
    FUZZ_TARGETS,
    MAX_FUZZ_INPUT_BYTES,
    OSV_PAGE_SEPARATOR,
    assert_deterministic_boundary,
    deterministic_outcome,
)

CORPUS_ROOT = Path(__file__).with_name("corpus")
CORPUS_EXPECTATIONS: dict[str, tuple[str, str | None]] = {
    "github/valid-spdx.json": ("accepted", None),
    "identity/unicode.txt": ("accepted", None),
    "json/deep-nesting.json": ("rejected", "nesting"),
    "json/duplicate-key.json": ("rejected", "duplicate_key"),
    "local/valid-findings.json": ("accepted", None),
    "osv/multi-page-query.json": ("accepted", None),
    "osv/safe-query.json": ("accepted", None),
    "osv/terminal-control.json": ("rejected", "OsvResponseError"),
    "osv/valid-batch.json": ("accepted", None),
    "osv/valid-get.json": ("accepted", None),
    "osv/valid-gzip-query.json": ("accepted", None),
    "sbom/forbidden-entity.xml": ("rejected", "SbomError"),
    "sbom/valid-json.json": ("accepted", None),
    "sbom/valid-xml.xml": ("accepted", None),
}

pytestmark = pytest.mark.fuzz


@pytest.mark.parametrize("target", FUZZ_TARGETS)
@given(data=st.binary(max_size=MAX_FUZZ_INPUT_BYTES))
def test_boundary_is_deterministic_and_typed(target: str, data: bytes) -> None:
    assert_deterministic_boundary(target, data)


@pytest.mark.parametrize("relative_seed", tuple(CORPUS_EXPECTATIONS))
def test_checked_in_corpus_preserves_security_semantics(relative_seed: str) -> None:
    target, _, _ = relative_seed.partition("/")
    seed = CORPUS_ROOT / relative_seed
    expected_state, expected_detail = CORPUS_EXPECTATIONS[relative_seed]

    assert_deterministic_boundary(target, seed.read_bytes())
    outcome = deterministic_outcome(target, seed.read_bytes())
    assert outcome[0] == expected_state
    if expected_detail is not None:
        assert outcome[1] == expected_detail


def test_every_checked_in_seed_has_an_explicit_security_expectation() -> None:
    checked_in_seeds = {
        seed.relative_to(CORPUS_ROOT).as_posix()
        for seed in CORPUS_ROOT.glob("*/*")
        if seed.is_file()
    }

    assert checked_in_seeds == set(CORPUS_EXPECTATIONS)


def test_duplicate_json_keys_have_a_stable_typed_rejection() -> None:
    assert deterministic_outcome("json", b'{"value":1,"value":2}') == (
        "rejected",
        "duplicate_key",
    )


def test_terminal_record_splitting_is_rejected_by_osv_boundary() -> None:
    document = b'T{"vulns":[{"id":"CVE-2026-0001\\n::error::forged"}]}'

    assert deterministic_outcome("osv", document) == ("rejected", "OsvResponseError")


def test_osv_fuzz_oracle_reaches_per_response_byte_limit() -> None:
    document = (
        b"T"
        + json.dumps(
            {"vulns": [], "padding": "x" * (17 * 1024)},
            separators=(",", ":"),
        ).encode()
    )

    assert deterministic_outcome("osv", document) == ("rejected", "OsvResponseError")


def test_osv_fuzz_oracle_reaches_cumulative_byte_limit() -> None:
    pages = (
        {"vulns": [], "next_page_token": "page-2", "padding": "x" * 12_000},
        {"vulns": [], "next_page_token": "page-3", "padding": "x" * 12_000},
        {"vulns": [], "padding": "x" * 12_000},
    )
    document = b"T" + OSV_PAGE_SEPARATOR.join(
        json.dumps(page, separators=(",", ":")).encode() for page in pages
    )

    assert deterministic_outcome("osv", document) == ("rejected", "OsvResponseError")


def test_osv_fuzz_oracle_reaches_total_vulnerability_limit() -> None:
    document = (
        b"T"
        + json.dumps(
            {"vulns": [{"id": f"CVE-2026-{index:04d}"} for index in range(25)]},
            separators=(",", ":"),
        ).encode()
    )

    assert deterministic_outcome("osv", document) == ("rejected", "OsvResponseError")


def test_equivalent_json_and_xml_component_identity_is_always_accepted() -> None:
    assert deterministic_outcome("identity", b"identity-equivalence")[0] == "accepted"


def test_identity_oracle_filters_xml_noncharacters_before_comparison() -> None:
    data = "component\n1.0.0\nref-\ufffe-\U0001fffe".encode()

    assert deterministic_outcome("identity", data)[0] == "accepted"
