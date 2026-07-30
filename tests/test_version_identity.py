from __future__ import annotations

from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

import vexcalibur
from vexcalibur import version_identity
from vexcalibur.version_identity import (
    SourceVersionIdentityError,
    verify_source_checkout_version,
)

ROOT = Path(__file__).parents[1]


def test_current_editable_version_identifies_checkout_head() -> None:
    verify_source_checkout_version(vexcalibur.__version__)


def test_editable_version_rejects_stale_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(version_identity, "_editable_source_root", lambda: ROOT)
    monkeypatch.setattr(version_identity, "_git_head", lambda root: "a" * 40)
    monkeypatch.setattr(version_identity, "_generated_commit_id", lambda version: "b" * 10)

    with pytest.raises(SourceVersionIdentityError, match="does not match checkout HEAD"):
        verify_source_checkout_version("0.4.3.dev1+gbbbbbbbbbb")


def test_editable_version_rejects_missing_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(version_identity, "_editable_source_root", lambda: ROOT)
    monkeypatch.setattr(version_identity, "_git_head", lambda root: "a" * 40)
    monkeypatch.setattr(version_identity, "_generated_commit_id", lambda version: None)

    with pytest.raises(SourceVersionIdentityError, match="has no source commit"):
        verify_source_checkout_version("0.4.3")


@pytest.mark.parametrize(
    "version",
    (
        "0.4.3+prefixgabcdef0",
        "0.4.3+gabcdef0suffix",
    ),
)
def test_generated_commit_id_requires_a_complete_version_fragment(version: str) -> None:
    assert version_identity._generated_commit_id(version) is None


def test_uv_cache_key_tracks_version_commit_and_tags() -> None:
    configuration = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert configuration["tool"]["uv"]["reinstall-package"] == ["vexcalibur"]
    assert configuration["tool"]["uv"]["cache-keys"] == [
        {"file": "pyproject.toml"},
        {"git": {"commit": True, "tags": True}},
    ]
