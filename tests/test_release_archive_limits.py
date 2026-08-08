from __future__ import annotations

import struct
import zipfile
from pathlib import Path

import pytest
import scripts.release_evidence as release_evidence

from tests.archive_fixtures import (
    append_ambiguous_zip_eocd,
    pax_record,
    write_central_directory_disk_zip,
    write_empty_member_zip,
    write_empty_member_zip_with_extra,
    write_extension_chain_tar_gzip,
    write_extension_tar_gzip,
)


def test_release_evidence_rejects_solaris_pax_sdist_size_rewrite(
    tmp_path: Path,
) -> None:
    sdist = tmp_path / "vexcalibur-0.1.0.tar.gz"
    write_extension_tar_gzip(
        sdist,
        extension_type=b"X",
        extension_payload=pax_record("size", "1"),
    )

    with pytest.raises(release_evidence.EvidenceError, match="unsupported PAX metadata key"):
        release_evidence._read_sdist_distribution_metadata(sdist, "0.1.0")


def test_release_evidence_rejects_oversized_pax_before_tarfile_parses_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sdist = tmp_path / "vexcalibur-0.1.0.tar.gz"
    write_extension_tar_gzip(
        sdist,
        extension_type=b"x",
        extension_payload=pax_record("mtime", "1" * (2 * 1024 * 1024)),
    )

    def fail_tarfile_open(*args: object, **kwargs: object) -> None:
        pytest.fail("oversized PAX metadata reached tarfile")

    assert sdist.stat().st_size < release_evidence.MAX_EVIDENCE_FILE_BYTES
    monkeypatch.setattr(release_evidence.tarfile, "open", fail_tarfile_open)

    with pytest.raises(release_evidence.EvidenceError, match="PAX metadata exceeds"):
        release_evidence._read_sdist_distribution_metadata(sdist, "0.1.0")


def test_release_evidence_rejects_deep_pax_chain_before_tarfile_parses_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sdist = tmp_path / "vexcalibur-0.1.0.tar.gz"
    record = pax_record("mtime", "1")
    write_extension_chain_tar_gzip(
        sdist,
        extensions=tuple((b"x", record) for _ in range(9)),
    )

    def fail_tarfile_open(*args: object, **kwargs: object) -> None:
        pytest.fail("deep PAX chain reached tarfile")

    monkeypatch.setattr(release_evidence.tarfile, "open", fail_tarfile_open)

    with pytest.raises(release_evidence.EvidenceError, match="too many consecutive PAX"):
        release_evidence._read_sdist_distribution_metadata(sdist, "0.1.0")


def test_release_evidence_rejects_member_flood_before_zipfile_parses_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = tmp_path / "vexcalibur-0.4.0-py3-none-any.whl"
    write_empty_member_zip(wheel, members=release_evidence.MAX_ARCHIVE_MEMBERS + 1)

    def fail_zipfile_open(*args: object, **kwargs: object) -> None:
        pytest.fail("oversized member count reached zipfile")

    monkeypatch.setattr(release_evidence.zipfile, "ZipFile", fail_zipfile_open)

    with pytest.raises(release_evidence.EvidenceError, match="too many archive members"):
        release_evidence.validate_wheel_source(wheel, release_sha="a" * 40)


def test_release_evidence_rejects_ambiguous_eocd_before_zipfile_parses_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = tmp_path / "vexcalibur-0.4.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("member", b"")
    append_ambiguous_zip_eocd(wheel)

    def fail_zipfile_open(*args: object, **kwargs: object) -> None:
        pytest.fail("ambiguous ZIP directory reached zipfile")

    monkeypatch.setattr(release_evidence.zipfile, "ZipFile", fail_zipfile_open)

    with pytest.raises(release_evidence.EvidenceError, match="invalid ZIP directory record"):
        release_evidence.validate_wheel_source(wheel, release_sha="a" * 40)


def test_release_evidence_rejects_extra_field_flood_before_zipfile_parses_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = tmp_path / "vexcalibur-0.4.0-py3-none-any.whl"
    write_empty_member_zip_with_extra(
        wheel,
        members=release_evidence.MAX_ARCHIVE_MEMBERS,
        extra=struct.pack("<2H", 0xCAFE, 0) * 11,
    )

    def fail_zipfile_open(*args: object, **kwargs: object) -> None:
        pytest.fail("oversized ZIP extra-field count reached zipfile")

    monkeypatch.setattr(release_evidence.zipfile, "ZipFile", fail_zipfile_open)

    with pytest.raises(
        release_evidence.EvidenceError,
        match="too many ZIP central directory extra fields",
    ):
        release_evidence.validate_wheel_source(wheel, release_sha="a" * 40)


def test_release_evidence_rejects_oversized_directory_before_zipfile_parses_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = tmp_path / "vexcalibur-0.4.0-py3-none-any.whl"
    extra_data = b"x" * 65_531
    extra = struct.pack("<2H", 0xCAFE, len(extra_data)) + extra_data
    write_empty_member_zip_with_extra(wheel, members=129, extra=extra)

    assert wheel.stat().st_size < release_evidence.MAX_EVIDENCE_FILE_BYTES

    def fail_zipfile_open(*args: object, **kwargs: object) -> None:
        pytest.fail("oversized ZIP central directory reached zipfile")

    monkeypatch.setattr(release_evidence.zipfile, "ZipFile", fail_zipfile_open)

    with pytest.raises(release_evidence.EvidenceError, match="central directory exceeds"):
        release_evidence.validate_wheel_source(wheel, release_sha="a" * 40)


def test_release_evidence_rejects_missing_zip64_member_data_before_zipfile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = tmp_path / "vexcalibur-0.4.0-py3-none-any.whl"
    write_central_directory_disk_zip(
        wheel,
        disk_number=0,
        zip64_fields=("local_header_offset",),
    )

    def fail_zipfile_open(*args: object, **kwargs: object) -> None:
        pytest.fail("incomplete ZIP64 member metadata reached zipfile")

    monkeypatch.setattr(release_evidence.zipfile, "ZipFile", fail_zipfile_open)

    with pytest.raises(release_evidence.EvidenceError, match="invalid ZIP64 central directory"):
        release_evidence.validate_wheel_source(wheel, release_sha="a" * 40)
