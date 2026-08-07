from __future__ import annotations

import tarfile
from io import BytesIO
from pathlib import Path

import pytest
import scripts.archive_limits as archive_limits
from scripts.archive_limits import (
    ArchivePreflightError,
    preflight_tar_gzip_stream,
)

from tests.archive_fixtures import (
    pax_record,
    write_extension_chain_tar_gzip,
    write_extension_tar_gzip,
)


def test_tar_preflight_accepts_bounded_setuptools_pax_mtime(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "setuptools.tar.gz"
    payload = b"bounded"
    member = tarfile.TarInfo("payload.txt")
    member.size = len(payload)
    member.pax_headers = {"mtime": "1700000000.123456"}
    with tarfile.open(archive_path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        archive.addfile(member, BytesIO(payload))

    preflight_tar_gzip_stream(
        archive_path,
        artifact="test tar",
        maximum_members=10,
        maximum_file_bytes=1024,
    )


def test_tar_preflight_rejects_oversized_pax_metadata_before_tarfile_parses_it(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "pax.tar.gz"
    payload = b"bounded"
    member = tarfile.TarInfo("payload.txt")
    member.size = len(payload)
    member.pax_headers = {"comment": "x" * (2 * 1024 * 1024)}
    with tarfile.open(archive_path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        archive.addfile(member, BytesIO(payload))

    with pytest.raises(ArchivePreflightError, match="PAX metadata exceeds"):
        preflight_tar_gzip_stream(
            archive_path,
            artifact="test tar",
            maximum_members=10,
            maximum_file_bytes=1024,
        )


def test_tar_preflight_rejects_pax_keys_that_override_member_identity(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "pax-path.tar.gz"
    payload = b"bounded"
    member = tarfile.TarInfo("payload.txt")
    member.size = len(payload)
    member.pax_headers = {"path": "different.txt"}
    with tarfile.open(archive_path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        archive.addfile(member, BytesIO(payload))

    with pytest.raises(ArchivePreflightError, match="unsupported PAX metadata key"):
        preflight_tar_gzip_stream(
            archive_path,
            artifact="test tar",
            maximum_members=10,
            maximum_file_bytes=1024,
        )


def test_tar_preflight_accepts_bounded_solaris_pax_mtime(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "solaris-pax.tar.gz"
    write_extension_tar_gzip(
        archive_path,
        extension_type=b"X",
        extension_payload=pax_record("mtime", "1700000000.123456"),
    )

    preflight_tar_gzip_stream(
        archive_path,
        artifact="test tar",
        maximum_members=10,
        maximum_file_bytes=1024,
    )


def test_tar_preflight_rejects_oversized_solaris_pax_metadata(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "oversized-solaris-pax.tar.gz"
    write_extension_tar_gzip(
        archive_path,
        extension_type=b"X",
        extension_payload=pax_record("mtime", "1" * (2 * 1024 * 1024)),
    )

    with pytest.raises(ArchivePreflightError, match="PAX metadata exceeds"):
        preflight_tar_gzip_stream(
            archive_path,
            artifact="test tar",
            maximum_members=10,
            maximum_file_bytes=1024,
        )


@pytest.mark.parametrize("key", ("path", "size"))
def test_tar_preflight_rejects_solaris_pax_member_rewrites(
    tmp_path: Path,
    key: str,
) -> None:
    archive_path = tmp_path / f"solaris-pax-{key}.tar.gz"
    write_extension_tar_gzip(
        archive_path,
        extension_type=b"X",
        extension_payload=pax_record(key, "different"),
    )

    with pytest.raises(ArchivePreflightError, match="unsupported PAX metadata key"):
        preflight_tar_gzip_stream(
            archive_path,
            artifact="test tar",
            maximum_members=10,
            maximum_file_bytes=1024,
        )


def test_tar_preflight_rejects_too_many_solaris_pax_records(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "many-solaris-pax-records.tar.gz"
    write_extension_tar_gzip(
        archive_path,
        extension_type=b"X",
        extension_payload=pax_record("mtime", "1") * 10_001,
    )

    with pytest.raises(ArchivePreflightError, match="too many PAX metadata records"):
        preflight_tar_gzip_stream(
            archive_path,
            artifact="test tar",
            maximum_members=10,
            maximum_file_bytes=1024,
        )


def test_tar_preflight_accepts_exact_pax_byte_and_record_limits(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "exact-pax-limits.tar.gz"
    short_records = pax_record("mtime", "0") * 9_999
    remaining_bytes = archive_limits._TAR_MAX_PAX_BYTES - len(short_records)
    value = "0" * remaining_bytes
    while True:
        final_record = pax_record("mtime", value)
        difference = remaining_bytes - len(final_record)
        if difference == 0:
            break
        value = value[: len(value) + difference]
    payload = short_records + final_record
    write_extension_tar_gzip(
        archive_path,
        extension_type=b"x",
        extension_payload=payload,
    )

    assert len(payload) == archive_limits._TAR_MAX_PAX_BYTES
    preflight_tar_gzip_stream(
        archive_path,
        artifact="test tar",
        maximum_members=10,
        maximum_file_bytes=1024,
    )


def test_tar_preflight_counts_pax_records_across_chained_headers(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "many-chained-pax-records.tar.gz"
    records = pax_record("mtime", "1") * 5_001
    write_extension_chain_tar_gzip(
        archive_path,
        extensions=((b"x", records), (b"g", records)),
    )

    with pytest.raises(ArchivePreflightError, match="too many PAX metadata records"):
        preflight_tar_gzip_stream(
            archive_path,
            artifact="test tar",
            maximum_members=10,
            maximum_file_bytes=1024,
        )


def test_tar_preflight_accepts_the_consecutive_pax_header_limit(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "bounded-pax-header-chain.tar.gz"
    record = pax_record("mtime", "1")
    write_extension_chain_tar_gzip(
        archive_path,
        extensions=tuple(
            (b"x", record) for _ in range(archive_limits._TAR_MAX_CONSECUTIVE_PAX_HEADERS)
        ),
    )

    preflight_tar_gzip_stream(
        archive_path,
        artifact="test tar",
        maximum_members=10_000,
        maximum_file_bytes=1024,
    )


def test_tar_preflight_rejects_deep_pax_header_chain_at_production_limits(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "deep-pax-header-chain.tar.gz"
    record = pax_record("mtime", "1")
    write_extension_chain_tar_gzip(
        archive_path,
        extensions=tuple(
            (b"x", record) for _ in range(archive_limits._TAR_MAX_CONSECUTIVE_PAX_HEADERS + 1)
        ),
    )

    with pytest.raises(ArchivePreflightError, match="too many consecutive PAX metadata headers"):
        preflight_tar_gzip_stream(
            archive_path,
            artifact="test tar",
            maximum_members=10_000,
            maximum_file_bytes=1024,
        )


@pytest.mark.parametrize("extension_type", (b"K", b"L", b"S"))
def test_tar_preflight_rejects_gnu_extension_headers(
    tmp_path: Path,
    extension_type: bytes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "gnu-extension.tar.gz"
    write_extension_tar_gzip(
        archive_path,
        extension_type=extension_type,
        extension_payload=b"x" * (2 * 1024 * 1024),
    )

    assert archive_path.stat().st_size < 32 * 1024 * 1024
    requested_bytes: list[int] = []
    original_read = archive_limits.gzip.GzipFile.read

    def record_read(stream: archive_limits.gzip.GzipFile, size: int = -1) -> bytes:
        requested_bytes.append(size)
        return original_read(stream, size)

    monkeypatch.setattr(archive_limits.gzip.GzipFile, "read", record_read)

    with pytest.raises(ArchivePreflightError, match="unsupported tar extension header"):
        preflight_tar_gzip_stream(
            archive_path,
            artifact="test tar",
            maximum_members=10,
            maximum_file_bytes=1024,
        )
    assert requested_bytes == [tarfile.BLOCKSIZE]


def test_tar_preflight_bounds_declared_member_bytes_before_reading_payload(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "oversized.tar.gz"
    payload = b"x" * 1025
    member = tarfile.TarInfo("payload.txt")
    member.size = len(payload)
    with tarfile.open(archive_path, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
        archive.addfile(member, BytesIO(payload))

    with pytest.raises(ArchivePreflightError, match="uncompressed byte limit"):
        preflight_tar_gzip_stream(
            archive_path,
            artifact="test tar",
            maximum_members=10,
            maximum_file_bytes=1024,
        )
