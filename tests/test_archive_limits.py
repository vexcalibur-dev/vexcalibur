from __future__ import annotations

import struct
import tarfile
import zipfile
from io import BytesIO
from pathlib import Path

import pytest
import scripts.archive_limits as archive_limits
from scripts.archive_limits import (
    ArchivePreflightError,
    preflight_tar_gzip_stream,
    preflight_zip_member_count,
)

from tests.archive_fixtures import pax_record, write_extension_tar_gzip


def test_zip_preflight_counts_central_directory_members_independently(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "forged-count.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("first", b"")
        archive.writestr("second", b"")

    contents = bytearray(archive_path.read_bytes())
    eocd_offset = contents.rfind(b"PK\x05\x06")
    struct.pack_into("<H", contents, eocd_offset + 8, 1)
    struct.pack_into("<H", contents, eocd_offset + 10, 1)
    archive_path.write_bytes(contents)

    with pytest.raises(ArchivePreflightError, match="too many archive members"):
        preflight_zip_member_count(
            archive_path,
            artifact="test ZIP",
            maximum_members=1,
            maximum_directory_bytes=1024,
        )


def test_zip_preflight_rejects_zip64_metadata_before_zipfile_parses_it(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "zip64-sentinel.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("member", b"")

    contents = bytearray(archive_path.read_bytes())
    eocd_offset = contents.rfind(b"PK\x05\x06")
    struct.pack_into("<H", contents, eocd_offset + 8, 0xFFFF)
    struct.pack_into("<H", contents, eocd_offset + 10, 0xFFFF)
    archive_path.write_bytes(contents)

    with pytest.raises(ArchivePreflightError, match="ZIP64"):
        preflight_zip_member_count(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


def test_zip_preflight_rejects_invalid_central_directory_signature(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "invalid-directory.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("member", b"")

    contents = bytearray(archive_path.read_bytes())
    central_offset = contents.find(b"PK\x01\x02")
    contents[central_offset : central_offset + 4] = b"NOPE"
    archive_path.write_bytes(contents)

    with pytest.raises(ArchivePreflightError, match="invalid ZIP central directory"):
        preflight_zip_member_count(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


def test_zip_preflight_rejects_a_truncated_central_directory(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "truncated-directory.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("member", b"")

    contents = bytearray(archive_path.read_bytes())
    eocd_offset = contents.rfind(b"PK\x05\x06")
    struct.pack_into("<L", contents, eocd_offset + 12, 10)
    struct.pack_into("<L", contents, eocd_offset + 16, eocd_offset - 10)
    archive_path.write_bytes(contents)

    with pytest.raises(ArchivePreflightError, match="truncated ZIP central directory"):
        preflight_zip_member_count(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


def test_zip_preflight_rejects_overlapping_central_directory_fields(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "overlapping-directory.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("member", b"")

    contents = bytearray(archive_path.read_bytes())
    central_offset = contents.find(b"PK\x01\x02")
    struct.pack_into("<H", contents, central_offset + 28, 0xFFFF)
    archive_path.write_bytes(contents)

    with pytest.raises(
        ArchivePreflightError,
        match="invalid ZIP central directory boundary",
    ):
        preflight_zip_member_count(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


def test_zip_preflight_rejects_oversized_central_directory_metadata(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "oversized-directory.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("member", b"")

    with pytest.raises(ArchivePreflightError, match="central directory exceeds"):
        preflight_zip_member_count(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1,
        )


def test_archive_snapshot_rejects_an_inode_swap_while_reading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "original.zip"
    replacement = tmp_path / "replacement.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("original", b"original")
    with zipfile.ZipFile(replacement, "w") as archive:
        archive.writestr("replacement", b"replacement")
    real_read = archive_limits.os.read
    replaced = False

    def replace_after_first_read(descriptor: int, size: int) -> bytes:
        nonlocal replaced
        value = real_read(descriptor, size)
        if value and not replaced:
            replaced = True
            replacement.replace(archive_path)
        return value

    monkeypatch.setattr(archive_limits.os, "read", replace_after_first_read)

    with pytest.raises(ArchivePreflightError, match="changed while it was read"):
        preflight_zip_member_count(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )

    assert replaced


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


def test_tar_preflight_rejects_sparse_extension_headers(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "sparse.tar.gz"
    write_extension_tar_gzip(
        archive_path,
        extension_type=b"S",
        extension_payload=b"",
    )

    with pytest.raises(ArchivePreflightError, match="unsupported tar extension header"):
        preflight_tar_gzip_stream(
            archive_path,
            artifact="test tar",
            maximum_members=10,
            maximum_file_bytes=1024,
        )


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
