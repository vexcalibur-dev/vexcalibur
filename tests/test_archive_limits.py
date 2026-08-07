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

from tests.archive_fixtures import (
    pax_record,
    write_extension_chain_tar_gzip,
    write_extension_tar_gzip,
)


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


def test_archive_snapshot_opens_the_descriptor_in_binary_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "binary.zip"
    payload = b"before\r\nafter\x1aend"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("payload.bin", payload)
    real_open = archive_limits.os.open
    native_binary_flag = hasattr(archive_limits.os, "O_BINARY")
    binary_flag = getattr(archive_limits.os, "O_BINARY", 1 << 29)
    observed_flags = 0

    def track_binary_flag(path: Path, flags: int) -> int:
        nonlocal observed_flags
        observed_flags = flags
        native_flags = flags if native_binary_flag else flags & ~binary_flag
        return real_open(path, native_flags)

    monkeypatch.setattr(archive_limits.os, "O_BINARY", binary_flag, raising=False)
    monkeypatch.setattr(archive_limits.os, "open", track_binary_flag)

    snapshot = preflight_zip_member_count(
        archive_path,
        artifact="test ZIP",
        maximum_members=10,
        maximum_directory_bytes=1024,
    )

    assert observed_flags & binary_flag
    with snapshot.open() as stream, zipfile.ZipFile(stream) as archive:
        assert archive.read("payload.bin") == payload


def test_archive_consumer_uses_the_preflighted_snapshot_after_path_replacement(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "artifact.zip"
    replacement = tmp_path / "replacement.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("selected", b"original")
    with zipfile.ZipFile(replacement, "w") as archive:
        archive.writestr("selected", b"replacement")

    snapshot = preflight_zip_member_count(
        archive_path,
        artifact="test ZIP",
        maximum_members=10,
        maximum_directory_bytes=1024,
    )
    replacement.replace(archive_path)

    with snapshot.open() as stream, zipfile.ZipFile(stream) as archive:
        assert archive.read("selected") == b"original"


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
