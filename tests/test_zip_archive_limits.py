from __future__ import annotations

import struct
import zipfile
from pathlib import Path

import pytest
import scripts.archive_limits as archive_limits

from tests.archive_fixtures import (
    ZipCentralDirectoryUint32Field,
    add_zip64_end_records,
    read_zip_record_field,
    replace_zip_record_signature,
    update_zip_record,
    write_central_directory_disk_zip,
    write_empty_member_zip,
    write_empty_member_zip_with_extra,
    zip64_extensible_data_block,
    zip_record_offset,
)

ArchivePreflightError = archive_limits.ArchivePreflightError
preflight_zip_archive = archive_limits.preflight_zip_archive


def test_zip_preflight_counts_central_directory_members_independently(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "forged-count.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("first", b"")
        archive.writestr("second", b"")

    update_zip_record(
        archive_path,
        record="classic",
        disk_members=1,
        total_members=1,
    )

    with pytest.raises(ArchivePreflightError, match="too many archive members"):
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=1,
            maximum_directory_bytes=1024,
        )


def test_zip_preflight_rejects_inconsistent_classic_member_count(tmp_path: Path) -> None:
    archive_path = tmp_path / "inconsistent-classic-member-count.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("first", b"")
        archive.writestr("second", b"")
    update_zip_record(
        archive_path,
        record="classic",
        disk_members=1,
        total_members=1,
    )

    with pytest.raises(
        ArchivePreflightError,
        match="inconsistent ZIP central directory metadata",
    ):
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


def test_zip_preflight_rejects_inconsistent_zip64_member_count(tmp_path: Path) -> None:
    archive_path = tmp_path / "inconsistent-zip64-member-count.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("first", b"")
        archive.writestr("second", b"")
    add_zip64_end_records(archive_path, disk_members=1, total_members=1)
    update_zip_record(
        archive_path,
        record="classic",
        disk_members=0xFFFF,
        total_members=0xFFFF,
    )

    with pytest.raises(
        ArchivePreflightError,
        match="inconsistent ZIP central directory metadata",
    ):
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


def test_zip_preflight_accepts_consistent_zip64_metadata(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "zip64.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("member", b"payload")
    add_zip64_end_records(
        archive_path,
        extensible_data=zip64_extensible_data_block(0xCAFE, b"bounded extension"),
    )
    update_zip_record(
        archive_path,
        record="classic",
        disk_members=0xFFFF,
        total_members=0xFFFF,
    )

    snapshot = preflight_zip_archive(
        archive_path,
        artifact="test ZIP",
        maximum_members=10,
        maximum_directory_bytes=1024,
    )

    with snapshot.open() as stream, zipfile.ZipFile(stream) as archive:
        assert archive.read("member") == b"payload"


@pytest.mark.parametrize("zip64", (False, True))
def test_zip_preflight_accepts_archive_with_prepended_data(
    tmp_path: Path,
    zip64: bool,
) -> None:
    archive_path = tmp_path / "prefixed.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("member", b"payload")
    if zip64:
        add_zip64_end_records(archive_path)
    archive_path.write_bytes(b"#!/bin/sh\n" + archive_path.read_bytes())

    snapshot = preflight_zip_archive(
        archive_path,
        artifact="test ZIP",
        maximum_members=10,
        maximum_directory_bytes=1024,
    )

    with snapshot.open() as stream, zipfile.ZipFile(stream) as archive:
        assert archive.read("member") == b"payload"


def test_zip_preflight_accepts_classic_archive_at_exact_member_field_limit(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "classic-member-limit.zip"
    write_empty_member_zip(archive_path, members=65_535)
    assert b"PK\x06\x06" not in archive_path.read_bytes()

    preflight_zip_archive(
        archive_path,
        artifact="test ZIP",
        maximum_members=65_535,
        maximum_directory_bytes=32 * 1024 * 1024,
    )


def test_zip_preflight_rejects_zip64_member_flood_before_scanning_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "zip64-member-flood.zip"
    write_empty_member_zip(archive_path, members=65_536)
    assert archive_path.stat().st_size < 32 * 1024 * 1024

    def fail_central_directory_scan(*args: object, **kwargs: object) -> None:
        pytest.fail("oversized ZIP64 count reached the central directory scanner")

    monkeypatch.setattr(
        archive_limits,
        "_preflight_zip_central_directory",
        fail_central_directory_scan,
    )

    with pytest.raises(ArchivePreflightError, match="too many archive members"):
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=65_535,
            maximum_directory_bytes=32 * 1024 * 1024,
        )


def test_zip_preflight_rejects_inconsistent_classic_maximum_count(tmp_path: Path) -> None:
    archive_path = tmp_path / "inconsistent-classic-count.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("member", b"")

    update_zip_record(
        archive_path,
        record="classic",
        disk_members=0xFFFF,
        total_members=0xFFFF,
    )

    with pytest.raises(ArchivePreflightError, match="truncated ZIP central directory"):
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=65_535,
            maximum_directory_bytes=1024,
        )


@pytest.mark.parametrize(
    "extensible_data",
    (
        b"\x01",
        struct.pack("<HL", 0xCAFE, 4) + b"abc",
        zip64_extensible_data_block(0xCAFE, b"data") + b"\x00",
    ),
)
def test_zip_preflight_rejects_invalid_zip64_extensible_data(
    tmp_path: Path,
    extensible_data: bytes,
) -> None:
    archive_path = tmp_path / "invalid-zip64-extension.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("member", b"")
    add_zip64_end_records(archive_path, extensible_data=extensible_data)

    with pytest.raises(ArchivePreflightError, match="invalid ZIP64 extensible data"):
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


def test_zip_preflight_bounds_zip64_extensible_data_blocks(tmp_path: Path) -> None:
    archive_path = tmp_path / "too-many-zip64-extensions.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("member", b"")
    add_zip64_end_records(
        archive_path,
        extensible_data=zip64_extensible_data_block(0xCAFE, b"") * 10_001,
    )

    with pytest.raises(ArchivePreflightError, match="too many ZIP64 extensible data blocks"):
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


def test_zip_preflight_accepts_exact_zip64_extensible_data_block_limit(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "zip64-extension-limit.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("member", b"")
    add_zip64_end_records(
        archive_path,
        extensible_data=zip64_extensible_data_block(0xCAFE, b"") * 10_000,
    )

    preflight_zip_archive(
        archive_path,
        artifact="test ZIP",
        maximum_members=10,
        maximum_directory_bytes=1024,
    )


def test_zip_preflight_enforces_zip64_limits_before_extensible_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "over-limit-zip64.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("member", b"")
    add_zip64_end_records(
        archive_path,
        disk_members=10_001,
        total_members=10_001,
        extensible_data=zip64_extensible_data_block(0xCAFE, b"data"),
    )
    update_zip_record(
        archive_path,
        record="classic",
        disk_members=0xFFFF,
        total_members=0xFFFF,
    )

    def fail_extensible_data_scan(*args: object, **kwargs: object) -> None:
        pytest.fail("over-limit ZIP64 record reached extensible-data parsing")

    monkeypatch.setattr(
        archive_limits,
        "_preflight_zip64_extensible_data",
        fail_extensible_data_scan,
    )

    with pytest.raises(ArchivePreflightError, match="too many archive members"):
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=10_000,
            maximum_directory_bytes=1024,
        )


def test_zip_preflight_rejects_truncated_zip64_record(tmp_path: Path) -> None:
    archive_path = tmp_path / "truncated-zip64-record.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("member", b"")
    add_zip64_end_records(archive_path)

    locator_offset = zip_record_offset(archive_path, record="locator")
    update_zip_record(
        archive_path,
        record="locator",
        record_offset=locator_offset - 20,
    )

    with pytest.raises(ArchivePreflightError, match="truncated ZIP64 directory record"):
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


def test_zip_preflight_rejects_invalid_zip64_record_signature(tmp_path: Path) -> None:
    archive_path = tmp_path / "invalid-zip64-record.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("member", b"")
    add_zip64_end_records(archive_path)

    replace_zip_record_signature(archive_path, record="zip64", signature=b"NOPE")

    with pytest.raises(ArchivePreflightError, match="invalid ZIP64 directory record"):
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


def test_zip_preflight_rejects_invalid_zip64_record_boundary(tmp_path: Path) -> None:
    archive_path = tmp_path / "invalid-zip64-boundary.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("member", b"")
    add_zip64_end_records(archive_path)

    record_size = read_zip_record_field(archive_path, record="zip64", field="record_size")
    update_zip_record(archive_path, record="zip64", record_size=record_size + 1)

    with pytest.raises(ArchivePreflightError, match="invalid ZIP64 directory record boundary"):
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


def test_zip_preflight_rejects_invalid_zip64_version(tmp_path: Path) -> None:
    archive_path = tmp_path / "invalid-zip64-version.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("member", b"")
    add_zip64_end_records(archive_path)

    update_zip_record(archive_path, record="zip64", version_needed=44)

    with pytest.raises(ArchivePreflightError, match="invalid ZIP64 version"):
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (("record_disk", 1), ("total_disks", 2)),
)
def test_zip_preflight_rejects_multidisk_zip64_locator(
    tmp_path: Path,
    field: str,
    value: int,
) -> None:
    archive_path = tmp_path / "multidisk-zip64.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("member", b"")
    add_zip64_end_records(archive_path)

    update_zip_record(archive_path, record="locator", **{field: value})

    with pytest.raises(ArchivePreflightError, match="unsupported multidisk ZIP64"):
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


def test_zip_preflight_rejects_zip64_member_count_mismatch(tmp_path: Path) -> None:
    archive_path = tmp_path / "zip64-member-count-mismatch.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("member", b"")
    add_zip64_end_records(archive_path, disk_members=0, total_members=1)
    update_zip_record(
        archive_path,
        record="classic",
        disk_members=0xFFFF,
        total_members=0xFFFF,
    )

    with pytest.raises(ArchivePreflightError, match="unsupported multidisk ZIP"):
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


@pytest.mark.parametrize(
    "field",
    (
        "disk_number",
        "directory_disk",
        "disk_members",
        "total_members",
        "directory_size",
        "directory_offset",
    ),
)
def test_zip_preflight_rejects_contradictory_zip64_metadata(
    tmp_path: Path,
    field: str,
) -> None:
    archive_path = tmp_path / "contradictory-zip64.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("member", b"")
    add_zip64_end_records(archive_path)

    original = read_zip_record_field(archive_path, record="zip64", field=field)
    update_zip_record(archive_path, record="zip64", **{field: original + 1})

    with pytest.raises(ArchivePreflightError, match="contradictory ZIP and ZIP64"):
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


@pytest.mark.parametrize(
    "field",
    ("disk_number", "directory_disk"),
)
def test_zip_preflight_rejects_zip64_multidisk_directory_fields(
    tmp_path: Path,
    field: str,
) -> None:
    archive_path = tmp_path / "multidisk-zip64-directory.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("member", b"")
    add_zip64_end_records(archive_path)

    update_zip_record(archive_path, record="zip64", **{field: 1})
    update_zip_record(archive_path, record="classic", **{field: 0xFFFF})

    with pytest.raises(ArchivePreflightError, match="unsupported multidisk ZIP"):
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


def test_zip_preflight_rejects_zip64_directory_overlap(tmp_path: Path) -> None:
    archive_path = tmp_path / "overlapping-zip64.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("member", b"")
    directory_size = read_zip_record_field(
        archive_path,
        record="classic",
        field="directory_size",
    )
    add_zip64_end_records(archive_path, directory_size=directory_size + 1)

    update_zip_record(archive_path, record="classic", directory_size=0xFFFFFFFF)

    with pytest.raises(ArchivePreflightError, match="invalid ZIP directory boundary"):
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


def test_zip_preflight_bounds_zip64_central_directory_size(tmp_path: Path) -> None:
    archive_path = tmp_path / "oversized-zip64-directory.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("member", b"")
    add_zip64_end_records(archive_path, directory_size=1025)

    update_zip_record(archive_path, record="classic", directory_size=0xFFFFFFFF)

    with pytest.raises(ArchivePreflightError, match="central directory exceeds"):
        preflight_zip_archive(
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
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


def test_zip_preflight_rejects_member_on_another_disk(tmp_path: Path) -> None:
    archive_path = tmp_path / "multidisk-member.zip"
    write_central_directory_disk_zip(archive_path, disk_number=1)

    with pytest.raises(ArchivePreflightError, match="unsupported multidisk ZIP"):
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


@pytest.mark.parametrize(
    "zip64_fields",
    (
        (),
        ("uncompressed_size",),
        ("compressed_size",),
        ("local_header_offset",),
        ("uncompressed_size", "compressed_size"),
        ("uncompressed_size", "local_header_offset"),
        ("compressed_size", "local_header_offset"),
        ("uncompressed_size", "compressed_size", "local_header_offset"),
    ),
)
@pytest.mark.parametrize("disk_number", (0, 1))
def test_zip_preflight_resolves_zip64_member_disk_number(
    tmp_path: Path,
    zip64_fields: tuple[ZipCentralDirectoryUint32Field, ...],
    disk_number: int,
) -> None:
    archive_path = tmp_path / "zip64-member-disk.zip"
    zip64_data = (b"\0" * (8 * len(zip64_fields))) + struct.pack("<L", disk_number)
    extra = struct.pack("<2H", 0x0001, len(zip64_data)) + zip64_data
    write_central_directory_disk_zip(
        archive_path,
        disk_number=0xFFFF,
        extra=extra,
        zip64_fields=zip64_fields,
    )

    if disk_number:
        with pytest.raises(ArchivePreflightError, match="unsupported multidisk ZIP"):
            preflight_zip_archive(
                archive_path,
                artifact="test ZIP",
                maximum_members=10,
                maximum_directory_bytes=1024,
            )
    else:
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


@pytest.mark.parametrize(
    "zip64_fields",
    (
        ("uncompressed_size",),
        ("compressed_size",),
        ("local_header_offset",),
        ("uncompressed_size", "compressed_size"),
        ("uncompressed_size", "local_header_offset"),
        ("compressed_size", "local_header_offset"),
        ("uncompressed_size", "compressed_size", "local_header_offset"),
    ),
)
def test_zip_preflight_resolves_zip64_member_fields_without_a_disk_sentinel(
    tmp_path: Path,
    zip64_fields: tuple[ZipCentralDirectoryUint32Field, ...],
) -> None:
    archive_path = tmp_path / "zip64-member-fields.zip"
    zip64_data = b"\0" * (8 * len(zip64_fields))
    extra = struct.pack("<2H", 0x0001, len(zip64_data)) + zip64_data
    write_central_directory_disk_zip(
        archive_path,
        disk_number=0,
        extra=extra,
        zip64_fields=zip64_fields,
    )

    preflight_zip_archive(
        archive_path,
        artifact="test ZIP",
        maximum_members=10,
        maximum_directory_bytes=1024,
    )


@pytest.mark.parametrize(
    "zip64_fields",
    (
        ("uncompressed_size",),
        ("compressed_size",),
        ("local_header_offset",),
        ("uncompressed_size", "compressed_size"),
        ("uncompressed_size", "local_header_offset"),
        ("compressed_size", "local_header_offset"),
        ("uncompressed_size", "compressed_size", "local_header_offset"),
    ),
)
def test_zip_preflight_rejects_truncated_required_zip64_member_fields(
    tmp_path: Path,
    zip64_fields: tuple[ZipCentralDirectoryUint32Field, ...],
) -> None:
    archive_path = tmp_path / "truncated-zip64-member-fields.zip"
    zip64_data = b"\0" * ((8 * len(zip64_fields)) - 1)
    extra = struct.pack("<2H", 0x0001, len(zip64_data)) + zip64_data
    write_central_directory_disk_zip(
        archive_path,
        disk_number=0,
        extra=extra,
        zip64_fields=zip64_fields,
    )

    with pytest.raises(ArchivePreflightError, match="invalid ZIP64 central directory metadata"):
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


@pytest.mark.parametrize(
    "field",
    ("uncompressed_size", "compressed_size", "local_header_offset"),
)
def test_zip_preflight_rejects_missing_required_zip64_member_fields(
    tmp_path: Path,
    field: ZipCentralDirectoryUint32Field,
) -> None:
    archive_path = tmp_path / "missing-zip64-member-field.zip"
    write_central_directory_disk_zip(
        archive_path,
        disk_number=0,
        zip64_fields=(field,),
    )

    with pytest.raises(ArchivePreflightError, match="invalid ZIP64 central directory metadata"):
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


def test_zip_preflight_rejects_a_zip64_member_with_an_old_extraction_version(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "old-version-zip64-member.zip"
    zip64_data = struct.pack("<Q", 0)
    extra = struct.pack("<2H", 0x0001, len(zip64_data)) + zip64_data
    write_central_directory_disk_zip(
        archive_path,
        disk_number=0,
        extra=extra,
        zip64_fields=("local_header_offset",),
        version_needed=20,
    )

    with pytest.raises(ArchivePreflightError, match="invalid ZIP64 member version"):
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


@pytest.mark.parametrize(
    "zip64_fields",
    ((), ("local_header_offset",)),
)
def test_zip_preflight_rejects_surplus_zip64_member_values(
    tmp_path: Path,
    zip64_fields: tuple[ZipCentralDirectoryUint32Field, ...],
) -> None:
    archive_path = tmp_path / "surplus-zip64-member-data.zip"
    required_size = 8 * len(zip64_fields)
    zip64_data = b"\0" * (required_size + 8)
    extra = struct.pack("<2H", 0x0001, len(zip64_data)) + zip64_data
    write_central_directory_disk_zip(
        archive_path,
        disk_number=0,
        extra=extra,
        zip64_fields=zip64_fields,
        version_needed=45,
    )

    with pytest.raises(
        ArchivePreflightError,
        match=r"(unexpected|invalid) ZIP64 central directory metadata",
    ):
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1024,
        )


@pytest.mark.parametrize(
    "extra",
    (
        b"",
        struct.pack("<2H", 0x0001, 0),
        b"\x01",
        struct.pack("<2H", 0x0001, 8) + b"\0" * 4,
        (struct.pack("<2HI", 0x0001, 4, 0) * 2),
    ),
)
def test_zip_preflight_rejects_invalid_zip64_member_disk_metadata(
    tmp_path: Path,
    extra: bytes,
) -> None:
    archive_path = tmp_path / "invalid-zip64-member-disk.zip"
    write_central_directory_disk_zip(
        archive_path,
        disk_number=0xFFFF,
        extra=extra,
    )

    with pytest.raises(ArchivePreflightError, match=r"ZIP.*central directory metadata"):
        preflight_zip_archive(
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

    eocd_offset = zip_record_offset(archive_path, record="classic")
    update_zip_record(
        archive_path,
        record="classic",
        directory_size=10,
        directory_offset=eocd_offset - 10,
    )

    with pytest.raises(ArchivePreflightError, match="truncated ZIP central directory"):
        preflight_zip_archive(
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
        preflight_zip_archive(
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
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=1,
        )


def test_zip_preflight_accepts_exact_member_and_directory_limits(tmp_path: Path) -> None:
    archive_path = tmp_path / "exact-directory-limits.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("first", b"")
        archive.writestr("second", b"")
    directory_size = read_zip_record_field(
        archive_path,
        record="classic",
        field="directory_size",
    )

    preflight_zip_archive(
        archive_path,
        artifact="test ZIP",
        maximum_members=2,
        maximum_directory_bytes=directory_size,
    )

    with pytest.raises(ArchivePreflightError, match="central directory exceeds"):
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=2,
            maximum_directory_bytes=directory_size - 1,
        )


@pytest.mark.parametrize(("fields_per_member", "accepted"), ((10, True), (11, False)))
def test_zip_preflight_bounds_central_directory_extra_fields(
    tmp_path: Path,
    fields_per_member: int,
    accepted: bool,
) -> None:
    archive_path = tmp_path / "central-extra-fields.zip"
    extra = struct.pack("<2H", 0xCAFE, 0) * fields_per_member
    write_empty_member_zip_with_extra(
        archive_path,
        members=10,
        extra=extra,
    )

    if accepted:
        preflight_zip_archive(
            archive_path,
            artifact="test ZIP",
            maximum_members=10,
            maximum_directory_bytes=4096,
        )
    else:
        with pytest.raises(ArchivePreflightError, match="too many ZIP central directory extra"):
            preflight_zip_archive(
                archive_path,
                artifact="test ZIP",
                maximum_members=10,
                maximum_directory_bytes=4096,
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
        preflight_zip_archive(
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

    snapshot = preflight_zip_archive(
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

    snapshot = preflight_zip_archive(
        archive_path,
        artifact="test ZIP",
        maximum_members=10,
        maximum_directory_bytes=1024,
    )
    replacement.replace(archive_path)

    with snapshot.open() as stream, zipfile.ZipFile(stream) as archive:
        assert archive.read("selected") == b"original"
