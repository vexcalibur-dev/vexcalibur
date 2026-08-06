"""Helpers for constructing adversarial tar fixtures."""

from __future__ import annotations

import gzip
import tarfile
from pathlib import Path


def pax_record(key: str, value: str) -> bytes:
    """Encode one PAX record with its self-inclusive decimal length."""
    body = f"{key}={value}\n".encode()
    size = len(body) + 2
    while True:
        encoded = f"{size} ".encode() + body
        if len(encoded) == size:
            return encoded
        size = len(encoded)


def write_extension_tar_gzip(
    path: Path,
    *,
    extension_type: bytes,
    extension_payload: bytes,
) -> None:
    """Write a gzip tar containing one extension header and one regular member."""
    extension = tarfile.TarInfo("././@PaxHeader")
    extension.type = extension_type
    extension.size = len(extension_payload)
    member = tarfile.TarInfo("vexcalibur-0.1.0/PKG-INFO")
    metadata = b"Name: vexcalibur\nVersion: 0.1.0\n"
    member.size = len(metadata)

    with gzip.open(path, "wb") as archive:
        for header, payload in (
            (extension, extension_payload),
            (member, metadata),
        ):
            archive.write(header.tobuf(format=tarfile.USTAR_FORMAT))
            archive.write(payload)
            archive.write(b"\0" * (-len(payload) % tarfile.BLOCKSIZE))
        archive.write(b"\0" * (2 * tarfile.BLOCKSIZE))
