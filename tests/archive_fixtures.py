"""Helpers for constructing adversarial tar fixtures."""

from __future__ import annotations

import gzip
import tarfile
from collections.abc import Sequence
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
    write_extension_chain_tar_gzip(
        path,
        extensions=((extension_type, extension_payload),),
    )


def write_extension_chain_tar_gzip(
    path: Path,
    *,
    extensions: Sequence[tuple[bytes, bytes]],
) -> None:
    """Write a gzip tar containing extension headers and one regular member."""
    member = tarfile.TarInfo("vexcalibur-0.1.0/PKG-INFO")
    metadata = b"Name: vexcalibur\nVersion: 0.1.0\n"
    member.size = len(metadata)

    with gzip.open(path, "wb") as archive:
        for extension_type, extension_payload in extensions:
            extension = tarfile.TarInfo("././@PaxHeader")
            extension.type = extension_type
            extension.size = len(extension_payload)
            archive.write(extension.tobuf(format=tarfile.USTAR_FORMAT))
            archive.write(extension_payload)
            archive.write(b"\0" * (-len(extension_payload) % tarfile.BLOCKSIZE))
        archive.write(member.tobuf(format=tarfile.USTAR_FORMAT))
        archive.write(metadata)
        archive.write(b"\0" * (-len(metadata) % tarfile.BLOCKSIZE))
        archive.write(b"\0" * (2 * tarfile.BLOCKSIZE))
