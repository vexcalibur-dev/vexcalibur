from __future__ import annotations

import gzip
import subprocess
import sys
import tarfile
from io import BytesIO
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "normalize-sdist.py"
EPOCH = 1_784_135_156


def _write_archive(path: Path, *, metadata_epoch: int, reverse: bool) -> None:
    members = [
        ("vexcalibur-0.4.0", None, 0o775),
        (
            "vexcalibur-0.4.0/PKG-INFO",
            b"Metadata-Version: 2.4\nName: vexcalibur\nVersion: 0.4.0\n",
            0o664,
        ),
        (
            "vexcalibur-0.4.0/src/vexcalibur/_version.py",
            b"__version__ = version = '0.4.0'\n__commit_id__ = commit_id = 'gaaaaaaaaaa'\n",
            0o775,
        ),
    ]
    if reverse:
        members.reverse()
    with (
        path.open("xb") as raw,
        gzip.GzipFile(
            filename=f"source-{metadata_epoch}.tar",
            mode="wb",
            fileobj=raw,
            mtime=metadata_epoch,
        ) as compressed,
        tarfile.open(
            fileobj=compressed,
            mode="w",
            format=tarfile.PAX_FORMAT,
        ) as archive,
    ):
        for name, contents, mode in members:
            member = tarfile.TarInfo(name)
            member.mtime = metadata_epoch
            member.uid = metadata_epoch % 1000
            member.gid = metadata_epoch % 500
            member.uname = f"user-{metadata_epoch}"
            member.gname = f"group-{metadata_epoch}"
            member.mode = mode
            if contents is None:
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            else:
                member.size = len(contents)
                archive.addfile(member, BytesIO(contents))


def _normalize(input_path: Path, output_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed interpreter, reviewed script, test-owned paths
        [
            sys.executable,
            str(SCRIPT),
            str(input_path),
            "--output",
            str(output_path),
            "--source-date-epoch",
            str(EPOCH),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_normalization_removes_archive_order_and_metadata_variance(tmp_path: Path) -> None:
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    _write_archive(first, metadata_epoch=EPOCH + 10, reverse=False)
    _write_archive(second, metadata_epoch=EPOCH + 20, reverse=True)
    assert first.read_bytes() != second.read_bytes()

    first_normalized = tmp_path / "first-normalized.tar.gz"
    second_normalized = tmp_path / "second-normalized.tar.gz"
    assert _normalize(first, first_normalized).returncode == 0
    assert _normalize(second, second_normalized).returncode == 0
    assert first_normalized.read_bytes() == second_normalized.read_bytes()

    with tarfile.open(first_normalized, "r:gz") as archive:
        members = archive.getmembers()
        assert [member.name for member in members] == sorted(member.name for member in members)
        assert {member.mtime for member in members} == {EPOCH}
        assert {member.uid for member in members} == {0}
        assert {member.gid for member in members} == {0}
        assert {member.uname for member in members} == {""}
        assert {member.gname for member in members} == {""}


def test_normalization_is_idempotent_and_never_clobbers(tmp_path: Path) -> None:
    source = tmp_path / "source.tar.gz"
    _write_archive(source, metadata_epoch=EPOCH + 10, reverse=False)
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    assert _normalize(source, first).returncode == 0
    assert _normalize(first, second).returncode == 0
    assert first.read_bytes() == second.read_bytes()

    existing = tmp_path / "existing.tar.gz"
    existing.write_bytes(b"do not replace")
    completed = _normalize(source, existing)
    assert completed.returncode == 1
    assert existing.read_bytes() == b"do not replace"


def test_normalization_rejects_links_without_leaving_output(tmp_path: Path) -> None:
    source = tmp_path / "link.tar.gz"
    with tarfile.open(source, "w:gz") as archive:
        link = tarfile.TarInfo("vexcalibur-0.4.0/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        archive.addfile(link)
    output = tmp_path / "normalized.tar.gz"

    completed = _normalize(source, output)

    assert completed.returncode == 1
    assert "link or special" in completed.stderr
    assert not output.exists()


@pytest.mark.parametrize(
    "member_name",
    ["C:/outside.txt", "c:relative.txt", "vexcalibur-0.4.0/control\nname"],
)
def test_normalization_rejects_drive_qualified_and_control_character_paths(
    tmp_path: Path,
    member_name: str,
) -> None:
    source = tmp_path / "unsafe.tar.gz"
    with tarfile.open(source, "w:gz") as archive:
        contents = b"unsafe"
        member = tarfile.TarInfo(member_name)
        member.size = len(contents)
        archive.addfile(member, BytesIO(contents))
    output = tmp_path / "normalized.tar.gz"

    completed = _normalize(source, output)

    assert completed.returncode == 1
    assert "unsafe member path" in completed.stderr
    assert not output.exists()
