from __future__ import annotations

import subprocess
import sys
import tarfile
import zipfile
from io import BytesIO
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "verify-dist-metadata.py"


def write_wheel(dist_dir: Path, name: str = "vexcalibur", version: str = "0.1.0") -> Path:
    path = dist_dir / f"{name}-{version}-py3-none-any.whl"
    metadata = f"Name: {name}\nVersion: {version}\n"
    with zipfile.ZipFile(path, "w") as wheel:
        wheel.writestr(f"{name}-{version}.dist-info/METADATA", metadata)
    return path


def write_sdist(dist_dir: Path, name: str = "vexcalibur", version: str = "0.1.0") -> Path:
    path = dist_dir / f"{name}-{version}.tar.gz"
    metadata = f"Name: {name}\nVersion: {version}\n".encode()
    info = tarfile.TarInfo(f"{name}-{version}/PKG-INFO")
    info.size = len(metadata)
    with tarfile.open(path, "w:gz") as sdist:
        sdist.addfile(info, BytesIO(metadata))
    return path


def add_sdist_file(path: Path, member_name: str, contents: bytes) -> None:
    replacement = path.with_name(f"{path.name}.replacement")
    with tarfile.open(path, "r:gz") as source, tarfile.open(replacement, "w:gz") as target:
        for member in source.getmembers():
            stream = source.extractfile(member) if member.isfile() else None
            target.addfile(member, stream)
        info = tarfile.TarInfo(member_name)
        info.size = len(contents)
        target.addfile(info, BytesIO(contents))
    replacement.replace(path)


def run_verifier(
    dist_dir: Path,
    *,
    expected_name: str = "vexcalibur",
    expected_version: str = "0.1.0",
    github_output: Path | None = None,
    source_root: Path | None = None,
    required_sdist_files: tuple[str, ...] = (),
) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        str(SCRIPT),
        str(dist_dir),
        "--expected-name",
        expected_name,
        "--expected-version",
        expected_version,
    ]
    if github_output is not None:
        command.extend(["--github-output", str(github_output)])
    if source_root is not None:
        command.extend(["--source-root", str(source_root)])
    for required_file in required_sdist_files:
        command.extend(["--required-sdist-file", required_file])
    return subprocess.run(  # noqa: S603
        command,
        check=False,
        text=True,
        capture_output=True,
    )


def test_verifier_accepts_matching_wheel_and_sdist(tmp_path: Path) -> None:
    write_wheel(tmp_path)
    sdist = write_sdist(tmp_path)
    add_sdist_file(
        sdist,
        "vexcalibur-0.1.0/src/vexcalibur.egg-info/PKG-INFO",
        b"Name: vexcalibur\nVersion: 0.1.0\n",
    )

    result = run_verifier(tmp_path)

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""


def test_verifier_writes_github_output(tmp_path: Path) -> None:
    wheel = write_wheel(tmp_path)
    sdist = write_sdist(tmp_path)
    github_output = tmp_path / "github-output.txt"

    result = run_verifier(tmp_path, github_output=github_output)

    assert result.returncode == 0
    assert github_output.read_text(encoding="utf-8").splitlines() == [
        "version=0.1.0",
        f"wheel={wheel}",
        f"sdist={sdist}",
    ]


def test_verifier_rejects_missing_wheel(tmp_path: Path) -> None:
    write_sdist(tmp_path)

    result = run_verifier(tmp_path)

    assert result.returncode == 1
    assert "Expected exactly one wheel artifact, found 0." in result.stderr


def test_verifier_rejects_unexpected_artifact(tmp_path: Path) -> None:
    write_wheel(tmp_path)
    write_sdist(tmp_path)
    (tmp_path / "extra.txt").write_text("unexpected\n", encoding="utf-8")

    result = run_verifier(tmp_path)

    assert result.returncode == 1
    assert "Unexpected files in distribution directory:" in result.stderr
    assert "extra.txt" in result.stderr


def test_verifier_rejects_wheel_version_mismatch(tmp_path: Path) -> None:
    write_wheel(tmp_path, version="0.2.0")
    write_sdist(tmp_path)

    result = run_verifier(tmp_path)

    assert result.returncode == 1
    assert "Built wheel version '0.2.0' does not match expected version '0.1.0'." in result.stderr


def test_verifier_rejects_sdist_name_mismatch(tmp_path: Path) -> None:
    write_wheel(tmp_path)
    write_sdist(tmp_path, name="other")

    result = run_verifier(tmp_path)

    assert result.returncode == 1
    assert "Built sdist name 'other' does not match expected name 'vexcalibur'." in result.stderr


def test_verifier_requires_exact_reviewed_files_in_sdist(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_path = source_root / "docs" / "example.py"
    source_path.parent.mkdir(parents=True)
    source_path.write_bytes(b"print('reviewed')\n")
    write_wheel(tmp_path)
    sdist = write_sdist(tmp_path)
    add_sdist_file(
        sdist,
        "vexcalibur-0.1.0/docs/example.py",
        source_path.read_bytes(),
    )

    result = run_verifier(
        tmp_path,
        source_root=source_root,
        required_sdist_files=("docs/example.py",),
    )

    assert result.returncode == 0


def test_verifier_rejects_changed_required_sdist_file(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_path = source_root / "docs" / "example.py"
    source_path.parent.mkdir(parents=True)
    source_path.write_bytes(b"print('reviewed')\n")
    write_wheel(tmp_path)
    sdist = write_sdist(tmp_path)
    add_sdist_file(
        sdist,
        "vexcalibur-0.1.0/docs/example.py",
        b"print('different')\n",
    )

    result = run_verifier(
        tmp_path,
        source_root=source_root,
        required_sdist_files=("docs/example.py",),
    )

    assert result.returncode == 1
    assert "Required sdist file differs from source" in result.stderr


def test_verifier_rejects_required_file_missing_from_sdist(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_path = source_root / "docs" / "example.py"
    source_path.parent.mkdir(parents=True)
    source_path.write_bytes(b"print('reviewed')\n")
    write_wheel(tmp_path)
    write_sdist(tmp_path)

    result = run_verifier(
        tmp_path,
        source_root=source_root,
        required_sdist_files=("docs/example.py",),
    )

    assert result.returncode == 1
    assert "Required file is missing or invalid in the sdist" in result.stderr


def test_verifier_rejects_compressed_wheel_metadata_bomb(tmp_path: Path) -> None:
    wheel = tmp_path / "vexcalibur-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "vexcalibur-0.1.0.dist-info/METADATA",
            b"Name: vexcalibur\nVersion: 0.1.0\n" + (b"A" * (1024 * 1024)),
        )
    write_sdist(tmp_path)

    result = run_verifier(tmp_path)

    assert result.returncode == 1
    assert "Wheel metadata is not a bounded regular member" in result.stderr


def test_verifier_rejects_wheel_member_flood(tmp_path: Path) -> None:
    wheel = write_wheel(tmp_path)
    with zipfile.ZipFile(wheel, "a") as archive:
        for index in range(10_000):
            archive.writestr(f"flood/{index}", b"")
    write_sdist(tmp_path)

    result = run_verifier(tmp_path)

    assert result.returncode == 1
    assert "Wheel contains too many archive members" in result.stderr
