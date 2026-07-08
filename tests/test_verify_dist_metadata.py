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


def run_verifier(
    dist_dir: Path,
    *,
    expected_name: str = "vexcalibur",
    expected_version: str = "0.1.0",
    github_output: Path | None = None,
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
    return subprocess.run(  # noqa: S603
        command,
        check=False,
        text=True,
        capture_output=True,
    )


def test_verifier_accepts_matching_wheel_and_sdist(tmp_path: Path) -> None:
    write_wheel(tmp_path)
    write_sdist(tmp_path)

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
