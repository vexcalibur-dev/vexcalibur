from __future__ import annotations

import os
import subprocess
import sys
import tarfile
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "verify-dist-metadata.py"
WRAPPER = REPO_ROOT / "scripts" / "run-dist-metadata-verifier.sh"
DEFAULT_METADATA_HEADERS = (
    "Metadata-Version: 2.4",
    "Requires-Python: >=3.10",
)


def write_wheel(
    dist_dir: Path,
    name: str = "vexcalibur",
    version: str = "0.1.0",
    *,
    metadata_headers: tuple[str, ...] = DEFAULT_METADATA_HEADERS,
    console_scripts: tuple[tuple[str, str], ...] = (),
) -> Path:
    path = dist_dir / f"{name}-{version}-py3-none-any.whl"
    metadata = "\n".join((f"Name: {name}", f"Version: {version}", *metadata_headers, ""))
    with zipfile.ZipFile(path, "w") as wheel:
        wheel.writestr(f"{name}-{version}.dist-info/METADATA", metadata)
        if console_scripts:
            wheel.writestr(
                f"{name}-{version}.dist-info/entry_points.txt",
                "[console_scripts]\n"
                + "".join(f"{script} = {target}\n" for script, target in console_scripts),
            )
    return path


def write_sdist(
    dist_dir: Path,
    name: str = "vexcalibur",
    version: str = "0.1.0",
    *,
    metadata_headers: tuple[str, ...] = DEFAULT_METADATA_HEADERS,
    console_scripts: tuple[tuple[str, str], ...] = (),
) -> Path:
    path = dist_dir / f"{name}-{version}.tar.gz"
    metadata = "\n".join((f"Name: {name}", f"Version: {version}", *metadata_headers, "")).encode()
    info = tarfile.TarInfo(f"{name}-{version}/PKG-INFO")
    info.size = len(metadata)
    with tarfile.open(path, "w:gz") as sdist:
        sdist.addfile(info, BytesIO(metadata))
        if console_scripts:
            entry_points = (
                "[console_scripts]\n"
                + "".join(f"{script} = {target}\n" for script, target in console_scripts)
            ).encode()
            entry_info = tarfile.TarInfo(f"{name}-{version}/src/{name}.egg-info/entry_points.txt")
            entry_info.size = len(entry_points)
            sdist.addfile(entry_info, BytesIO(entry_points))
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


def write_project_metadata(
    source_root: Path,
    *,
    requires_python: str | None = ">=3.10",
    dependencies: tuple[str, ...] = (),
    optional_dependencies: dict[str, tuple[str, ...]] | None = None,
    console_scripts: tuple[tuple[str, str], ...] = (),
) -> None:
    lines = [
        "[project]",
        'name = "vexcalibur"',
        'dynamic = ["version"]',
    ]
    if requires_python is not None:
        lines.append(f'requires-python = "{requires_python}"')
    lines.append("dependencies = [")
    lines.extend(f'  "{requirement}",' for requirement in dependencies)
    lines.append("]")
    if optional_dependencies:
        lines.extend(("", "[project.optional-dependencies]"))
        for extra, requirements in optional_dependencies.items():
            lines.extend(
                (
                    f"{extra} = [",
                    *(f'  "{requirement}",' for requirement in requirements),
                    "]",
                )
            )
    if console_scripts:
        lines.extend(("", "[project.scripts]"))
        lines.extend(f'{name} = "{target}"' for name, target in console_scripts)
    source_root.mkdir(parents=True, exist_ok=True)
    (source_root / "pyproject.toml").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def run_verifier(
    dist_dir: Path,
    *,
    expected_name: str = "vexcalibur",
    expected_version: str = "0.1.0",
    github_output: Path | None = None,
    source_root: Path | None = None,
    required_sdist_files: tuple[str, ...] = (),
    wrapper: bool = False,
) -> subprocess.CompletedProcess[str]:
    command = [
        *(("/bin/bash", str(WRAPPER)) if wrapper else (sys.executable, str(SCRIPT))),
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
        env=({**os.environ, "UV_OFFLINE": "1"} if wrapper else None),
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


def test_locked_wrapper_runs_verifier_in_an_isolated_environment(tmp_path: Path) -> None:
    write_wheel(tmp_path)
    write_sdist(tmp_path)

    result = run_verifier(tmp_path, wrapper=True)

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("header", ["Name", "Version", "Metadata-Version", "Requires-Python"])
def test_verifier_rejects_repeated_singleton_metadata(
    tmp_path: Path,
    header: str,
) -> None:
    duplicate_value = {
        "Name": "vexcalibur",
        "Version": "0.1.0",
        "Metadata-Version": "2.4",
        "Requires-Python": ">=3.10",
    }[header]
    write_wheel(
        tmp_path,
        metadata_headers=(*DEFAULT_METADATA_HEADERS, f"{header}: {duplicate_value}"),
    )
    write_sdist(tmp_path)

    result = run_verifier(tmp_path)

    assert result.returncode == 1
    assert f"Artifact must contain exactly one nonempty {header} metadata header." in result.stderr


def test_verifier_rejects_sdist_dependency_metadata_drift(tmp_path: Path) -> None:
    common_headers = (
        "Metadata-Version: 2.4",
        "Requires-Python: >=3.10,<4",
        "Requires-Dist: packageurl-python>=0.17,<1",
    )
    write_wheel(
        tmp_path,
        metadata_headers=(*common_headers, "Requires-Dist: httpx>=0.27,<1"),
    )
    write_sdist(tmp_path, metadata_headers=common_headers)

    result = run_verifier(tmp_path)

    assert result.returncode == 1
    assert "Built wheel and sdist Requires-Dist metadata do not match." in result.stderr


def test_verifier_rejects_console_script_metadata_drift(tmp_path: Path) -> None:
    write_wheel(
        tmp_path,
        console_scripts=(("vexcalibur", "vexcalibur.cli:app"),),
    )
    write_sdist(tmp_path)

    result = run_verifier(tmp_path)

    assert result.returncode == 1
    assert "Built wheel and sdist console scripts do not match." in result.stderr


def test_verifier_checks_artifact_metadata_against_pyproject(tmp_path: Path) -> None:
    headers = (
        "Metadata-Version: 2.4",
        "Requires-Python: <4,>=3.10",
        "Requires-Dist: httpx<1,>=0.27",
        'Requires-Dist: sphinx<9,>=8; extra == "docs"',
        "Provides-Extra: docs",
    )
    scripts = (
        ("vexcalibur", "vexcalibur.cli:app"),
        ("vexy", "vexcalibur.compat.vexy:app"),
    )
    write_wheel(tmp_path, metadata_headers=headers, console_scripts=scripts)
    write_sdist(tmp_path, metadata_headers=headers, console_scripts=scripts)
    source_root = tmp_path / "source"
    write_project_metadata(
        source_root,
        requires_python=">=3.10,<4",
        dependencies=("httpx>=0.27,<1",),
        optional_dependencies={"docs": ("sphinx>=8,<9",)},
        console_scripts=scripts,
    )

    result = run_verifier(tmp_path, source_root=source_root)

    assert result.returncode == 0, result.stderr


def test_verifier_rejects_missing_project_dependency_in_both_artifacts(
    tmp_path: Path,
) -> None:
    write_wheel(tmp_path)
    write_sdist(tmp_path)
    source_root = tmp_path / "source"
    write_project_metadata(source_root, dependencies=("httpx>=0.27,<1",))

    result = run_verifier(tmp_path, source_root=source_root)

    assert result.returncode == 1
    assert "Built wheel Requires-Dist metadata does not match pyproject.toml." in result.stderr


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
    write_project_metadata(source_root)
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
    write_project_metadata(source_root)
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
    write_project_metadata(source_root)
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
