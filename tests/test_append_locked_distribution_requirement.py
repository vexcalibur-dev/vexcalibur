from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest
from scripts.append_locked_distribution_requirement import (
    append_locked_distribution_requirement,
)


def _write_test_wheel(wheel: Path, *, module_contents: str = "") -> None:
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("vexcalibur/__init__.py", module_contents)
        archive.writestr(
            "vexcalibur-0.0.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: vexcalibur\nVersion: 0.0\n",
        )
        archive.writestr(
            "vexcalibur-0.0.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr("vexcalibur-0.0.dist-info/RECORD", "")


@pytest.mark.parametrize(
    "filename",
    [
        "vexcalibur-test-py3-none-any.whl",
        "vexcalibur-test.tar.gz",
    ],
)
def test_append_locked_distribution_requirement_pins_exact_bytes(
    tmp_path: Path,
    filename: str,
) -> None:
    distribution = tmp_path / filename
    distribution.write_bytes(b"original distribution bytes")
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("dependency==1.0 --hash=sha256:abc\n", encoding="utf-8")

    append_locked_distribution_requirement(distribution, requirements)

    content = requirements.read_text(encoding="utf-8")
    assert f"vexcalibur @ {distribution.as_uri()} \\" in content
    assert hashlib.sha256(distribution.read_bytes()).hexdigest() in content


def test_appended_requirement_hash_detects_tampered_distribution(
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "vexcalibur-test-py3-none-any.whl"
    wheel.write_bytes(b"original wheel bytes")
    requirements = tmp_path / "requirements.txt"
    requirements.touch()
    append_locked_distribution_requirement(wheel, requirements)
    pinned_hash = re.search(
        r"--hash=sha256:([0-9a-f]{64})",
        requirements.read_text(encoding="utf-8"),
    )
    assert pinned_hash is not None

    wheel.write_bytes(b"tampered wheel bytes")

    assert hashlib.sha256(wheel.read_bytes()).hexdigest() != pinned_hash.group(1)


def test_uv_rejects_wheel_tampered_after_requirement_is_locked(tmp_path: Path) -> None:
    wheel = tmp_path / "vexcalibur-0.0-py3-none-any.whl"
    _write_test_wheel(wheel)
    requirements = tmp_path / "requirements.txt"
    requirements.touch()
    append_locked_distribution_requirement(wheel, requirements)
    _write_test_wheel(wheel, module_contents='TAMPERED = "yes"\n')
    environment = {
        **os.environ,
        "UV_CACHE_DIR": str(tmp_path / "uv-cache"),
    }
    uv = shutil.which("uv")
    assert uv is not None
    subprocess.run(  # noqa: S603 - resolved developer tool from the current environment.
        [uv, "venv", str(tmp_path / "venv")],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )

    result = subprocess.run(  # noqa: S603 - resolved developer tool and local test files.
        [
            uv,
            "pip",
            "sync",
            "--require-hashes",
            "--python",
            str(tmp_path / "venv" / "bin" / "python"),
            str(requirements),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode != 0
    assert "hash" in result.stderr.lower()


def test_locked_installer_does_not_install_constraint_only_packages(tmp_path: Path) -> None:
    wheel = tmp_path / "vexcalibur-0.0-py3-none-any.whl"
    _write_test_wheel(wheel)
    venv = tmp_path / "venv"
    requirements = tmp_path / "requirements.txt"
    environment = {
        **os.environ,
        "UV_CACHE_DIR": str(tmp_path / "uv-cache"),
        "UV_OFFLINE": "1",
    }

    subprocess.run(  # noqa: S603 - repository-owned script and local test artifact.
        [
            str(Path(__file__).parents[1] / "scripts" / "install-locked-distribution.sh"),
            str(venv),
            str(wheel),
            str(requirements),
        ],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    installed = subprocess.run(  # noqa: S603 - test-owned virtual environment.
        [
            str(venv / "bin" / "python"),
            "-I",
            "-c",
            (
                "from importlib.metadata import distributions; "
                "print('\\n'.join(sorted(d.metadata['Name'] for d in distributions())))"
            ),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert installed.stdout.splitlines() == ["vexcalibur"]


def test_append_locked_distribution_requirement_rejects_non_file(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="not a regular file"):
        append_locked_distribution_requirement(
            tmp_path,
            tmp_path / "requirements.txt",
        )
