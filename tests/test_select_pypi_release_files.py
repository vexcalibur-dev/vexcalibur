from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "select-pypi-release-files.py"
VERSION = "0.4.0"
WHEEL = f"vexcalibur-{VERSION}-py3-none-any.whl"
SDIST = f"vexcalibur-{VERSION}.tar.gz"
CONTENTS = {
    WHEEL: b"wheel contents\n",
    SDIST: b"sdist contents\n",
}
PACKAGE_TYPES = {WHEEL: "bdist_wheel", SDIST: "sdist"}


def digest(filename: str) -> str:
    return hashlib.sha256(CONTENTS[filename]).hexdigest()


def write_distributions(root: Path) -> Path:
    directory = root / "dist"
    directory.mkdir()
    for filename, contents in CONTENTS.items():
        (directory / filename).write_bytes(contents)
    return directory


def file_record(filename: str, *, sha256: str | None = None) -> dict[str, Any]:
    return {
        "filename": filename,
        "packagetype": PACKAGE_TYPES.get(filename, "sdist"),
        "digests": {"sha256": digest(filename) if sha256 is None else sha256},
    }


def write_response(root: Path, files: list[dict[str, Any]]) -> Path:
    path = root / "pypi.json"
    path.write_text(
        json.dumps(
            {
                "info": {"name": "vexcalibur", "version": VERSION},
                "urls": files,
            }
        ),
        encoding="utf-8",
    )
    return path


def run_selector(
    root: Path,
    *,
    response: Path | None,
    distribution_directory: Path | None = None,
    output_directory: Path | None = None,
    github_output: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    if distribution_directory is None:
        distribution_directory = write_distributions(root)
    if output_directory is None:
        output_directory = root / "selected"
    command = [
        sys.executable,
        str(SCRIPT),
        str(distribution_directory),
        "--version",
        VERSION,
        "--output-directory",
        str(output_directory),
    ]
    if response is None:
        command.append("--pypi-missing")
    else:
        command.extend(["--pypi-response", str(response)])
    if github_output is not None:
        command.extend(["--github-output", str(github_output)])
    environment = os.environ.copy()
    environment.pop("GITHUB_OUTPUT", None)
    return subprocess.run(  # noqa: S603
        command,
        check=False,
        text=True,
        capture_output=True,
        env=environment,
    )


def result_document(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    return json.loads(result.stdout)


def assert_output_files(root: Path, expected: list[str]) -> None:
    output = root / "selected"
    assert sorted(path.name for path in output.iterdir()) == sorted(expected)
    for filename in expected:
        assert (output / filename).read_bytes() == CONTENTS[filename]
        assert not (output / filename).is_symlink()


def test_explicit_missing_response_selects_both_distributions(tmp_path: Path) -> None:
    result = run_selector(tmp_path, response=None)

    assert result_document(result) == {
        "publish_needed": True,
        "missing_count": 2,
        "missing_files": [WHEEL, SDIST],
        "satisfied_files": [],
    }
    assert_output_files(tmp_path, [WHEEL, SDIST])


def test_empty_version_response_selects_both_distributions(tmp_path: Path) -> None:
    response = write_response(tmp_path, [])

    result = run_selector(tmp_path, response=response)

    assert result_document(result)["missing_files"] == [WHEEL, SDIST]
    assert_output_files(tmp_path, [WHEEL, SDIST])


def test_both_existing_distributions_are_satisfied(tmp_path: Path) -> None:
    response = write_response(tmp_path, [file_record(WHEEL), file_record(SDIST)])

    result = run_selector(tmp_path, response=response)

    assert result_document(result) == {
        "publish_needed": False,
        "missing_count": 0,
        "missing_files": [],
        "satisfied_files": [WHEEL, SDIST],
    }
    assert_output_files(tmp_path, [])


def test_existing_wheel_selects_only_sdist(tmp_path: Path) -> None:
    response = write_response(tmp_path, [file_record(WHEEL)])

    result = run_selector(tmp_path, response=response)

    assert result_document(result)["missing_files"] == [SDIST]
    assert_output_files(tmp_path, [SDIST])


def test_existing_sdist_selects_only_wheel(tmp_path: Path) -> None:
    response = write_response(tmp_path, [file_record(SDIST)])

    result = run_selector(tmp_path, response=response)

    assert result_document(result)["missing_files"] == [WHEEL]
    assert_output_files(tmp_path, [WHEEL])


def test_digest_mismatch_fails_without_creating_output(tmp_path: Path) -> None:
    response = write_response(tmp_path, [file_record(WHEEL, sha256="0" * 64)])

    result = run_selector(tmp_path, response=response)

    assert result.returncode == 1
    assert "different digest or package type" in result.stderr
    assert not (tmp_path / "selected").exists()


def test_package_type_mismatch_fails_without_creating_output(tmp_path: Path) -> None:
    wheel = file_record(WHEEL)
    wheel["packagetype"] = "sdist"
    response = write_response(tmp_path, [wheel])

    result = run_selector(tmp_path, response=response)

    assert result.returncode == 1
    assert "different digest or package type" in result.stderr
    assert not (tmp_path / "selected").exists()


def test_unexpected_release_file_fails_closed(tmp_path: Path) -> None:
    unexpected = f"vexcalibur-{VERSION}-cp314-cp314-manylinux_x86_64.whl"
    response = write_response(
        tmp_path,
        [
            {
                "filename": unexpected,
                "packagetype": "bdist_wheel",
                "digests": {"sha256": "1" * 64},
            }
        ],
    )

    result = run_selector(tmp_path, response=response)

    assert result.returncode == 1
    assert "unexpected release files" in result.stderr
    assert unexpected in result.stderr
    assert not (tmp_path / "selected").exists()


def test_malformed_response_fails_closed(tmp_path: Path) -> None:
    response = tmp_path / "pypi.json"
    response.write_text('{"info":', encoding="utf-8")

    result = run_selector(tmp_path, response=response)

    assert result.returncode == 1
    assert "not valid JSON" in result.stderr
    assert not (tmp_path / "selected").exists()


def test_oversized_response_fails_closed(tmp_path: Path) -> None:
    response = tmp_path / "pypi.json"
    response.write_bytes(b" " * (4 * 1024 * 1024 + 1))

    result = run_selector(tmp_path, response=response)

    assert result.returncode == 1
    assert "exceeds the 4194304-byte limit" in result.stderr
    assert not (tmp_path / "selected").exists()


def test_duplicate_json_key_fails_closed(tmp_path: Path) -> None:
    response = tmp_path / "pypi.json"
    response.write_text(
        '{"info":{"name":"vexcalibur","version":"0.4.0"},"urls":[],"urls":[]}',
        encoding="utf-8",
    )

    result = run_selector(tmp_path, response=response)

    assert result.returncode == 1
    assert "duplicate JSON object key: 'urls'" in result.stderr
    assert not (tmp_path / "selected").exists()


def test_duplicate_file_record_fails_closed(tmp_path: Path) -> None:
    response = write_response(tmp_path, [file_record(WHEEL), file_record(WHEEL)])

    result = run_selector(tmp_path, response=response)

    assert result.returncode == 1
    assert "duplicate file record" in result.stderr
    assert not (tmp_path / "selected").exists()


def test_existing_output_directory_is_never_reused(tmp_path: Path) -> None:
    response = write_response(tmp_path, [])
    output = tmp_path / "selected"
    output.mkdir()
    collision = output / WHEEL
    collision.write_text("do not overwrite\n", encoding="utf-8")

    result = run_selector(tmp_path, response=response, output_directory=output)

    assert result.returncode == 1
    assert "output directory must be fresh" in result.stderr
    assert collision.read_text(encoding="utf-8") == "do not overwrite\n"


def test_output_directory_symlink_is_never_followed(tmp_path: Path) -> None:
    response = write_response(tmp_path, [])
    target = tmp_path / "outside"
    target.mkdir()
    output = tmp_path / "selected"
    output.symlink_to(target, target_is_directory=True)

    result = run_selector(tmp_path, response=response, output_directory=output)

    assert result.returncode == 1
    assert "output directory must be fresh" in result.stderr
    assert list(target.iterdir()) == []


def test_unexpected_local_distribution_fails_without_creating_output(tmp_path: Path) -> None:
    distributions = write_distributions(tmp_path)
    (distributions / "extra.txt").write_text("unexpected\n", encoding="utf-8")

    result = run_selector(
        tmp_path,
        response=None,
        distribution_directory=distributions,
    )

    assert result.returncode == 1
    assert "distribution directory must contain exactly" in result.stderr
    assert "extra.txt" in result.stderr
    assert not (tmp_path / "selected").exists()


def test_input_distribution_symlink_is_rejected(tmp_path: Path) -> None:
    distributions = write_distributions(tmp_path)
    wheel = distributions / WHEEL
    target = tmp_path / "outside.whl"
    target.write_bytes(wheel.read_bytes())
    wheel.unlink()
    wheel.symlink_to(target)

    result = run_selector(
        tmp_path,
        response=None,
        distribution_directory=distributions,
    )

    assert result.returncode == 1
    assert "could not open input distribution" in result.stderr
    assert not (tmp_path / "selected").exists()


def test_pypi_response_symlink_is_rejected(tmp_path: Path) -> None:
    real_response = write_response(tmp_path, [])
    response = tmp_path / "response-link.json"
    response.symlink_to(real_response)

    result = run_selector(tmp_path, response=response)

    assert result.returncode == 1
    assert "could not open PyPI response" in result.stderr
    assert not (tmp_path / "selected").exists()


def test_github_output_reports_exact_missing_set(tmp_path: Path) -> None:
    response = write_response(tmp_path, [file_record(WHEEL)])
    github_output = tmp_path / "github-output.txt"

    result = run_selector(tmp_path, response=response, github_output=github_output)

    assert result_document(result)["missing_files"] == [SDIST]
    assert github_output.read_text(encoding="utf-8").splitlines() == [
        "publish_needed=true",
        "missing_count=1",
        f'missing_files=["{SDIST}"]',
    ]
