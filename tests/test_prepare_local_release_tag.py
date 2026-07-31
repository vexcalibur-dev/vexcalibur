from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from setuptools_scm import get_version

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "prepare-local-release-tag.sh"
GIT = "/usr/bin/git"


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(  # noqa: S603 - fixed Git binary and test-owned repository
        [GIT, *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _commit(repository: Path, contents: str) -> str:
    (repository / "tracked.txt").write_text(contents)
    _git(repository, "add", "tracked.txt")
    _git(repository, "commit", "-m", contents.strip())
    return _git(repository, "rev-parse", "HEAD")


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--initial-branch=main")
    _git(repository, "config", "user.name", "Release Test")
    _git(repository, "config", "user.email", "release-test@example.test")
    return repository


def _setuptools_scm_version(repository: Path) -> str:
    return get_version(
        root=repository,
        local_scheme="no-local-version",
    )


def test_rejects_competing_version_tags_without_mutating_tags(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    first_sha = _commit(repository, "first\n")
    _git(repository, "tag", "v0.0.0", first_sha)
    release_sha = _commit(repository, "release\n")
    _git(repository, "tag", "--annotate", "v9.9.9", "--message", "real release", release_sha)

    completed = subprocess.run(  # noqa: S603 - reviewed repository script and test-owned inputs
        [str(SCRIPT), "v1.2.3", release_sha, sys.executable],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "competing version tag(s): v9.9.9" in completed.stderr
    assert _git(repository, "tag", "--list") == "v0.0.0\nv9.9.9"
    assert _git(repository, "rev-parse", "v0.0.0^{commit}") == first_sha
    assert _git(repository, "rev-parse", "v9.9.9^{commit}") == release_sha


def test_created_release_tag_is_the_setuptools_scm_version(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    release_sha = _commit(repository, "release\n")
    _git(repository, "tag", "documentation", release_sha)

    subprocess.run(  # noqa: S603 - reviewed repository script and test-owned inputs
        [str(SCRIPT), "v1.2.3", release_sha, sys.executable],
        cwd=repository,
        check=True,
    )

    assert _setuptools_scm_version(repository) == "1.2.3"
    assert _git(repository, "tag", "--points-at", release_sha) == "documentation\nv1.2.3"


def test_rejects_an_existing_tag_on_another_commit(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    first_sha = _commit(repository, "first\n")
    _git(repository, "tag", "v1.2.3", first_sha)
    release_sha = _commit(repository, "release\n")

    completed = subprocess.run(  # noqa: S603 - reviewed repository script and test-owned inputs
        [str(SCRIPT), "v1.2.3", release_sha, sys.executable],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "already exists" in completed.stderr
    assert _git(repository, "rev-parse", "v1.2.3^{commit}") == first_sha


def test_tag_enumeration_failure_does_not_create_release_tag(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    release_sha = _commit(repository, "release\n")
    executable_directory = tmp_path / "bin"
    executable_directory.mkdir()
    git_wrapper = executable_directory / "git"
    git_wrapper.write_text(
        """#!/bin/bash
set -euo pipefail
if [[ "${1:-}" = tag && "${2:-}" = --points-at ]]; then
  exit 42
fi
exec "${REAL_GIT}" "$@"
""",
        encoding="utf-8",
    )
    git_wrapper.chmod(0o700)
    environment = os.environ.copy()
    environment["PATH"] = f"{executable_directory}{os.pathsep}{environment['PATH']}"
    environment["REAL_GIT"] = GIT

    completed = subprocess.run(  # noqa: S603 - reviewed script and test-owned inputs
        [str(SCRIPT), "v1.2.3", release_sha, sys.executable],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "could not enumerate tags" in completed.stderr
    assert _git(repository, "tag", "--list") == ""


def test_tag_probe_failure_does_not_create_release_tag(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    release_sha = _commit(repository, "release\n")
    executable_directory = tmp_path / "bin"
    executable_directory.mkdir()
    git_wrapper = executable_directory / "git"
    git_wrapper.write_text(
        """#!/bin/bash
set -euo pipefail
if [[ "${1:-}" = rev-parse && "${2:-}" = -q && "${3:-}" = --verify ]]; then
  exit 42
fi
exec "${REAL_GIT}" "$@"
""",
        encoding="utf-8",
    )
    git_wrapper.chmod(0o700)
    environment = os.environ.copy()
    environment["PATH"] = f"{executable_directory}{os.pathsep}{environment['PATH']}"
    environment["REAL_GIT"] = GIT

    completed = subprocess.run(  # noqa: S603 - reviewed script and test-owned inputs
        [str(SCRIPT), "v1.2.3", release_sha, sys.executable],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "could not inspect existing release tag" in completed.stderr
    assert _git(repository, "tag", "--list") == ""


@pytest.mark.parametrize("competing_tag", ("9.9.9", "release-9.9.9"))
def test_rejects_other_setuptools_scm_version_tags(
    tmp_path: Path,
    competing_tag: str,
) -> None:
    repository = _repository(tmp_path)
    release_sha = _commit(repository, "release\n")
    _git(repository, "tag", competing_tag, release_sha)

    completed = subprocess.run(  # noqa: S603 - reviewed script and test-owned inputs
        [str(SCRIPT), "v1.2.3", release_sha, sys.executable],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "setuptools-scm resolved 9.9.9, expected 1.2.3" in completed.stderr
    assert _git(repository, "tag", "--list") == competing_tag
