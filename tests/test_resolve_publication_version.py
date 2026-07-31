from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "resolve-publication-version.sh"
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


def _repository(tmp_path: Path) -> tuple[Path, str]:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--initial-branch=main")
    _git(repository, "config", "user.name", "Release Test")
    _git(repository, "config", "user.email", "release-test@example.test")
    (repository / "tracked.txt").write_text("release\n")
    _git(repository, "add", "tracked.txt")
    _git(repository, "commit", "-m", "release")
    return repository, _git(repository, "rev-parse", "HEAD")


def _resolve(repository: Path, release_sha: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - reviewed script and test-owned inputs
        [str(SCRIPT), release_sha],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )


def test_uses_synthetic_version_for_an_untagged_commit(tmp_path: Path) -> None:
    repository, release_sha = _repository(tmp_path)

    completed = _resolve(repository, release_sha)

    assert completed.returncode == 0
    assert completed.stdout == "synthetic=true\ntag=v0.0.0\nversion=0.0.0\n"
    assert _git(repository, "tag", "--list") == ""


def test_reuses_the_single_immutable_release_tag(tmp_path: Path) -> None:
    repository, release_sha = _repository(tmp_path)
    _git(repository, "tag", "--annotate", "v1.2.3", "--message", "release", release_sha)

    completed = _resolve(repository, release_sha)

    assert completed.returncode == 0
    assert completed.stdout == "synthetic=false\ntag=v1.2.3\nversion=1.2.3\n"
    assert _git(repository, "tag", "--list") == "v1.2.3"


def test_ignores_nonrelease_tags(tmp_path: Path) -> None:
    repository, release_sha = _repository(tmp_path)
    _git(repository, "tag", "documentation", release_sha)

    completed = _resolve(repository, release_sha)

    assert completed.returncode == 0
    assert completed.stdout == "synthetic=true\ntag=v0.0.0\nversion=0.0.0\n"


def test_rejects_a_lightweight_release_tag(tmp_path: Path) -> None:
    repository, release_sha = _repository(tmp_path)
    _git(repository, "tag", "v1.2.3", release_sha)

    completed = _resolve(repository, release_sha)

    assert completed.returncode == 1
    assert completed.stderr == "release tag must be annotated: v1.2.3\n"


def test_rejects_a_nested_annotated_release_tag(tmp_path: Path) -> None:
    repository, release_sha = _repository(tmp_path)
    _git(
        repository,
        "tag",
        "--annotate",
        "release-target",
        "--message",
        "inner",
        release_sha,
    )
    _git(
        repository,
        "tag",
        "--annotate",
        "v1.2.3",
        "--message",
        "outer",
        "release-target",
    )

    completed = _resolve(repository, release_sha)

    assert completed.returncode == 1
    assert completed.stderr == "release tag must directly annotate the release commit: v1.2.3\n"


def test_rejects_multiple_release_tags_without_mutation(tmp_path: Path) -> None:
    repository, release_sha = _repository(tmp_path)
    _git(repository, "tag", "--annotate", "v1.2.3", "--message", "release", release_sha)
    _git(repository, "tag", "--annotate", "v2.0.0", "--message", "release", release_sha)

    completed = _resolve(repository, release_sha)

    assert completed.returncode == 1
    assert "multiple version tags: v1.2.3 v2.0.0" in completed.stderr
    assert _git(repository, "tag", "--list") == "v1.2.3\nv2.0.0"


@pytest.mark.parametrize("release_sha", ("not-a-sha", "a" * 40))
def test_rejects_invalid_commits(tmp_path: Path, release_sha: str) -> None:
    repository, _ = _repository(tmp_path)

    completed = _resolve(repository, release_sha)

    assert completed.returncode == 2
