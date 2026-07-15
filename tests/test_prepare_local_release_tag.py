from __future__ import annotations

import subprocess
from pathlib import Path

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


def test_synthetic_ci_tag_isolated_from_real_and_conflicting_tags(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    first_sha = _commit(repository, "first\n")
    _git(repository, "tag", "v0.0.0", first_sha)
    release_sha = _commit(repository, "release\n")
    _git(repository, "tag", "--annotate", "v9.9.9", "--message", "real release", release_sha)

    subprocess.run(  # noqa: S603 - reviewed repository script and test-owned inputs
        [str(SCRIPT), "v0.0.0", release_sha, "true"],
        cwd=repository,
        check=True,
    )

    assert _git(repository, "tag", "--list") == "v0.0.0"
    assert _git(repository, "rev-parse", "v0.0.0^{commit}") == release_sha
    assert _git(repository, "describe", "--tags", "--exact-match", "HEAD") == "v0.0.0"


def test_normal_mode_rejects_an_existing_tag_on_another_commit(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    first_sha = _commit(repository, "first\n")
    _git(repository, "tag", "v1.2.3", first_sha)
    release_sha = _commit(repository, "release\n")

    completed = subprocess.run(  # noqa: S603 - reviewed repository script and test-owned inputs
        [str(SCRIPT), "v1.2.3", release_sha, "false"],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "already exists" in completed.stderr
    assert _git(repository, "rev-parse", "v1.2.3^{commit}") == first_sha
