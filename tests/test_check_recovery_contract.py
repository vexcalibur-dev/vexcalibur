from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
CHECKER = ROOT / "scripts" / "check-recovery-contract.py"
GIT = "/usr/bin/git"


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(  # noqa: S603 - fixed Git binary and test-owned repository
        [GIT, *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _commit(repository: Path, message: str) -> str:
    _git(repository, "add", ".")
    _git(
        repository,
        "-c",
        "user.name=Vexcalibur Test",
        "-c",
        "user.email=vexcalibur@example.test",
        "commit",
        "-m",
        message,
    )
    return _git(repository, "rev-parse", "HEAD")


def _run_checker(repository: Path, ref: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed interpreter and reviewed local script
        [sys.executable, "-I", str(CHECKER), "--ref", ref],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )


def test_recovery_contract_rejects_legacy_commit_and_accepts_schema_one(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--initial-branch=main")
    (repository / "README.md").write_text("# Test\n", encoding="utf-8")
    legacy_commit = _commit(repository, "test: create legacy release")

    legacy = _run_checker(repository, legacy_commit)

    assert legacy.returncode == 2
    assert "could not read the tagged recovery contract" in legacy.stderr

    contract_path = repository / "release-evidence" / "recovery-contract.json"
    contract_path.parent.mkdir()
    contract_path.write_text('{"schema_version":1}\n', encoding="utf-8")
    current_commit = _commit(repository, "test: add recovery contract")

    current = _run_checker(repository, current_commit)

    assert current.returncode == 0
    assert current.stdout == "recovery contract 1 verified\n"


def test_recovery_contract_rejects_boolean_schema_version(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--initial-branch=main")
    contract_path = repository / "release-evidence" / "recovery-contract.json"
    contract_path.parent.mkdir()
    contract_path.write_text('{"schema_version":true}\n', encoding="utf-8")
    commit = _commit(repository, "test: add invalid recovery contract")

    result = _run_checker(repository, commit)

    assert result.returncode == 2
    assert "unsupported recovery contract" in result.stderr
