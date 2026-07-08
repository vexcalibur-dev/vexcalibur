from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "next-release-tag.sh"
GIT = shutil.which("git")
BASH = shutil.which("bash")

if GIT is None:
    raise RuntimeError("git is required to test release version calculation")
if BASH is None:
    raise RuntimeError("bash is required to test release version calculation")


def run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(  # noqa: S603
        [GIT, *args],
        cwd=repo,
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout.strip()


def commit(repo: Path, message: str, filename: str = "change.txt") -> None:
    path = repo / filename
    path.write_text(f"{message}\n", encoding="utf-8")
    run_git(repo, "add", filename)
    run_git(repo, "commit", "-m", message)


def init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    run_git(repo, "init", "-b", "main")
    run_git(repo, "config", "user.name", "Release Test")
    run_git(repo, "config", "user.email", "release-test@example.invalid")
    shutil.copy2(SCRIPT, repo / "next-release-tag.sh")
    commit(repo, "chore: initialize", "README.md")
    return repo


def run_release_script(repo: Path, version: str = "") -> dict[str, str]:
    env = os.environ.copy()
    env.pop("GITHUB_OUTPUT", None)
    result = subprocess.run(  # noqa: S603
        [BASH, "next-release-tag.sh", version],
        cwd=repo,
        check=True,
        text=True,
        capture_output=True,
        env=env,
    )
    return dict(line.split("=", 1) for line in result.stdout.splitlines())


def run_release_script_failure(repo: Path, version: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("GITHUB_OUTPUT", None)
    return subprocess.run(  # noqa: S603
        [BASH, "next-release-tag.sh", version],
        cwd=repo,
        check=False,
        text=True,
        capture_output=True,
        env=env,
    )


def run_release_script_with_github_output(repo: Path, version: str = "") -> dict[str, str]:
    output_path = repo / "github-output.txt"
    env = os.environ.copy()
    env["GITHUB_OUTPUT"] = str(output_path)
    result = subprocess.run(  # noqa: S603
        [BASH, "next-release-tag.sh", version],
        cwd=repo,
        check=True,
        text=True,
        capture_output=True,
        env=env,
    )
    assert result.stdout == ""
    return dict(line.split("=", 1) for line in output_path.read_text(encoding="utf-8").splitlines())


def test_initial_release_defaults_to_0_1_0(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)

    assert run_release_script(repo) == {
        "skip": "false",
        "tag": "v0.1.0",
        "version": "0.1.0",
        "previous_tag": "",
        "bump": "initial",
    }


def test_manual_release_accepts_explicit_version(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)

    assert run_release_script(repo, "v0.3.0") == {
        "skip": "false",
        "tag": "v0.3.0",
        "version": "0.3.0",
        "previous_tag": "",
        "bump": "manual",
    }


def test_manual_release_must_exceed_latest_existing_tag(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    run_git(repo, "tag", "-a", "v0.1.0", "-m", "Release v0.1.0")
    commit(repo, "fix: update after first release")

    result = run_release_script_failure(repo, "0.1.0")

    assert result.returncode == 1
    assert "manual version 0.1.0 must be greater than base version 0.1.0" in result.stderr


def test_malformed_release_like_tags_are_ignored(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    run_git(repo, "tag", "-a", "v01.2.3", "-m", "Malformed release-like tag")
    run_git(repo, "tag", "-a", "v0.1.0", "-m", "Release v0.1.0")
    commit(repo, "fix: update after first release")

    assert run_release_script(repo) == {
        "skip": "false",
        "tag": "v0.1.1",
        "version": "0.1.1",
        "previous_tag": "v0.1.0",
        "bump": "patch",
    }


def test_only_malformed_release_like_tags_do_not_block_initial_release(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    run_git(repo, "tag", "-a", "v01.2.3", "-m", "Malformed release-like tag")

    assert run_release_script(repo) == {
        "skip": "false",
        "tag": "v0.1.0",
        "version": "0.1.0",
        "previous_tag": "",
        "bump": "initial",
    }


def test_manual_release_can_exceed_tag_on_current_head(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    run_git(repo, "tag", "-a", "v0.1.0", "-m", "Release v0.1.0")

    assert run_release_script(repo, "0.2.0") == {
        "skip": "false",
        "tag": "v0.2.0",
        "version": "0.2.0",
        "previous_tag": "v0.1.0",
        "bump": "manual",
    }


def test_manual_release_rejects_lower_version(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    run_git(repo, "tag", "-a", "v0.2.0", "-m", "Release v0.2.0")
    commit(repo, "fix: update after second release")

    result = run_release_script_failure(repo, "0.1.9")

    assert result.returncode == 1
    assert "manual version 0.1.9 must be greater than base version 0.2.0" in result.stderr


def test_manual_release_rejects_malformed_version(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)

    result = run_release_script_failure(repo, "01.2.3")

    assert result.returncode == 1
    assert "version 01.2.3 must be MAJOR.MINOR.PATCH without leading zeros" in result.stderr


def test_manual_release_rejects_unbounded_version_component(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)

    result = run_release_script_failure(repo, "0.0.1000000")

    assert result.returncode == 1
    assert "version component 1000000 must be less than or equal to 999999" in result.stderr


def test_manual_release_ignores_skip_marker(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    run_git(repo, "tag", "-a", "v0.1.0", "-m", "Release v0.1.0")
    commit(repo, "fix: update after first release [skip release]")

    assert run_release_script(repo, "0.1.1") == {
        "skip": "false",
        "tag": "v0.1.1",
        "version": "0.1.1",
        "previous_tag": "v0.1.0",
        "bump": "manual",
    }


def test_outputs_can_be_written_to_github_output_file(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)

    assert run_release_script_with_github_output(repo) == {
        "skip": "false",
        "tag": "v0.1.0",
        "version": "0.1.0",
        "previous_tag": "",
        "bump": "initial",
    }


def test_existing_head_tag_can_create_missing_release(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    run_git(repo, "tag", "-a", "v0.1.0", "-m", "Release v0.1.0")

    assert run_release_script(repo) == {
        "skip": "false",
        "tag": "v0.1.0",
        "version": "0.1.0",
        "previous_tag": "",
        "bump": "existing",
    }


def test_docs_only_change_after_tag_skips_release(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    run_git(repo, "tag", "-a", "v0.1.0", "-m", "Release v0.1.0")
    commit(repo, "docs: update usage notes")

    assert run_release_script(repo) == {
        "skip": "true",
        "tag": "",
        "version": "",
        "previous_tag": "v0.1.0",
        "bump": "skip",
    }


def test_fix_change_after_tag_bumps_patch(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    run_git(repo, "tag", "-a", "v0.1.0", "-m", "Release v0.1.0")
    commit(repo, "fix: handle empty SBOM components")

    assert run_release_script(repo) == {
        "skip": "false",
        "tag": "v0.1.1",
        "version": "0.1.1",
        "previous_tag": "v0.1.0",
        "bump": "patch",
    }


def test_commit_type_matching_is_case_insensitive(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    run_git(repo, "tag", "-a", "v0.1.0", "-m", "Release v0.1.0")
    commit(repo, "Fix: handle empty SBOM components")

    assert run_release_script(repo) == {
        "skip": "false",
        "tag": "v0.1.1",
        "version": "0.1.1",
        "previous_tag": "v0.1.0",
        "bump": "patch",
    }


def test_dependency_change_after_tag_bumps_patch(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    run_git(repo, "tag", "-a", "v0.1.0", "-m", "Release v0.1.0")
    commit(repo, "build(deps): bump typer")

    assert run_release_script(repo) == {
        "skip": "false",
        "tag": "v0.1.1",
        "version": "0.1.1",
        "previous_tag": "v0.1.0",
        "bump": "patch",
    }


def test_perf_and_refactor_changes_after_tag_bump_patch(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    run_git(repo, "tag", "-a", "v0.1.0", "-m", "Release v0.1.0")
    commit(repo, "perf: cache parsed SBOM components", "perf.txt")
    commit(repo, "refactor: simplify VEX rendering", "refactor.txt")

    assert run_release_script(repo) == {
        "skip": "false",
        "tag": "v0.1.1",
        "version": "0.1.1",
        "previous_tag": "v0.1.0",
        "bump": "patch",
    }


def test_revert_change_after_tag_bumps_patch(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    run_git(repo, "tag", "-a", "v0.1.0", "-m", "Release v0.1.0")
    commit(repo, 'Revert "feat: add SPDX ingest"')

    assert run_release_script(repo) == {
        "skip": "false",
        "tag": "v0.1.1",
        "version": "0.1.1",
        "previous_tag": "v0.1.0",
        "bump": "patch",
    }


def test_conventional_revert_change_after_tag_bumps_patch(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    run_git(repo, "tag", "-a", "v0.1.0", "-m", "Release v0.1.0")
    commit(repo, "revert: remove SPDX ingest")

    assert run_release_script(repo) == {
        "skip": "false",
        "tag": "v0.1.1",
        "version": "0.1.1",
        "previous_tag": "v0.1.0",
        "bump": "patch",
    }


def test_feature_change_after_tag_bumps_minor(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    run_git(repo, "tag", "-a", "v0.1.0", "-m", "Release v0.1.0")
    commit(repo, "feat: add SPDX ingest")

    assert run_release_script(repo) == {
        "skip": "false",
        "tag": "v0.2.0",
        "version": "0.2.0",
        "previous_tag": "v0.1.0",
        "bump": "minor",
    }


def test_breaking_change_after_tag_bumps_major(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    run_git(repo, "tag", "-a", "v0.2.3", "-m", "Release v0.2.3")
    commit(repo, "feat!: change provider configuration")

    assert run_release_script(repo) == {
        "skip": "false",
        "tag": "v1.0.0",
        "version": "1.0.0",
        "previous_tag": "v0.2.3",
        "bump": "major",
    }


def test_breaking_change_footer_after_tag_bumps_major(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    run_git(repo, "tag", "-a", "v0.2.3", "-m", "Release v0.2.3")
    commit(
        repo,
        "fix: change provider configuration\n\nBREAKING-CHANGE: provider names changed",
    )

    assert run_release_script(repo) == {
        "skip": "false",
        "tag": "v1.0.0",
        "version": "1.0.0",
        "previous_tag": "v0.2.3",
        "bump": "major",
    }


def test_skip_marker_skips_automatic_release(tmp_path: Path) -> None:
    repo = init_repo(tmp_path)
    run_git(repo, "tag", "-a", "v0.1.0", "-m", "Release v0.1.0")
    commit(repo, "fix: handle optional metadata [skip release]")

    assert run_release_script(repo) == {
        "skip": "true",
        "tag": "",
        "version": "",
        "previous_tag": "v0.1.0",
        "bump": "skip",
    }
