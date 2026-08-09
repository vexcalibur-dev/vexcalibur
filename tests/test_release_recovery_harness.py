"""Controlled-process and fake-service tests for the release harness."""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.release_recovery_harness import ReleaseRecoveryHarness


@pytest.mark.parametrize(
    "arguments",
    (
        ["api", "graphql"],
        [
            "api",
            "graphql",
            "-f",
            "query=query($own er:String!){repository(owner:$own er){id}}",
            "-F",
            "owner=vexcalibur-dev",
            "-F",
            "repository=vexcalibur",
            "-F",
            "tag=v1.2.3",
        ],
        [
            "api",
            "--method",
            "DELETE",
            "repos/vexcalibur-dev/vexcalibur/immutable-releases",
            "--jq",
            ".enabled",
        ],
        ["release", "verify", "v1.2.3", "--repo", "attacker/other"],
        [
            "release",
            "create",
            "v1.2.3",
            "--repo",
            "vexcalibur-dev/vexcalibur",
            "--draft",
            "--verify-tag",
            "--target",
            "a" * 40,
            "--title",
            "v1.2.3",
            "--notes-file",
            "/etc/hosts",
        ],
        ["repo", "view"],
    ),
)
def test_fake_github_rejects_and_records_unmodeled_commands(
    tmp_path: Path,
    arguments: list[str],
) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)

    completed = subprocess.run(  # noqa: S603 - test-owned fail-closed fake
        [str(harness.fake_bin / "gh"), *arguments],
        check=False,
        capture_output=True,
        text=True,
        env={
            "GH_TEST_STATE": str(harness.state_path),
            "GH_TOKEN": harness.write_token,
            "PATH": str(harness.fake_bin),
            "RUNNER_TEMP": str(harness.runner_temp),
        },
    )

    assert completed.returncode == 96
    assert "unmodeled gh command" in completed.stderr
    assert harness.calls(*arguments) == [arguments]


def test_fake_github_requires_the_write_token_for_mutations(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)

    completed = harness.run_release_step(
        "publish-release",
        "Create GitHub Release",
        expression_values={
            "needs.validation.outputs.tag": harness.release_tag,
            "needs.validation.outputs.sha": harness.release_sha,
            "steps.app-token.outputs.app-slug": harness.app_slug,
            "steps.app-token.outputs.token": harness.read_token,
        },
    )

    assert completed.returncode != 0
    assert "invalid fake GitHub token" in completed.stderr
    assert harness.state["release"] is None


def test_fake_github_rejects_noncanonical_asset_endpoints(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    asset = harness.write_asset()
    harness.update_state(release=harness.contract_release())
    harness.add_remote_asset(asset)

    completed = subprocess.run(  # noqa: S603 - test-owned fail-closed fake
        [
            str(harness.fake_bin / "gh"),
            "api",
            "--method",
            "DELETE",
            "repos/vexcalibur-dev/vexcalibur/releases/assets//1000",
        ],
        check=False,
        capture_output=True,
        text=True,
        env={
            "GH_TEST_STATE": str(harness.state_path),
            "GH_TOKEN": harness.write_token,
            "PATH": str(harness.fake_bin),
            "RUNNER_TEMP": str(harness.runner_temp),
        },
    )

    assert completed.returncode == 96
    assert len(harness.state["release"]["_assets"]) == 1


def test_fake_github_rejects_mutating_an_immutable_release(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    asset = harness.write_asset()
    harness.update_state(release=harness.contract_release(published=True))
    harness.add_remote_asset(asset)
    transition = harness.runner_temp / "immutable-publication-transition.json"
    transition.write_text(
        json.dumps(
            {
                "tag_name": harness.release_tag,
                "target_commitish": harness.release_sha,
                "name": harness.release_tag,
                "body": harness.notes,
                "draft": False,
                "prerelease": False,
            }
        ),
        encoding="utf-8",
    )
    repository = harness.state["repository"]
    release_id = harness.state["release"]["id"]
    commands = (
        ["release", "upload", harness.release_tag, str(asset), "--repo", repository],
        ["api", "--method", "DELETE", f"repos/{repository}/releases/assets/1000"],
        [
            "api",
            "--method",
            "PATCH",
            f"repos/{repository}/releases/{release_id}",
            "--input",
            str(transition),
        ],
    )
    before = harness.state["release"]

    for command in commands:
        completed = subprocess.run(  # noqa: S603 - test-owned fail-closed fake
            [str(harness.fake_bin / "gh"), *command],
            check=False,
            capture_output=True,
            text=True,
            env={
                "GH_TEST_STATE": str(harness.state_path),
                "GH_TOKEN": harness.write_token,
                "PATH": str(harness.fake_bin),
                "RUNNER_TEMP": str(harness.runner_temp),
            },
        )

        assert completed.returncode == 96
        assert harness.state["release"] == before


def test_fake_python_rejects_an_unmodeled_network_client(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    argument = tmp_path / "argument.json"
    argument.write_text("{}\n", encoding="utf-8")

    completed = subprocess.run(  # noqa: S603 - test-owned fail-closed fake
        [str(harness.fake_bin / "python3"), "-I", "-", str(argument)],
        check=False,
        capture_output=True,
        env={"GH_TEST_STATE": str(harness.state_path)},
        input="import urllib.request\nurllib.request.urlopen('http://127.0.0.1:9')\n",
        text=True,
    )

    assert completed.returncode == 96
    assert "unmodeled python3 command" in completed.stderr
    assert harness.state["unmodeled_calls"] == [["python3", "-I", "-", str(argument)]]


@pytest.mark.parametrize("command", ("curl unsupported", "python3 unsupported"))
def test_harness_detects_suppressed_fake_client_rejections(
    tmp_path: Path,
    command: str,
) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)

    completed = harness.run_test_script(f"{command} || true")

    assert completed.returncode == 96
    assert "workflow invoked an unmodeled command" in completed.stderr


def test_harness_stops_a_timed_out_process_group(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    monkeypatch.setattr(
        "tests.release_recovery_harness.WORKFLOW_TEST_TIMEOUT_SECONDS",
        0.05,
    )

    completed = harness.run_test_script("while true; do :; done")

    assert completed.returncode == 124
    assert "workflow step exceeded the test timeout" in completed.stderr


@pytest.mark.parametrize("name", ("BASH_ENV", "LD_PRELOAD", "PYTHONPATH"))
def test_harness_rejects_process_startup_environment(
    tmp_path: Path,
    name: str,
) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)

    with pytest.raises(ValueError, match="unsafe process environment"):
        harness._run_controlled(
            "true",
            cwd=harness.runner_temp,
            environment={"PATH": str(harness.fake_bin), name: "attacker-controlled"},
        )


def test_harness_resolves_uv_past_version_manager_shims(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)

    assert (harness.fake_bin / "uv").is_symlink()
    assert "/shims/" not in str((harness.fake_bin / "uv").resolve())


def test_harness_resolves_uv_from_a_pyenv_shim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shim = tmp_path / ".pyenv" / "shims" / "uv"
    target = tmp_path / ".pyenv" / "versions" / "tools" / "bin" / "uv"
    manager = tmp_path / "bin" / "pyenv"
    for path in (shim, target, manager):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
        path.chmod(0o755)
    manager.write_text(f"#!/bin/sh\nprintf '%s\\n' {shlex.quote(str(target))}\n", encoding="utf-8")

    def find_command(command: str) -> str | None:
        return {
            "uv": str(shim),
            "asdf": None,
            "mise": None,
            "pyenv": str(manager),
        }.get(command)

    monkeypatch.setattr(shutil, "which", find_command)

    assert ReleaseRecoveryHarness._resolve_command("uv") == str(target.resolve())


def test_harness_uses_git_resolved_past_a_version_manager_shim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shim = tmp_path / ".mise" / "shims" / "git"
    target = tmp_path / ".mise" / "installs" / "git" / "bin" / "git"
    manager = tmp_path / "manager-bin" / "mise"
    for path in (shim, target, manager):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
        path.chmod(0o755)
    manager.write_text(f"#!/bin/sh\nprintf '%s\\n' {shlex.quote(str(target))}\n", encoding="utf-8")
    find_system_command = shutil.which

    def find_command(command: str) -> str | None:
        return {
            "git": str(shim),
            "asdf": None,
            "mise": str(manager),
            "pyenv": None,
        }.get(command, find_system_command(command))

    monkeypatch.setattr(shutil, "which", find_command)

    harness = ReleaseRecoveryHarness(tmp_path)

    assert harness.git == str(target.resolve())
    assert (harness.fake_bin / "git").resolve() == target.resolve()


def test_harness_resolves_the_python_interpreter_symlink(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)

    assert harness.python == str(Path(sys.executable).resolve())
    assert Path(harness.python).is_file()
    assert shlex.quote(harness.python) in (harness.fake_bin / "gh").read_text(encoding="utf-8")


def test_harness_rejects_malformed_nested_call_state(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    state = harness.state
    state["calls"] = [["api", 123]]
    harness.state_path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(ValueError, match="recorded calls"):
        _ = harness.state


@pytest.mark.parametrize(
    ("field", "value", "error"),
    (
        (
            "tag_ref",
            {"ref": "refs/tags/v0.1.0", "object": {"type": "tag", "sha": 1}},
            "tag ref object values",
        ),
        (
            "tag_object",
            {"tag": "v0.1.0", "message": "{}", "object": {}, "tagger": {}},
            "nested tag object",
        ),
        (
            "tag_object",
            {
                "tag": "v0.1.0",
                "message": "{}",
                "object": {"type": "commit", "sha": "a" * 40},
                "tagger": {"name": "app", "email": 1},
            },
            "nested tag tagger values",
        ),
    ),
)
def test_harness_rejects_malformed_nested_tag_state(
    tmp_path: Path,
    field: str,
    value: dict[str, object],
    error: str,
) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    state = harness.state
    state[field] = value
    harness.state_path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(ValueError, match=error):
        _ = harness.state
