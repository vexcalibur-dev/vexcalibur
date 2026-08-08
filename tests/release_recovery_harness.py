"""Credentialless harness that executes shell steps from the release workflows."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

from tests.release_workflow_helpers import (
    _job,
    _job_environment,
    _pypi_text,
    _step,
    _step_environment,
    _step_script,
    _workflow_environment,
    _workflow_text,
)

ROOT = Path(__file__).parents[1]
FAKE_GH = ROOT / "tests" / "fixtures" / "fake_release_gh.py"
FAKE_PYPI_CLI = ROOT / "tests" / "fixtures" / "fake_pypi_cli.py"
FAKE_PYTHON = ROOT / "tests" / "fixtures" / "fake_release_python.py"
RECOVERY_CHECKER = ROOT / "scripts" / "check-recovery-contract.py"
WORKFLOW_TEST_TIMEOUT_SECONDS = 30
SYSTEM_COMMANDS = (
    "awk",
    "bash",
    "chmod",
    "cmp",
    "comm",
    "find",
    "git",
    "grep",
    "jq",
    "mkdir",
    "mktemp",
    "sed",
    "sha256sum",
    "sort",
    "stat",
    "tail",
    "uv",
    "wc",
)


EXPRESSION = re.compile(r"^\$\{\{\s*(.+?)\s*}}$")
IMMUTABLE_STATE_KEYS = {
    "app_slug",
    "bot_user_id",
    "read_token",
    "main_sha",
    "release_id",
    "release_sha",
    "release_tag",
    "repository",
    "tag_object",
    "tag_object_sha",
    "tag_ref",
    "write_token",
}


class ReleaseRecoveryHarness:
    """Run exact workflow step bodies against persistent fake GitHub state."""

    def __init__(self, tmp_path: Path) -> None:
        self.root = tmp_path
        self.runner_temp = tmp_path / "runner"
        self.asset_dir = self.runner_temp / "release-assets"
        self.notes_path = self.runner_temp / "release-notes" / "vexcalibur-release-notes.md"
        self.state_path = tmp_path / "github-state.json"
        self.output_path = tmp_path / "github-output"
        self.fake_bin = tmp_path / "bin"
        self.home = tmp_path / "home"
        self.release_tag = "v1.2.3"
        self.release_sha = "a" * 40
        self.main_sha = self.release_sha
        self.app_slug = "vexcalibur-dev-automation"
        self.bot_user_id = 12345
        self.read_token = "read-only-token"  # noqa: S105  # pragma: allowlist secret
        self.write_token = "write-token"  # noqa: S105  # pragma: allowlist secret
        self.notes = "reviewed release notes\n"
        git = shutil.which("git")
        if git is None:
            raise RuntimeError("required test command is unavailable: git")
        self.git = git
        self.python = str(Path(sys.executable).resolve())

        self.asset_dir.mkdir(parents=True)
        self.notes_path.parent.mkdir(parents=True)
        self.notes_path.write_text(self.notes, encoding="utf-8")
        self.output_path.touch()
        self.fake_bin.mkdir()
        self.home.mkdir()
        self._install_commands()
        self._write_executable(
            "gh",
            f'exec {shlex.quote(self.python)} {shlex.quote(str(FAKE_GH))} "$@"',
        )
        self._write_executable(
            "python3",
            f'exec {shlex.quote(self.python)} {shlex.quote(str(FAKE_PYTHON))} "$@"',
        )
        for command in ("curl",):
            self._write_executable(
                command,
                (
                    f"exec {shlex.quote(self.python)} "
                    f'{shlex.quote(str(FAKE_PYPI_CLI))} {command} "$@"'
                ),
            )
        self._write_executable("sleep", ":")
        self._write_state(self._initial_state())

    def _initial_state(self) -> dict[str, Any]:
        tag_object_sha = "b" * 40
        return {
            "repository": "vexcalibur-dev/vexcalibur",
            "release_tag": self.release_tag,
            "release_sha": self.release_sha,
            "release_id": 123,
            "release": None,
            "app_slug": self.app_slug,
            "bot_user_id": self.bot_user_id,
            "read_token": self.read_token,
            "write_token": self.write_token,
            "main_sha": self.main_sha,
            "comparison_status": "identical",
            "tag_object_sha": tag_object_sha,
            "tag_ref": {
                "ref": f"refs/tags/{self.release_tag}",
                "object": {"type": "tag", "sha": tag_object_sha},
            },
            "tag_object": self._tag_object(self.release_sha),
            "immutable_policy": True,
            "publication_completes": True,
            "publication_polls_remaining": 0,
            "concurrent_create": False,
            "graphql_responses": [],
            "graphql_scripted": False,
            "rest_lookup_id": None,
            "next_asset_id": 1000,
            "upload_mode": "complete",
            "upload_exit": 0,
            "starter_uploads_remaining": 0,
            "verify_release_failures": 0,
            "verify_asset_failures": 0,
            "pypi_http_status": 200,
            "pypi_response": {},
            "run_id": "987654321",
            "run_artifacts": [
                {
                    "name": f"release-assets-{self.release_sha}",
                    "digest": "d" * 64,
                    "expired": False,
                }
            ],
            "authentication_failures": 0,
            "policy_responses": [],
            "policy_failures": [],
            "allowed_asset_roots": [str(self.asset_dir.resolve())],
            "calls": [],
            "unmodeled_calls": [],
        }

    def _tag_object(self, release_sha: str) -> dict[str, Any]:
        notes_sha256 = hashlib.sha256(self.notes.encode()).hexdigest()
        tag_message = json.dumps(
            {
                "schema_version": 1,
                "tag": self.release_tag,
                "release_notes_sha256": notes_sha256,
                "release_notes": self.notes,
            },
            separators=(",", ":"),
        )
        return {
            "tag": self.release_tag,
            "message": tag_message,
            "object": {"type": "commit", "sha": release_sha},
            "tagger": {
                "name": f"{self.app_slug}[bot]",
                "email": f"{self.bot_user_id}+{self.app_slug}[bot]@users.noreply.github.com",
            },
        }

    def _install_commands(self) -> None:
        for command in SYSTEM_COMMANDS:
            target = self._resolve_command(command)
            if target is None:
                raise RuntimeError(f"required test command is unavailable: {command}")
            destination = self.fake_bin / command
            destination.symlink_to(target)

    @staticmethod
    def _resolve_command(command: str) -> str | None:
        target = shutil.which(command)
        if command != "uv" or target is None or "/shims/" not in target:
            return None if target is None else str(Path(target).resolve())
        for manager in ("asdf", "mise", "pyenv"):
            manager_path = shutil.which(manager)
            if manager_path is None:
                continue
            completed = subprocess.run(  # noqa: S603 - resolved version-manager executable
                [manager_path, "which", command],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            resolved = completed.stdout.strip()
            if completed.returncode == 0 and Path(resolved).is_file():
                return str(Path(resolved).resolve())
        return str(Path(target).resolve())

    def _write_executable(self, name: str, body: str) -> None:
        path = self.fake_bin / name
        path.write_text(f"#!/bin/bash\nset -euo pipefail\n{body}\n", encoding="utf-8")
        path.chmod(0o755)

    def _write_state(self, state: dict[str, Any]) -> None:
        self._validate_state(state)
        self.state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")

    def _validate_state(self, state: dict[str, Any]) -> None:
        if set(state) != set(self._initial_state()):
            raise ValueError("fake GitHub state fields differ from the declared schema")
        string_fields = (
            "repository",
            "release_tag",
            "release_sha",
            "app_slug",
            "main_sha",
            "comparison_status",
            "tag_object_sha",
            "upload_mode",
            "read_token",
            "write_token",
            "run_id",
        )
        integer_fields = (
            "release_id",
            "bot_user_id",
            "next_asset_id",
            "upload_exit",
            "starter_uploads_remaining",
            "verify_release_failures",
            "verify_asset_failures",
            "pypi_http_status",
            "publication_polls_remaining",
            "authentication_failures",
        )
        boolean_fields = (
            "immutable_policy",
            "publication_completes",
            "concurrent_create",
            "graphql_scripted",
        )
        if not all(type(state[field]) is str for field in string_fields):
            raise ValueError("fake GitHub string state is malformed")
        if not all(type(state[field]) is int for field in integer_fields):
            raise ValueError("fake GitHub integer state is malformed")
        if not all(type(state[field]) is bool for field in boolean_fields):
            raise ValueError("fake GitHub boolean state is malformed")
        if state["comparison_status"] not in {"ahead", "behind", "diverged", "identical"}:
            raise ValueError("fake comparison status is malformed")
        if state["upload_mode"] not in {"complete", "missing", "starter-once"}:
            raise ValueError("fake upload mode is malformed")
        if state["publication_polls_remaining"] < 0:
            raise ValueError("fake publication poll count is malformed")
        for field in (
            "allowed_asset_roots",
            "calls",
            "graphql_responses",
            "policy_failures",
            "policy_responses",
            "run_artifacts",
            "unmodeled_calls",
        ):
            if type(state[field]) is not list:
                raise ValueError(f"fake GitHub list state is malformed: {field}")
        if state["release"] is not None and type(state["release"]) is not dict:
            raise ValueError("fake release state is malformed")
        if state["rest_lookup_id"] is not None and type(state["rest_lookup_id"]) is not int:
            raise ValueError("fake REST lookup id is malformed")
        if type(state["pypi_response"]) is not dict:
            raise ValueError("fake PyPI response is malformed")
        if type(state["tag_ref"]) is not dict or type(state["tag_object"]) is not dict:
            raise ValueError("fake tag state is malformed")
        if not all(type(root) is str for root in state["allowed_asset_roots"]):
            raise ValueError("fake asset roots are malformed")
        if not all(
            type(call) is list and all(type(item) is str for item in call)
            for call in state["calls"]
        ):
            raise ValueError("fake recorded calls are malformed")
        if not all(
            type(call) is list and all(type(item) is str for item in call)
            for call in state["unmodeled_calls"]
        ):
            raise ValueError("fake unmodeled calls are malformed")
        if not all(type(value) is bool for value in state["policy_failures"]):
            raise ValueError("fake policy failures are malformed")
        if not all(type(value) is dict for value in state["policy_responses"]):
            raise ValueError("fake policy responses are malformed")
        for artifact in state["run_artifacts"]:
            if type(artifact) is not dict or set(artifact) != {"name", "digest", "expired"}:
                raise ValueError("fake run artifact fields are malformed")
            if type(artifact["name"]) is not str or type(artifact["expired"]) is not bool:
                raise ValueError("fake run artifact state is malformed")
            if type(artifact["digest"]) is not str or not re.fullmatch(
                r"[0-9a-f]{64}", artifact["digest"]
            ):
                raise ValueError("fake run artifact digest is malformed")
        self._validate_tag_state(state)
        if state["release"] is not None:
            self._validate_release(cast(dict[str, Any], state["release"]))

    @staticmethod
    def _validate_tag_state(state: dict[str, Any]) -> None:
        tag_ref = state["tag_ref"]
        tag_object = state["tag_object"]
        if set(tag_ref) != {"ref", "object"} or type(tag_ref["ref"]) is not str:
            raise ValueError("fake tag ref is malformed")
        if type(tag_ref["object"]) is not dict or set(tag_ref["object"]) != {"type", "sha"}:
            raise ValueError("fake tag ref object is malformed")
        if not all(type(tag_ref["object"][field]) is str for field in ("type", "sha")):
            raise ValueError("fake tag ref object values are malformed")
        if set(tag_object) != {"tag", "message", "object", "tagger"}:
            raise ValueError("fake tag object is malformed")
        if not all(type(tag_object[field]) is str for field in ("tag", "message")):
            raise ValueError("fake tag object identity is malformed")
        nested_schemas = {
            "object": {"type", "sha"},
            "tagger": {"name", "email"},
        }
        for field, expected_keys in nested_schemas.items():
            nested = tag_object[field]
            if type(nested) is not dict or set(nested) != expected_keys:
                raise ValueError(f"fake nested tag {field} is malformed")
            if not all(type(nested[key]) is str for key in expected_keys):
                raise ValueError(f"fake nested tag {field} values are malformed")

    @staticmethod
    def _validate_release(release: dict[str, Any]) -> None:
        if set(release) != {
            "id",
            "tag_name",
            "target_commitish",
            "name",
            "body",
            "draft",
            "prerelease",
            "immutable",
            "author",
            "_assets",
        }:
            raise ValueError("fake release fields are malformed")
        if type(release["id"]) is not int or not all(
            type(release[field]) is str
            for field in ("tag_name", "target_commitish", "name", "body")
        ):
            raise ValueError("fake release identity is malformed")
        if not all(type(release[field]) is bool for field in ("draft", "prerelease")):
            raise ValueError("fake release state is malformed")
        if release["immutable"] is not None and type(release["immutable"]) is not bool:
            raise ValueError("fake release immutable state is malformed")
        if type(release["author"]) is not dict or type(release["author"].get("login")) is not str:
            raise ValueError("fake release author is malformed")
        assets = release["_assets"]
        if type(assets) is not list:
            raise ValueError("fake release assets are malformed")
        required = {"id", "name", "size", "state", "uploader", "label", "_bytes"}
        for asset in assets:
            if type(asset) is not dict or set(asset) != required:
                raise ValueError("fake release asset fields are malformed")
            if type(asset["id"]) is not int or type(asset["size"]) is not int:
                raise ValueError("fake release asset numbers are malformed")
            if not all(type(asset[field]) is str for field in ("name", "state", "_bytes")):
                raise ValueError("fake release asset state is malformed")
            if (
                type(asset["uploader"]) is not dict
                or type(asset["uploader"].get("login")) is not str
            ):
                raise ValueError("fake release asset uploader is malformed")
            if asset["label"] is not None and type(asset["label"]) is not str:
                raise ValueError("fake release asset label is malformed")

    @property
    def state(self) -> dict[str, Any]:
        value = json.loads(self.state_path.read_text(encoding="utf-8"))
        if type(value) is not dict:
            raise ValueError("fake GitHub state must be a JSON object")
        state = cast(dict[str, Any], value)
        self._validate_state(state)
        return state

    def update_state(self, **changes: object) -> None:
        state = self.state
        unknown = set(changes).difference(state)
        if unknown:
            raise ValueError(f"unknown fake GitHub state: {sorted(unknown)}")
        forbidden = set(changes).intersection(IMMUTABLE_STATE_KEYS)
        if forbidden:
            raise ValueError(f"use a dedicated identity method for: {sorted(forbidden)}")
        state.update(changes)
        self._write_state(state)

    def configure_commits(self, *, release_sha: str, main_sha: str) -> None:
        self.release_sha = release_sha
        self.main_sha = main_sha
        state = self.state
        state["release_sha"] = release_sha
        state["main_sha"] = main_sha
        state["comparison_status"] = "identical" if release_sha == main_sha else "ahead"
        state["tag_object"] = self._tag_object(release_sha)
        for artifact in state["run_artifacts"]:
            artifact["name"] = f"release-assets-{release_sha}"
        self._write_state(state)

    def configure_tag_state(
        self,
        *,
        tag_ref: dict[str, Any] | None = None,
        tag_object: dict[str, Any] | None = None,
    ) -> None:
        state = self.state
        if tag_ref is not None:
            state["tag_ref"] = tag_ref
        if tag_object is not None:
            state["tag_object"] = tag_object
        self._write_state(state)

    def allow_asset_root(self, path: Path) -> None:
        state = self.state
        resolved = str(path.resolve())
        if resolved not in state["allowed_asset_roots"]:
            state["allowed_asset_roots"].append(resolved)
        self._write_state(state)

    def contract_release(self, *, published: bool = False) -> dict[str, Any]:
        return {
            "id": 123,
            "tag_name": self.release_tag,
            "target_commitish": self.release_sha,
            "name": self.release_tag,
            "body": self.notes,
            "draft": not published,
            "prerelease": False,
            "immutable": published,
            "author": {"login": f"{self.app_slug}[bot]"},
            "_assets": [],
        }

    def write_asset(
        self, name: str = "vexcalibur-1.2.3.tar.gz", contents: bytes = b"asset\n"
    ) -> Path:
        path = self.asset_dir / name
        path.write_bytes(contents)
        return path

    def prepare_validated_assets(self) -> dict[str, str]:
        """Create the bounded flat artifact expected by the publisher trust gate."""
        self.write_asset()
        manifest = self.write_asset("manifest.json", b'{"schema_version":2}\n')
        checksum = self.asset_dir / "SHA256SUMS"
        lines = []
        for path in sorted(path for path in self.asset_dir.iterdir() if path != checksum):
            lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n")
        checksum.write_text("".join(lines), encoding="utf-8")
        state = self.state
        artifact = state["run_artifacts"][0]
        return {
            "artifact_name": cast(str, artifact["name"]),
            "artifact_digest": f"sha256:{artifact['digest']}",
            "checksum_sha256": hashlib.sha256(checksum.read_bytes()).hexdigest(),
            "notes_sha256": hashlib.sha256(self.notes.encode()).hexdigest(),
            "manifest_name": manifest.name,
        }

    def add_remote_asset(
        self,
        local_path: Path,
        *,
        contents: bytes | None = None,
        uploader: str | None = None,
        state_name: str = "uploaded",
    ) -> None:
        state = self.state
        release = state["release"]
        if release is None:
            raise ValueError("a release is required before adding an asset")
        remote_contents = local_path.read_bytes() if contents is None else contents
        release["_assets"].append(
            {
                "id": state["next_asset_id"],
                "name": local_path.name,
                "size": len(remote_contents),
                "state": state_name,
                "uploader": {"login": uploader or f"{self.app_slug}[bot]"},
                "label": None,
                "_bytes": base64.b64encode(remote_contents).decode("ascii"),
            }
        )
        state["next_asset_id"] += 1
        self._write_state(state)

    def create_recovery_repository(self) -> Path:
        repository = self.root / "repository"
        repository.mkdir()
        self._git(repository, "init", "--initial-branch=main", "--object-format=sha1")
        scripts = repository / "scripts"
        contract = repository / "release-evidence" / "recovery-contract.json"
        scripts.mkdir()
        contract.parent.mkdir()
        shutil.copyfile(RECOVERY_CHECKER, scripts / RECOVERY_CHECKER.name)
        contract.write_text('{"schema_version":1}\n', encoding="utf-8")
        (repository / "tracked.txt").write_text("release\n", encoding="utf-8")
        release_sha = self._commit(repository, "test: create release")
        self._git(
            repository,
            "-c",
            "user.name=Vexcalibur Test",
            "-c",
            "user.email=vexcalibur@example.test",
            "tag",
            "--annotate",
            self.release_tag,
            "--message",
            "release",
        )
        (repository / "tracked.txt").write_text("main advanced\n", encoding="utf-8")
        main_sha = self._commit(repository, "test: advance main")
        self.configure_commits(release_sha=release_sha, main_sha=main_sha)
        return repository

    def _git(self, repository: Path, *arguments: str) -> str:
        completed = subprocess.run(  # noqa: S603 - resolved Git and test-owned arguments
            [
                self.git,
                "-c",
                "commit.gpgSign=false",
                "-c",
                "tag.gpgSign=false",
                "-c",
                "core.hooksPath=/dev/null",
                *arguments,
            ],
            cwd=repository,
            check=False,
            capture_output=True,
            text=True,
            env=self._git_environment(),
        )
        if completed.returncode != 0:
            raise RuntimeError(f"test Git command failed: {completed.stderr.strip()}")
        return completed.stdout.strip()

    def _git_environment(self) -> dict[str, str]:
        return {
            "GIT_ALLOW_PROTOCOL": "file",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_DEFAULT_HASH": "sha1",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": str(self.home),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": str(self.fake_bin),
            "XDG_CONFIG_HOME": str(self.home / ".config"),
        }

    def _commit(self, repository: Path, message: str) -> str:
        self._git(repository, "add", ".")
        self._git(
            repository,
            "-c",
            "user.name=Vexcalibur Test",
            "-c",
            "user.email=vexcalibur@example.test",
            "commit",
            "-m",
            message,
        )
        return self._git(repository, "rev-parse", "HEAD")

    def run_release_step(
        self,
        job: str,
        name: str,
        *,
        cwd: Path | None = None,
        expression_values: dict[str, str] | None = None,
        runtime_environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return self._run_step(
            _workflow_text(),
            job,
            name,
            cwd=cwd,
            expression_values=expression_values,
            runtime_environment=runtime_environment,
        )

    def run_pypi_step(
        self,
        job: str,
        name: str,
        *,
        cwd: Path | None = None,
        expression_values: dict[str, str] | None = None,
        runtime_environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return self._run_step(
            _pypi_text(),
            job,
            name,
            cwd=cwd,
            expression_values=expression_values,
            runtime_environment=runtime_environment,
        )

    def _run_step(
        self,
        workflow: str,
        job: str,
        name: str,
        *,
        cwd: Path | None,
        expression_values: dict[str, str] | None,
        runtime_environment: dict[str, str] | None,
    ) -> subprocess.CompletedProcess[str]:
        self.output_path.write_text("", encoding="utf-8")
        job_text = _job(workflow, job)
        step = _step(job_text, name)
        script = _step_script(step)
        for absolute_command in ("/bin/", "/usr/bin/", "/usr/local/bin/"):
            if absolute_command in script:
                raise ValueError(
                    f"workflow step bypasses the allowlisted command path: {absolute_command}"
                )
        for network_escape in ("/dev/tcp", "/dev/udp", "import socket", "from socket"):
            if network_escape in script:
                raise ValueError(f"workflow step contains a network escape: {network_escape}")
        state = self.state
        unmodeled_count = len(state["unmodeled_calls"])
        authentication_failure_count = state["authentication_failures"]
        environment = {
            **self._git_environment(),
            "GH_TEST_STATE": str(self.state_path),
            "GITHUB_OUTPUT": str(self.output_path),
            "GITHUB_REPOSITORY": cast(str, state["repository"]),
            "GITHUB_RUN_ID": cast(str, state["run_id"]),
            "RUNNER_TEMP": str(self.runner_temp),
            "UV_NO_SYNC": "1",
            "UV_OFFLINE": "1",
        }
        values = expression_values or {}
        step_environment = _step_environment(step)
        declared_environment = {
            **_workflow_environment(workflow),
            **_job_environment(job_text),
            **step_environment,
        }
        for key, raw_value in declared_environment.items():
            match = EXPRESSION.fullmatch(raw_value)
            if match is None:
                environment[key] = raw_value
                continue
            expression = match.group(1)
            if expression not in values:
                raise ValueError(f"no value supplied for workflow expression: {expression}")
            environment[key] = values[expression]
        if runtime_environment is not None:
            overlap = set(runtime_environment).intersection(declared_environment)
            if overlap:
                raise ValueError(
                    f"runtime environment overrides workflow bindings: {sorted(overlap)}"
                )
            environment.update(runtime_environment)
        completed = self._run_controlled(
            script,
            cwd=cwd or self.runner_temp,
            environment=environment,
        )
        return self._enforce_fake_contract(
            completed,
            unmodeled_count=unmodeled_count,
            authentication_failure_count=authentication_failure_count,
        )

    def run_test_script(self, script: str) -> subprocess.CompletedProcess[str]:
        """Run a test-owned script under the same fake-command contract."""
        state = self.state
        completed = self._run_controlled(
            script,
            cwd=self.runner_temp,
            environment={
                **self._git_environment(),
                "GH_TEST_STATE": str(self.state_path),
                "GH_TOKEN": self.write_token,
                "RUNNER_TEMP": str(self.runner_temp),
                "UV_NO_SYNC": "1",
                "UV_OFFLINE": "1",
            },
        )
        return self._enforce_fake_contract(
            completed,
            unmodeled_count=len(state["unmodeled_calls"]),
            authentication_failure_count=state["authentication_failures"],
        )

    def _enforce_fake_contract(
        self,
        completed: subprocess.CompletedProcess[str],
        *,
        unmodeled_count: int,
        authentication_failure_count: int,
    ) -> subprocess.CompletedProcess[str]:
        final_state = self.state
        if len(final_state["unmodeled_calls"]) != unmodeled_count:
            return subprocess.CompletedProcess(
                completed.args,
                96,
                completed.stdout,
                f"{completed.stderr}workflow invoked an unmodeled command\n",
            )
        if final_state["authentication_failures"] != authentication_failure_count:
            return subprocess.CompletedProcess(
                completed.args,
                97,
                completed.stdout,
                f"{completed.stderr}workflow used the wrong GitHub token\n",
            )
        return completed

    def _run_controlled(
        self,
        script: str,
        *,
        cwd: Path,
        environment: dict[str, str],
    ) -> subprocess.CompletedProcess[str]:
        unsafe_environment = {
            name
            for name in environment
            if name in {"BASH_ENV", "ENV", "PYTHONHOME", "PYTHONPATH", "SHELLOPTS"}
            or name.startswith(("DYLD_", "LD_"))
        }
        if unsafe_environment:
            raise ValueError(
                f"workflow declares unsafe process environment: {sorted(unsafe_environment)}"
            )
        environment["TMPDIR"] = str(self.root / "tmp")
        (self.root / "tmp").mkdir(exist_ok=True)
        arguments = ["/bin/bash", "-c", script]
        process = subprocess.Popen(  # noqa: S603 - checked-in workflow shell under fake PATH
            arguments,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=WORKFLOW_TEST_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
            return subprocess.CompletedProcess(
                arguments,
                124,
                stdout,
                f"{stderr}workflow step exceeded the test timeout\n",
            )
        return subprocess.CompletedProcess(
            arguments,
            process.returncode,
            stdout,
            stderr,
        )

    def outputs(self) -> dict[str, str]:
        values: dict[str, str] = {}
        for line in self.output_path.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if not separator or not key or key in values:
                raise ValueError(f"invalid workflow output line: {line!r}")
            values[key] = value
        return values

    def calls(self, *prefix: str) -> list[list[str]]:
        calls = self.state["calls"]
        return [call for call in calls if call[: len(prefix)] == list(prefix)]
