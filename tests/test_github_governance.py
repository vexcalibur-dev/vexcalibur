"""Tests for the read-only GitHub governance drift checker."""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest

FIXTURE = Path("tests/fixtures/governance/expected.json")
SCRIPT = Path("scripts/check_github_governance.py")
SPEC = importlib.util.spec_from_file_location("check_github_governance", SCRIPT)
assert SPEC is not None
assert SPEC.loader is not None
governance = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = governance
SPEC.loader.exec_module(governance)


def test_expected_snapshot_matches_policy() -> None:
    snapshot = governance.load_snapshot(FIXTURE)

    assert governance.validate_snapshot(snapshot) == ()


def test_offline_cli_accepts_expected_snapshot(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = governance.main(["--snapshot", str(FIXTURE)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out == "GitHub governance matches the committed Vexcalibur policy.\n"
    assert captured.err == ""


def test_validation_reports_security_relevant_drift_deterministically(tmp_path: Path) -> None:
    raw = cast(dict[str, object], json.loads(FIXTURE.read_text(encoding="utf-8")))
    mutated = copy.deepcopy(raw)
    repositories = cast(dict[str, list[dict[str, object]]], mutated["repository_rulesets"])

    core_branch = repositories["vexcalibur"][0]
    core_rules = cast(list[dict[str, object]], core_branch["rules"])
    status_parameters = cast(dict[str, object], core_rules[3]["parameters"])
    checks = cast(list[dict[str, object]], status_parameters["required_status_checks"])
    checks[0]["integration_id"] = 0

    core_immutable = repositories["vexcalibur"][2]
    core_immutable["rules"] = [{"type": "deletion"}]

    actions = cast(dict[str, object], mutated["organization_actions_permissions"])
    actions["sha_pinning_required"] = False

    repository_settings = cast(dict[str, dict[str, object]], mutated["repositories"])
    repository_settings[".github"]["default_branch"] = "trunk"
    orb = repository_settings["vexcalibur-orb"]
    security = cast(dict[str, object], orb["security_and_analysis"])
    secret_scanning = cast(dict[str, object], security["secret_scanning"])
    secret_scanning["status"] = "disabled"

    codeql = cast(dict[str, dict[str, object]], mutated["codeql_default_setups"])
    codeql["vexcalibur-orb"]["threat_model"] = "remote"

    deployment = cast(dict[str, object], mutated["pypi_deployment_branch_policies"])
    policies = cast(list[dict[str, object]], deployment["branch_policies"])
    policies[0]["name"] = "main"

    path = tmp_path / "drift.json"
    path.write_text(json.dumps(mutated), encoding="utf-8")
    violations = governance.validate_snapshot(governance.load_snapshot(path))

    assert violations == tuple(sorted(violations))
    assert len(violations) == 7
    assert any(".github default branch" in violation for violation in violations)
    assert any(
        "vexcalibur default-branch ruleset required checks" in violation
        and '["CI result",0]' in violation
        for violation in violations
    )
    assert any("immutable release-tag ruleset rule types" in violation for violation in violations)
    assert any("organization Actions SHA pinning" in violation for violation in violations)
    assert any("vexcalibur-orb secret_scanning" in violation for violation in violations)
    assert any(
        "vexcalibur-orb CodeQL default setup threat model" in violation for violation in violations
    )
    assert any("pypi deployment policies" in violation for violation in violations)


def test_missing_required_ruleset_is_a_violation(tmp_path: Path) -> None:
    raw = cast(dict[str, object], json.loads(FIXTURE.read_text(encoding="utf-8")))
    repositories = cast(dict[str, list[dict[str, object]]], raw["repository_rulesets"])
    repositories["vexcalibur-action"] = [
        ruleset
        for ruleset in repositories["vexcalibur-action"]
        if ruleset["name"] != governance.BRANCH_RULESET_NAME
    ]
    path = tmp_path / "missing.json"
    path.write_text(json.dumps(raw), encoding="utf-8")

    violations = governance.validate_snapshot(governance.load_snapshot(path))

    assert (
        "vexcalibur-action ruleset 'protected main (PR + CI)': expected exactly one, got 0"
        in violations
    )


def test_malformed_nested_policy_fails_closed(tmp_path: Path) -> None:
    raw = cast(dict[str, object], json.loads(FIXTURE.read_text(encoding="utf-8")))
    repositories = cast(dict[str, list[dict[str, object]]], raw["repository_rulesets"])
    branch_bypasses = cast(list[object], repositories["vexcalibur"][0]["bypass_actors"])
    branch_bypasses.append("malformed actor silently discarded")
    path = tmp_path / "malformed.json"
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(governance.GovernanceReadError, match="non-object item"):
        governance.validate_snapshot(governance.load_snapshot(path))


def test_missing_nested_policy_field_fails_closed(tmp_path: Path) -> None:
    raw = cast(dict[str, object], json.loads(FIXTURE.read_text(encoding="utf-8")))
    repositories = cast(dict[str, list[dict[str, object]]], raw["repository_rulesets"])
    del repositories["vexcalibur"][0]["bypass_actors"]
    path = tmp_path / "missing-nested-field.json"
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(governance.GovernanceReadError, match="array of objects"):
        governance.validate_snapshot(governance.load_snapshot(path))


def test_gh_api_failure_omits_command_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(governance.shutil, "which", lambda _executable: "/usr/bin/gh")
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(
            args=["gh", "api"],
            returncode=1,
            stdout="",
            stderr="authentication failed for GH_TOKEN=do-not-print",
        )

    monkeypatch.setattr(governance.subprocess, "run", fake_run)

    with pytest.raises(governance.GovernanceReadError) as captured:
        governance.GhApiClient().get("repos/vexcalibur-dev/vexcalibur")

    assert "do-not-print" not in str(captured.value)
    assert "GitHub endpoint was inaccessible" in str(captured.value)
    assert commands == [
        [
            "/usr/bin/gh",
            "api",
            "--hostname",
            "github.com",
            "--method",
            "GET",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "X-GitHub-Api-Version: 2026-03-10",
            "repos/vexcalibur-dev/vexcalibur",
        ]
    ]


def test_live_read_failure_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class FailingClient:
        def get(self, endpoint: str) -> object:
            raise governance.GovernanceReadError(f"endpoint unavailable: {endpoint}")

    monkeypatch.setattr(governance, "GhApiClient", FailingClient)

    exit_code = governance.main([])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "could not read every required setting" in captured.err


def test_gh_execution_failure_is_credential_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(governance.shutil, "which", lambda _executable: "/usr/bin/gh")

    def fail_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise OSError("credential-bearing process detail must not be copied")

    monkeypatch.setattr(governance.subprocess, "run", fail_run)

    with pytest.raises(governance.GovernanceReadError) as captured:
        governance.GhApiClient().get("repos/vexcalibur-dev/vexcalibur")

    assert str(captured.value) == "the gh CLI could not be executed"
    assert "credential-bearing" not in str(captured.value)
