from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "check-immutable-release-policy.sh"


def _fake_gh(tmp_path: Path) -> tuple[Path, Path]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    executable = fake_bin / "gh"
    executable.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${GH_POLICY_STATE}/calls"
count=0
if [[ -f "${GH_POLICY_STATE}/count" ]]; then
  count="$(cat "${GH_POLICY_STATE}/count")"
fi
count=$((count + 1))
printf '%s\n' "${count}" > "${GH_POLICY_STATE}/count"
response="${GH_POLICY_STATE}/response-${count}.json"
if [[ ! -f "${response}" ]]; then
  response="${GH_POLICY_STATE}/response.json"
fi
if [[ -f "${GH_POLICY_STATE}/fail-${count}" ]]; then
  echo "simulated policy request failure" >&2
  exit 1
fi
cat "${response}"
""",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return fake_bin, state


def _run_policy_check(
    tmp_path: Path,
    fake_bin: Path,
    state: Path,
) -> subprocess.CompletedProcess[str]:
    runner_temp = tmp_path / "runner"
    runner_temp.mkdir(exist_ok=True)
    return subprocess.run(  # noqa: S603 - reviewed script with a test-owned gh stub
        [str(SCRIPT)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "GH_POLICY_STATE": str(state),
            "GITHUB_REPOSITORY": "vexcalibur-dev/vexcalibur",
            "RUNNER_TEMP": str(runner_temp),
        },
    )


def _write_response(path: Path, *, enabled: object, enforced: object) -> None:
    path.write_text(
        json.dumps({"enabled": enabled, "enforced_by_owner": enforced}),
        encoding="utf-8",
    )


def test_accepts_owner_enforced_immutable_releases(tmp_path: Path) -> None:
    fake_bin, state = _fake_gh(tmp_path)
    _write_response(state / "response.json", enabled=True, enforced=True)

    completed = _run_policy_check(tmp_path, fake_bin, state)

    assert completed.returncode == 0, completed.stderr
    calls = (state / "calls").read_text(encoding="utf-8")
    assert "repos/vexcalibur-dev/vexcalibur/immutable-releases" in calls
    assert "X-GitHub-Api-Version: 2026-03-10" in calls


@pytest.mark.parametrize(
    ("enabled", "enforced"),
    (
        (False, True),
        (True, False),
        ("true", True),
        (True, None),
    ),
)
def test_rejects_disabled_or_malformed_policy(
    tmp_path: Path,
    enabled: object,
    enforced: object,
) -> None:
    fake_bin, state = _fake_gh(tmp_path)
    _write_response(state / "response.json", enabled=enabled, enforced=enforced)

    completed = _run_policy_check(tmp_path, fake_bin, state)

    assert completed.returncode == 1
    assert "not enabled and owner-enforced" in completed.stderr


def test_recheck_detects_policy_drift(tmp_path: Path) -> None:
    fake_bin, state = _fake_gh(tmp_path)
    _write_response(state / "response-1.json", enabled=True, enforced=True)
    _write_response(state / "response-2.json", enabled=False, enforced=True)

    first = _run_policy_check(tmp_path, fake_bin, state)
    second = _run_policy_check(tmp_path, fake_bin, state)

    assert first.returncode == 0, first.stderr
    assert second.returncode == 1
    assert "not enabled and owner-enforced" in second.stderr


def test_rejects_an_unreadable_policy_endpoint(tmp_path: Path) -> None:
    fake_bin, state = _fake_gh(tmp_path)
    _write_response(state / "response.json", enabled=True, enforced=True)
    (state / "fail-1").touch()

    completed = _run_policy_check(tmp_path, fake_bin, state)

    assert completed.returncode == 1
    assert "Could not verify" in completed.stderr
    assert "simulated policy request failure" in completed.stderr
