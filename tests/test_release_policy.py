"""Behavioral tests for the checkout-free release policy preflight."""

from __future__ import annotations

import json
import os
import re
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def _job(text: str, name: str) -> str:
    pattern = rf"(?ms)^  {re.escape(name)}:\n.*?(?=^  [a-z0-9][a-z0-9-]*:\n|\Z)"
    match = re.search(pattern, text)
    assert match is not None, f"release workflow has no {name!r} job"
    return match.group(0)


def _step(job: str, name: str) -> str:
    pattern = rf"(?ms)^      - name: {re.escape(name)}\n.*?(?=^      - name: |\Z)"
    match = re.search(pattern, job)
    assert match is not None, f"workflow job has no {name!r} step"
    return match.group(0)


def _step_script(step: str) -> str:
    marker = "        run: |\n"
    assert marker in step
    return textwrap.dedent(step.partition(marker)[2])


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
arguments=" $* "
if [[ "${arguments}" == *"/immutable-releases "* ]]; then
  count=0
  if [[ -f "${GH_POLICY_STATE}/count" ]]; then
    count="$(cat "${GH_POLICY_STATE}/count")"
  fi
  count=$((count + 1))
  printf '%s\n' "${count}" > "${GH_POLICY_STATE}/count"
  if [[ -f "${GH_POLICY_STATE}/fail-${count}" ]]; then
    echo "simulated policy request failure" >&2
    exit 1
  fi
  response="${GH_POLICY_STATE}/policy-${count}.json"
  if [[ ! -f "${response}" ]]; then
    response="${GH_POLICY_STATE}/policy.json"
  fi
  query=""
  previous=""
  for argument in "$@"; do
    if [[ "${previous}" == "--jq" ]]; then
      query="${argument}"
      break
    fi
    previous="${argument}"
  done
  [[ -n "${query}" ]] || exit 97
  jq -r "${query}" "${response}"
  exit
fi
if [[ "${arguments}" == *"/git/ref/heads/main "* ]]; then
  printf '{"object":{"sha":"%s"}}\n' "${RELEASE_SHA}" | jq -r .object.sha
  exit
fi
exit 96
""",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    return fake_bin, state


def _write_policy(path: Path, *, enabled: object, enforced: object) -> None:
    path.write_text(
        json.dumps({"enabled": enabled, "enforced_by_owner": enforced}),
        encoding="utf-8",
    )


def _run_preflight(
    tmp_path: Path,
    fake_bin: Path,
    state: Path,
) -> subprocess.CompletedProcess[str]:
    runner_temp = tmp_path / "runner"
    runner_temp.mkdir(exist_ok=True)
    step = _step(
        _job(WORKFLOW.read_text(encoding="utf-8"), "publish-release"),
        "Preflight immutable release policy and target",
    )
    return subprocess.run(  # noqa: S603 - reviewed workflow with a test-owned gh stub
        ["/bin/bash", "-c", _step_script(step)],
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
            "RELEASE_MODE": "normal",
            "RELEASE_SHA": "a" * 40,
            "RELEASE_TAG": "v1.2.3",
            "GH_TOKEN": "test-token",  # pragma: allowlist secret
        },
    )


def test_preflight_accepts_boolean_owner_enforcement(tmp_path: Path) -> None:
    fake_bin, state = _fake_gh(tmp_path)
    _write_policy(state / "policy.json", enabled=True, enforced=True)

    completed = _run_preflight(tmp_path, fake_bin, state)

    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    ("enabled", "enforced"),
    (
        (False, True),
        (True, False),
        ("true", True),
        (True, "true"),
        (True, None),
    ),
)
def test_preflight_rejects_disabled_or_malformed_policy(
    tmp_path: Path,
    enabled: object,
    enforced: object,
) -> None:
    fake_bin, state = _fake_gh(tmp_path)
    _write_policy(state / "policy.json", enabled=enabled, enforced=enforced)

    completed = _run_preflight(tmp_path, fake_bin, state)

    assert completed.returncode == 1
    assert "not enabled and owner-enforced" in completed.stderr


def test_preflight_rejects_policy_request_failure(tmp_path: Path) -> None:
    fake_bin, state = _fake_gh(tmp_path)
    _write_policy(state / "policy.json", enabled=True, enforced=True)
    (state / "fail-1").touch()

    completed = _run_preflight(tmp_path, fake_bin, state)

    assert completed.returncode == 1
    assert "Could not preflight" in completed.stderr
    assert "simulated policy request failure" in completed.stderr


def test_repeated_preflight_detects_policy_drift(tmp_path: Path) -> None:
    fake_bin, state = _fake_gh(tmp_path)
    _write_policy(state / "policy-1.json", enabled=True, enforced=True)
    _write_policy(state / "policy-2.json", enabled=False, enforced=True)

    first = _run_preflight(tmp_path, fake_bin, state)
    second = _run_preflight(tmp_path, fake_bin, state)

    assert first.returncode == 0, first.stderr
    assert second.returncode == 1
    assert "not enabled and owner-enforced" in second.stderr
