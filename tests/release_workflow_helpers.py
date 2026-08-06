"""Shared helpers for GitHub release workflow contract tests."""

from __future__ import annotations

import json
import os
import re
import subprocess
import textwrap
from pathlib import Path

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
RELEASE_VALIDATION_WORKFLOW = ROOT / ".github" / "workflows" / "release-validation.yml"
PYPI_WORKFLOW = ROOT / ".github" / "workflows" / "pypi.yml"


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


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


def _workflow_job_dependencies(text: str) -> dict[str, set[str]]:
    jobs_text = text.partition("\njobs:\n")[2]
    job_names = re.findall(r"(?m)^  ([a-z][a-z0-9-]*):\n", jobs_text)
    dependencies: dict[str, set[str]] = {}
    for job_name in job_names:
        job = _job(jobs_text, job_name)
        inline = re.search(r"(?m)^    needs: \[([^\]]+)\]$", job)
        scalar = re.search(r"(?m)^    needs: ([a-z][a-z0-9-]*)$", job)
        block = re.search(
            r"(?ms)^    needs:\n((?:      - [a-z][a-z0-9-]*\n)+)",
            job,
        )
        if inline is not None:
            dependencies[job_name] = {value.strip() for value in inline.group(1).split(",")}
        elif scalar is not None:
            dependencies[job_name] = {scalar.group(1)}
        elif block is not None:
            dependencies[job_name] = set(
                re.findall(r"(?m)^      - ([a-z][a-z0-9-]*)$", block.group(1))
            )
        else:
            dependencies[job_name] = set()
    return dependencies


def _has_job_ancestor(
    dependencies: dict[str, set[str]],
    *,
    job_name: str,
    ancestor: str,
) -> bool:
    pending = list(dependencies[job_name])
    visited: set[str] = set()
    while pending:
        dependency = pending.pop()
        if dependency == ancestor:
            return True
        if dependency in visited:
            continue
        visited.add(dependency)
        pending.extend(dependencies.get(dependency, ()))
    return False


def _run_create_release_step(
    tmp_path: Path,
    *,
    graphql_responses: list[object],
    create_exit: int = 0,
    rest_release_id: int = 123,
) -> tuple[subprocess.CompletedProcess[str], str]:
    runner_temp = tmp_path / "runner"
    notes_path = runner_temp / "release-notes" / "vexcalibur-release-notes.md"
    notes_path.parent.mkdir(parents=True)
    notes_path.write_text("reviewed release notes\n", encoding="utf-8")
    github_output = tmp_path / "github-output"
    github_output.touch()
    gh_test_dir = tmp_path / "gh-test"
    gh_test_dir.mkdir()
    for index, response in enumerate(graphql_responses, start=1):
        (gh_test_dir / f"graphql-{index}.json").write_text(
            json.dumps(response),
            encoding="utf-8",
        )
    (gh_test_dir / "release.json").write_text(
        json.dumps(
            {
                "id": rest_release_id,
                "tag_name": "v1.2.3",
                "target_commitish": "a" * 40,
                "name": "v1.2.3",
                "body": "reviewed release notes\n",
                "draft": True,
                "prerelease": False,
                "immutable": False,
                "author": {"login": "automation[bot]"},
            }
        ),
        encoding="utf-8",
    )

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_gh = fake_bin / "gh"
    fake_gh.write_text(
        """#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${GH_TEST_DIR}/calls"
if [[ "$1" == "api" && "${2:-}" == "graphql" ]]; then
  count=0
  if [[ -f "${GH_TEST_DIR}/query-count" ]]; then
    count="$(cat "${GH_TEST_DIR}/query-count")"
  fi
  count=$((count + 1))
  printf '%s\n' "${count}" > "${GH_TEST_DIR}/query-count"
  response="${GH_TEST_DIR}/graphql-${count}.json"
  [[ -f "${response}" ]] || exit 98
  cat "${response}"
  exit 0
fi
if [[ "$1" == "api" && "${2:-}" == repos/*/releases/123 ]]; then
  cat "${GH_TEST_DIR}/release.json"
  exit 0
fi
if [[ "$1" == "release" && "${2:-}" == "create" ]]; then
  [[ " $* " == *" --verify-tag "* ]] || exit 97
  exit "${GH_CREATE_EXIT}"
fi
exit 96
""",
        encoding="utf-8",
    )
    fake_gh.chmod(0o755)

    step = _step(_job(_workflow_text(), "publish-release"), "Create GitHub Release")
    completed = subprocess.run(  # noqa: S603 - reviewed workflow with a test-owned gh stub
        ["/bin/bash", "-c", _step_script(step)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        env={
            **os.environ,
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_REPOSITORY": "vexcalibur-dev/vexcalibur",
            "GITHUB_OUTPUT": str(github_output),
            "RELEASE_TAG": "v1.2.3",
            "RELEASE_SHA": "a" * 40,
            "APP_SLUG": "automation",
            "GH_TOKEN": "test-token",  # pragma: allowlist secret
            "GH_TEST_DIR": str(gh_test_dir),
            "GH_CREATE_EXIT": str(create_exit),
        },
    )
    calls_path = gh_test_dir / "calls"
    calls = calls_path.read_text(encoding="utf-8") if calls_path.exists() else ""
    return completed, calls


def _validation_text() -> str:
    return RELEASE_VALIDATION_WORKFLOW.read_text(encoding="utf-8")


def _pypi_text() -> str:
    return PYPI_WORKFLOW.read_text(encoding="utf-8")


def _workflow_call_outputs(text: str) -> set[str]:
    start = text.index("    outputs:\n")
    end = text.index("\npermissions:\n", start)
    return set(re.findall(r"(?m)^      ([a-z][a-z0-9-]*):\n", text[start:end]))
