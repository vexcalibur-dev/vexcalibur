"""Behavioral tests for CI publication and concurrency contracts."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_VALIDATION_WORKFLOW = ROOT / ".github" / "workflows" / "release-validation.yml"
PREPARE_TAG = ROOT / "scripts" / "prepare-local-release-tag.sh"
RESOLVE_VERSION = ROOT / "scripts" / "resolve-publication-version.sh"
GIT = "/usr/bin/git"


def _job(text: str, name: str) -> str:
    pattern = rf"(?ms)^  {re.escape(name)}:\n.*?(?=^  [a-z0-9][a-z0-9-]*:\n|\Z)"
    match = re.search(pattern, text)
    assert match is not None, f"workflow has no {name!r} job"
    return match.group(0)


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(  # noqa: S603 - fixed Git binary and test-owned repository
        [GIT, *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _concurrency_key(
    event_name: str,
    *,
    scheduled_profile: bool = False,
    live_services: bool = False,
) -> str:
    return (
        f"ci-CI-refs/heads/main-{event_name}-"
        f"{str(scheduled_profile).lower()}-{str(live_services).lower()}"
    )


def test_ci_concurrency_key_uses_event_and_profile_inputs() -> None:
    ci = CI_WORKFLOW.read_text(encoding="utf-8")
    concurrency = ci.partition("\nconcurrency:\n")[2].partition("\npermissions:\n")[0]
    normalized = re.sub(r"\s+", "", concurrency)

    assert (
        "group:>-ci-${{github.workflow}}-"
        "${{github.event.pull_request.number||github.ref}}-"
        "${{github.event_name}}-"
        "${{inputs.run_scheduled_profile||false}}-"
        "${{inputs.run_live_services||false}}"
    ) in normalized
    assert "cancel-in-progress:true" in normalized


@pytest.mark.parametrize(
    ("first", "second"),
    (
        (
            _concurrency_key("push"),
            _concurrency_key("schedule"),
        ),
        (
            _concurrency_key("push"),
            _concurrency_key("workflow_dispatch", live_services=True),
        ),
        (
            _concurrency_key("workflow_dispatch", scheduled_profile=True),
            _concurrency_key("workflow_dispatch", live_services=True),
        ),
    ),
)
def test_live_and_standard_ci_profiles_do_not_cancel_each_other(
    first: str,
    second: str,
) -> None:
    assert first != second


def test_same_ci_profile_supersedes_an_older_run() -> None:
    assert _concurrency_key("push") == _concurrency_key("push")
    assert _concurrency_key(
        "workflow_dispatch",
        live_services=True,
    ) == _concurrency_key("workflow_dispatch", live_services=True)


def test_ci_passes_a_resolved_tag_snapshot_to_publication_validation() -> None:
    ci = CI_WORKFLOW.read_text(encoding="utf-8")
    result = _job(ci, "ci")
    version = _job(ci, "publication-version")
    publication = _job(ci, "publication-contract")

    assert "scripts/resolve-publication-version.sh" in version
    assert "fetch-depth: 0" in version
    assert "persist-credentials: false" in version
    assert "synthetic: ${{ steps.version.outputs.synthetic }}" in version
    assert "uses: ./.github/workflows/release-validation.yml" in publication
    assert "needs: publication-version" in publication
    assert "release-sha: ${{ github.sha }}" in publication
    assert "release-tag: ${{ needs.publication-version.outputs.tag }}" in publication
    assert "release-version: ${{ needs.publication-version.outputs.version }}" in publication
    assert (
        "release-tag-is-synthetic: ${{ needs.publication-version.outputs.synthetic == 'true' }}"
    ) in publication
    assert "publication-only: true" in publication
    assert "unprivileged-ci-contract: true" in publication
    assert "allow-public-evidence-upload: true" in publication
    assert "needs.publication-contract.result" in result


def test_installed_cli_job_installs_its_selected_python() -> None:
    installed = _job(CI_WORKFLOW.read_text(encoding="utf-8"), "installed-cli")

    assert 'uv python install "${MAX_PYTHON}"' in installed


def test_synthetic_publication_contract_isolated_from_later_remote_tag(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "--initial-branch=main")
    _git(repository, "config", "user.name", "Release Test")
    _git(repository, "config", "user.email", "release-test@example.test")
    (repository / "tracked.txt").write_text("release\n", encoding="utf-8")
    _git(repository, "add", "tracked.txt")
    _git(repository, "commit", "-m", "release")
    release_sha = _git(repository, "rev-parse", "HEAD")

    resolved = subprocess.run(  # noqa: S603 - reviewed script and test-owned repository
        [str(RESOLVE_VERSION), release_sha],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    assert resolved.stdout.startswith("synthetic=true\n")

    _git(repository, "tag", "--annotate", "v9.9.9", "--message", "concurrent release")
    checkout = tmp_path / "checkout"
    subprocess.run(  # noqa: S603 - fixed Git binary and test-owned repository
        [
            GIT,
            "clone",
            "--depth=1",
            "--no-tags",
            "--branch=main",
            repository.as_uri(),
            str(checkout),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert _git(checkout, "tag", "--list") == ""

    subprocess.run(  # noqa: S603 - reviewed script and test-owned repository
        [str(PREPARE_TAG), "v0.0.0", release_sha, sys.executable],
        cwd=checkout,
        check=True,
        capture_output=True,
        text=True,
    )

    assert _git(checkout, "tag", "--list") == "v0.0.0"


def test_release_validation_requires_explicit_public_evidence_upload_consent() -> None:
    validation = RELEASE_VALIDATION_WORKFLOW.read_text(encoding="utf-8")
    consent = _job(validation, "consent")

    assert "allow-public-evidence-upload:" in validation
    assert "required: true" in validation
    assert "ALLOW_PUBLIC_EVIDENCE_UPLOAD" in consent
    assert "explicit consent to upload public evidence" in consent
    assert "needs: consent" in _job(validation, "build")
    assert "UNPRIVILEGED_CI_CONTRACT" in consent
    assert "matching tag and version inputs" in consent
    assert "RELEASE_TAG_IS_SYNTHETIC" in consent
    assert "A synthetic tag requires the unprivileged v0.0.0 CI contract." in consent
    assert "The local v0.0.0 CI contract requires an isolated tag snapshot." in consent
