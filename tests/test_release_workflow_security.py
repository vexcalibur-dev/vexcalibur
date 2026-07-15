"""Security-contract tests for the GitHub release workflow."""

from __future__ import annotations

import re
from pathlib import Path

WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "release.yml"
PYPI_WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "pypi.yml"


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _job(text: str, name: str) -> str:
    pattern = rf"(?ms)^  {re.escape(name)}:\n.*?(?=^  [a-z0-9][a-z0-9-]*:\n|\Z)"
    match = re.search(pattern, text)
    assert match is not None, f"release workflow has no {name!r} job"
    return match.group(0)


def test_release_note_scanner_is_credentialless_and_isolated() -> None:
    text = _workflow_text()
    generate = _job(text, "generate-release-notes")
    scan = _job(text, "scan-release-notes")
    publish = _job(text, "publish-release")

    assert "secrets.AUTOMATION_SECRET" in generate
    assert "detect-secrets-hook" not in generate

    assert "detect-secrets-hook" in scan
    assert "create-github-app-token" not in scan
    assert "${{ secrets." not in scan
    assert "enable-cache: false" in scan

    assert "detect-secrets-hook" not in publish
    assert "uv sync" not in publish
    assert "setup-uv" not in publish
    assert "secrets.AUTOMATION_SECRET" in publish

    assert text.count("detect-secrets-hook") == 1
    assert text.count("secrets.AUTOMATION_SECRET") == 2


def test_publisher_verifies_the_scanned_artifact_before_minting_token() -> None:
    publish = _job(_workflow_text(), "publish-release")

    assert "- generate-release-notes" in publish
    assert "- scan-release-notes" in publish
    download = publish.index("name: Download scanned release notes")
    verify = publish.index("name: Verify scanned release notes")
    token = publish.index("name: Generate app token")
    tag = publish.index("name: Create release tag")
    release = publish.index("name: Create GitHub Release")
    assert download < verify < token < tag < release

    assert "GENERATED_NOTES_SHA256" in publish
    assert "SCANNED_NOTES_SHA256" in publish
    assert "sha256sum" in publish
    assert '--notes-file "${RUNNER_TEMP}/release-notes/' in publish


def test_release_notes_keep_one_digest_across_all_jobs() -> None:
    text = _workflow_text()
    generate = _job(text, "generate-release-notes")
    scan = _job(text, "scan-release-notes")
    publish = _job(text, "publish-release")

    artifact_name = "release-notes-${{ needs.validation.outputs.sha }}"
    assert artifact_name in generate
    assert artifact_name in scan
    assert artifact_name in publish
    assert "notes-sha256: ${{ steps.notes.outputs.sha256 }}" in generate
    assert "EXPECTED_NOTES_SHA256" in scan
    assert "notes-sha256: ${{ steps.verify-notes.outputs.sha256 }}" in scan
    assert "Generated and scanned release-note digests disagree." in publish


def test_pypi_re_resolves_the_validated_tag_immediately_before_publish() -> None:
    text = PYPI_WORKFLOW.read_text(encoding="utf-8")
    re_resolve = text.index("name: Re-resolve validated release tag")
    publish = text.index("name: Publish distributions")

    assert re_resolve < publish
    boundary = text[re_resolve:publish]
    assert "needs.validation.outputs.sha" in boundary
    assert "needs.validation.outputs.tag" in boundary
    assert "/git/ref/tags/${RELEASE_TAG}" in boundary
    assert "/git/ref/heads/main" in boundary
    assert 'object_type}" != "commit"' in boundary
