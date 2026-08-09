"""Structural contract tests for release workflow extraction."""

from __future__ import annotations

import pytest

from tests.release_workflow_helpers import (
    _job,
    _job_condition,
    _job_environment,
    _job_step_names,
    _pypi_text,
    _step,
    _step_environment,
    _workflow_environment,
    _workflow_text,
)


def _assert_ordered_subsequence(actual: list[str], expected: tuple[str, ...]) -> None:
    indexes = [actual.index(name) for name in expected]
    assert indexes == sorted(indexes)


def test_workflow_environment_parser_rejects_block_scalars() -> None:
    step = """\
      - name: Unsupported environment
        env:
          VALUE: |
            multiline
        run: |
          true
"""

    with pytest.raises(AssertionError, match="block scalars"):
        _step_environment(step)


def test_workflow_environment_parser_models_precedence_and_step_boundaries() -> None:
    workflow = """\
env:
  VALUE: workflow
  QUOTED: 'it''s valid'

  # Comments and blank lines do not end a YAML mapping.
  SYMBOL: '|'
jobs:
  publish:
    env:
      VALUE: job
    steps:
      - name: First
        env:
          VALUE: step
          FIRST_ONLY: present
        run: |
          true
      - name: Second
        env:
          SECOND_ONLY: absent
        run: |
          true
"""
    job = _job(workflow, "publish")
    step = _step(job, "First")

    environment = {
        **_workflow_environment(workflow),
        **_job_environment(job),
        **_step_environment(step),
    }

    assert environment == {
        "VALUE": "step",
        "QUOTED": "it's valid",
        "SYMBOL": "|",
        "FIRST_ONLY": "present",
    }
    assert "SECOND_ONLY" not in step


@pytest.mark.parametrize(
    ("workflow", "expected"),
    (
        ('"env":\n  VALUE: plain # comment\n', {"VALUE": "plain"}),
        ("env : {VALUE: supported}\n", {"VALUE": "supported"}),
    ),
)
def test_workflow_environment_parser_handles_yaml_mapping_syntax(
    workflow: str,
    expected: dict[str, str],
) -> None:
    assert _workflow_environment(workflow) == expected


@pytest.mark.parametrize(
    ("workflow", "error"),
    (
        ("env:\n  VALUE: {CHILD: unsupported}\n", "nested workflow environment"),
        ("env:\n  VALUE: first\n  VALUE: second\n", "duplicate key"),
        ("env:\n  FIRST: value\nenv:\n  SECOND: value\n", "duplicate environment"),
    ),
)
def test_workflow_environment_parser_rejects_ambiguous_or_nested_values(
    workflow: str,
    error: str,
) -> None:
    with pytest.raises(AssertionError, match=error):
        _workflow_environment(workflow)


def test_recovery_transitions_are_unique_and_ordered_in_the_workflows() -> None:
    release_job = _job(_workflow_text(), "publish-release")
    _assert_ordered_subsequence(
        _job_step_names(release_job),
        (
            "Verify validated release assets",
            "Verify scanned release notes",
            "Preflight immutable release policy and target",
            "Create release tag",
            "Create GitHub Release",
            "Reconcile exact release assets",
            "Publish immutable GitHub Release",
            "Verify release and every asset attestation",
        ),
    )
    assert _job_condition(release_job) == "needs.resolve.outputs.skip != 'true'"

    pypi_job = _job(_pypi_text(), "publish")
    _assert_ordered_subsequence(
        _job_step_names(pypi_job),
        (
            "Verify exact publication files",
            "Re-resolve validated release tag",
            "Publish distributions",
        ),
    )
    assert _job_condition(pypi_job) == "needs.validation.outputs.publish_needed == 'true'"


def test_workflow_wires_recovery_outputs_into_each_transition() -> None:
    release_job = _job(_workflow_text(), "publish-release")
    expected_release_environments = {
        "Verify validated release assets": {
            "ARTIFACT_NAME": "${{ needs.validation.outputs.release-assets-artifact }}",
            "EXPECTED_ARTIFACT_DIGEST": (
                "${{ needs.validation.outputs.release-assets-artifact-digest }}"
            ),
            "EXPECTED_CHECKSUM_FILE_SHA256": (
                "${{ needs.validation.outputs.release-assets-sha256 }}"
            ),
            "GH_TOKEN": "${{ github.token }}",
        },
        "Verify scanned release notes": {
            "GENERATED_NOTES_SHA256": ("${{ needs.generate-release-notes.outputs.notes-sha256 }}"),
            "SCANNED_NOTES_SHA256": "${{ needs.scan-release-notes.outputs.notes-sha256 }}",
        },
        "Preflight immutable release policy and target": {
            "GH_TOKEN": "${{ steps.app-token.outputs.token }}",
            "RELEASE_MODE": "${{ needs.resolve.outputs.mode }}",
            "RELEASE_SHA": "${{ needs.validation.outputs.sha }}",
            "RELEASE_TAG": "${{ needs.validation.outputs.tag }}",
        },
        "Create release tag": {
            "RELEASE_TAG": "${{ needs.validation.outputs.tag }}",
            "RELEASE_SHA": "${{ needs.validation.outputs.sha }}",
            "APP_SLUG": "${{ steps.app-token.outputs.app-slug }}",
            "GH_TOKEN": "${{ steps.app-token.outputs.token }}",
        },
        "Create GitHub Release": {
            "RELEASE_TAG": "${{ needs.validation.outputs.tag }}",
            "RELEASE_SHA": "${{ needs.validation.outputs.sha }}",
            "APP_SLUG": "${{ steps.app-token.outputs.app-slug }}",
            "GH_TOKEN": "${{ steps.app-token.outputs.token }}",
        },
        "Reconcile exact release assets": {
            "APP_SLUG": "${{ steps.app-token.outputs.app-slug }}",
            "GH_TOKEN": "${{ steps.app-token.outputs.token }}",
            "RELEASE_ID": "${{ steps.release.outputs.id }}",
            "RELEASE_PUBLISHED": "${{ steps.release.outputs.published }}",
            "RELEASE_TAG": "${{ needs.validation.outputs.tag }}",
        },
        "Publish immutable GitHub Release": {
            "APP_SLUG": "${{ steps.app-token.outputs.app-slug }}",
            "GH_TOKEN": "${{ steps.app-token.outputs.token }}",
            "RELEASE_ID": "${{ steps.release.outputs.id }}",
            "RELEASE_MODE": "${{ needs.resolve.outputs.mode }}",
            "RELEASE_PUBLISHED": "${{ steps.release.outputs.published }}",
            "RELEASE_SHA": "${{ needs.validation.outputs.sha }}",
            "RELEASE_TAG": "${{ needs.validation.outputs.tag }}",
        },
        "Verify release and every asset attestation": {
            "GH_TOKEN": "${{ steps.app-token.outputs.token }}",
            "RELEASE_TAG": "${{ needs.validation.outputs.tag }}",
        },
    }
    for step_name, expected in expected_release_environments.items():
        assert _step_environment(_step(release_job, step_name)) == expected

    pypi_publish = _job(_pypi_text(), "publish")
    assert _step_environment(_step(pypi_publish, "Verify exact publication files")) == {
        "DIST_DIR": "dist",
        "EXPECTED_COUNT": "${{ needs.validation.outputs.missing_count }}",
        "MISSING_FILES_JSON": "${{ needs.validation.outputs.missing_files }}",
        "SDIST_NAME": "${{ needs.validation.outputs.sdist_name }}",
        "SDIST_SHA256": "${{ needs.validation.outputs.sdist_sha256 }}",
        "WHEEL_NAME": "${{ needs.validation.outputs.wheel_name }}",
        "WHEEL_SHA256": "${{ needs.validation.outputs.wheel_sha256 }}",
    }
    assert _step_environment(_step(pypi_publish, "Re-resolve validated release tag")) == {
        "DIST_DIR": "dist",
        "EXPECTED_RELEASE_ID": "${{ needs.validation.outputs.release_id }}",
        "EXPECTED_SHA": "${{ needs.validation.outputs.sha }}",
        "GH_TOKEN": "${{ github.token }}",
        "RELEASE_TAG": "${{ needs.validation.outputs.tag }}",
    }
