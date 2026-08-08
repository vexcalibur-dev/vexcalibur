"""Behavioral tests for the checkout-free release policy preflight."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tests.release_recovery_harness import ReleaseRecoveryHarness


def _run_preflight(harness: ReleaseRecoveryHarness) -> subprocess.CompletedProcess[str]:
    return harness.run_release_step(
        "publish-release",
        "Preflight immutable release policy and target",
        expression_values={
            "needs.resolve.outputs.mode": "normal",
            "needs.validation.outputs.sha": harness.release_sha,
            "needs.validation.outputs.tag": harness.release_tag,
            "steps.app-token.outputs.token": harness.write_token,
        },
    )


def test_preflight_accepts_boolean_owner_enforcement(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    harness.update_state(
        policy_responses=[{"enabled": True, "enforced_by_owner": True}],
    )

    completed = _run_preflight(harness)

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
    harness = ReleaseRecoveryHarness(tmp_path)
    harness.update_state(
        policy_responses=[{"enabled": enabled, "enforced_by_owner": enforced}],
    )

    completed = _run_preflight(harness)

    assert completed.returncode == 1
    assert "not enabled and owner-enforced" in completed.stderr


def test_preflight_rejects_policy_request_failure(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    harness.update_state(policy_failures=[True])

    completed = _run_preflight(harness)

    assert completed.returncode == 1
    assert "Could not preflight" in completed.stderr
    assert "simulated policy request failure" in completed.stderr


def test_repeated_preflight_detects_policy_drift(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    harness.update_state(
        policy_responses=[
            {"enabled": True, "enforced_by_owner": True},
            {"enabled": False, "enforced_by_owner": True},
        ],
    )

    first = _run_preflight(harness)
    second = _run_preflight(harness)

    assert first.returncode == 0, first.stderr
    assert second.returncode == 1
    assert "not enabled and owner-enforced" in second.stderr


def test_publication_rejects_policy_drift_after_successful_preflight(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    asset = harness.write_asset()
    harness.update_state(
        release=harness.contract_release(),
        policy_responses=[
            {"enabled": True, "enforced_by_owner": True},
            {"enabled": False, "enforced_by_owner": True},
        ],
    )
    harness.add_remote_asset(asset)

    preflight = _run_preflight(harness)
    published = harness.run_release_step(
        "publish-release",
        "Publish immutable GitHub Release",
        expression_values={
            "needs.resolve.outputs.mode": "normal",
            "needs.validation.outputs.sha": harness.release_sha,
            "needs.validation.outputs.tag": harness.release_tag,
            "steps.app-token.outputs.app-slug": harness.app_slug,
            "steps.app-token.outputs.token": harness.write_token,
            "steps.release.outputs.id": "123",
            "steps.release.outputs.published": "false",
        },
    )

    assert preflight.returncode == 0, preflight.stderr
    assert published.returncode != 0
    assert "no longer enabled and owner-enforced" in published.stderr
    assert not any("PATCH" in call for call in harness.calls("api"))
