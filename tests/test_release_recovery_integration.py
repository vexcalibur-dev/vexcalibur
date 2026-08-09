"""Offline integration tests for release and publication recovery."""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.release_recovery_harness import ReleaseRecoveryHarness


def _asset_contents(asset: dict[str, object]) -> bytes:
    encoded = asset["_bytes"]
    assert isinstance(encoded, str)
    return base64.b64decode(encoded)


def _release_context(
    harness: ReleaseRecoveryHarness,
    *,
    resolution: dict[str, str] | None = None,
    release: dict[str, str] | None = None,
) -> dict[str, str]:
    mode = "recovery" if resolution is None else resolution["mode"]
    release_sha = harness.release_sha if resolution is None else resolution["sha"]
    release_tag = harness.release_tag if resolution is None else resolution["tag"]
    context = {
        "github.token": harness.read_token,
        "needs.resolve.outputs.mode": mode,
        "needs.validation.outputs.sha": release_sha,
        "needs.validation.outputs.tag": release_tag,
        "steps.app-token.outputs.app-slug": harness.app_slug,
        "steps.app-token.outputs.token": harness.write_token,
    }
    if release is not None:
        context.update(
            {
                "steps.release.outputs.id": release["id"],
                "steps.release.outputs.published": release["published"],
            }
        )
    return context


def _run_create(
    harness: ReleaseRecoveryHarness,
    *,
    resolution: dict[str, str] | None = None,
) -> dict[str, str]:
    completed = harness.run_release_step(
        "publish-release",
        "Create GitHub Release",
        expression_values=_release_context(harness, resolution=resolution),
    )
    assert completed.returncode == 0, completed.stderr
    return harness.outputs()


def _run_reconcile(
    harness: ReleaseRecoveryHarness,
    release: dict[str, str],
    *,
    resolution: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return harness.run_release_step(
        "publish-release",
        "Reconcile exact release assets",
        expression_values=_release_context(harness, resolution=resolution, release=release),
    )


def test_release_recovery_executes_the_complete_allowed_transition(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    repository = harness.create_recovery_repository()
    artifact = harness.prepare_validated_assets()
    local_asset = harness.asset_dir / "vexcalibur-1.2.3.tar.gz"
    harness.update_state(publication_polls_remaining=6)

    resolved = harness.run_release_step(
        "resolve",
        "Determine release version",
        cwd=repository,
        expression_values={
            "github.event.inputs.version || ''": "",
            "github.event.inputs['recovery-tag'] || ''": harness.release_tag,
            "github.token": harness.read_token,
        },
        runtime_environment={"GITHUB_SHA": harness.main_sha},
    )
    assert resolved.returncode == 0, resolved.stderr
    resolution = harness.outputs()
    assert resolution["mode"] == "recovery"
    assert resolution["sha"] == harness.release_sha
    assert artifact["artifact_name"] == f"release-assets-{resolution['sha']}"

    verified_assets = harness.run_release_step(
        "publish-release",
        "Verify validated release assets",
        expression_values={
            "github.token": harness.read_token,
            "needs.validation.outputs.release-assets-artifact": artifact["artifact_name"],
            "needs.validation.outputs.release-assets-artifact-digest": artifact["artifact_digest"],
            "needs.validation.outputs.release-assets-sha256": artifact["checksum_sha256"],
        },
    )
    assert verified_assets.returncode == 0, f"{verified_assets.stdout}\n{verified_assets.stderr}"

    verified_notes = harness.run_release_step(
        "publish-release",
        "Verify scanned release notes",
        expression_values={
            "needs.generate-release-notes.outputs.notes-sha256": artifact["notes_sha256"],
            "needs.scan-release-notes.outputs.notes-sha256": artifact["notes_sha256"],
        },
    )
    assert verified_notes.returncode == 0, f"{verified_notes.stdout}\n{verified_notes.stderr}"

    preflight = harness.run_release_step(
        "publish-release",
        "Preflight immutable release policy and target",
        expression_values=_release_context(harness, resolution=resolution),
    )
    assert preflight.returncode == 0, preflight.stderr

    tag = harness.run_release_step(
        "publish-release",
        "Create release tag",
        expression_values=_release_context(harness, resolution=resolution),
    )
    assert tag.returncode == 0, tag.stderr

    release = _run_create(harness, resolution=resolution)
    assert release == {"id": "123", "published": "false"}

    reconciled = _run_reconcile(harness, release, resolution=resolution)
    assert reconciled.returncode == 0, reconciled.stderr

    published = harness.run_release_step(
        "publish-release",
        "Publish immutable GitHub Release",
        expression_values=_release_context(
            harness,
            resolution=resolution,
            release=release,
        ),
    )
    assert published.returncode == 0, published.stderr

    verified = harness.run_release_step(
        "publish-release",
        "Verify release and every asset attestation",
        expression_values=_release_context(harness, resolution=resolution),
    )
    assert verified.returncode == 0, verified.stderr

    state = harness.state
    assert state["release"]["draft"] is False
    assert state["release"]["immutable"] is True
    assert harness.calls("release", "create")
    assert harness.calls("release", "upload")
    assert harness.calls("release", "verify")
    expected_verifications = [
        [
            "release",
            "verify-asset",
            harness.release_tag,
            str(path),
            "--repo",
            state["repository"],
        ]
        for path in sorted(harness.asset_dir.iterdir())
    ]
    assert harness.calls("release", "verify-asset") == expected_verifications
    assert any("PATCH" in call for call in harness.calls("api"))
    matching_assets = [
        asset for asset in state["release"]["_assets"] if asset["name"] == local_asset.name
    ]
    assert len(matching_assets) == 1
    assert _asset_contents(matching_assets[0]) == local_asset.read_bytes()
    calls = state["calls"]
    patch_index = next(index for index, call in enumerate(calls) if "PATCH" in call)
    release_endpoint = f"repos/{state['repository']}/releases/{state['release_id']}"
    assert calls[patch_index + 1 :].count(["api", release_endpoint]) == 6


@pytest.mark.parametrize(
    ("tampering", "error"),
    (
        ("expired", "expired or malformed"),
        ("artifact-digest", "artifact digest differs"),
        ("missing-artifact", "expected exactly one"),
        ("duplicate-identical-artifact", "expected exactly one"),
        ("duplicate-conflicting-artifact", "expected exactly one"),
        ("checksum-file", "sha256sums file differs"),
        ("asset-bytes", "failed"),
        ("extra-file", "does not bind"),
        ("symlink", "directory or non-regular file"),
    ),
)
def test_validated_release_asset_gate_rejects_tampering_before_write_access(
    tmp_path: Path,
    tampering: str,
    error: str,
) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    artifact = harness.prepare_validated_assets()
    run_artifacts = harness.state["run_artifacts"]
    if tampering == "expired":
        run_artifacts[0]["expired"] = True
        harness.update_state(run_artifacts=run_artifacts)
    elif tampering == "artifact-digest":
        run_artifacts[0]["digest"] = "e" * 64
        harness.update_state(run_artifacts=run_artifacts)
    elif tampering == "missing-artifact":
        harness.update_state(run_artifacts=[])
    elif tampering == "duplicate-identical-artifact":
        harness.update_state(run_artifacts=[run_artifacts[0], dict(run_artifacts[0])])
    elif tampering == "duplicate-conflicting-artifact":
        conflicting = {**run_artifacts[0], "digest": "e" * 64}
        harness.update_state(run_artifacts=[run_artifacts[0], conflicting])
    elif tampering == "checksum-file":
        (harness.asset_dir / "SHA256SUMS").write_bytes(b"changed\n")
    elif tampering == "asset-bytes":
        (harness.asset_dir / artifact["manifest_name"]).write_bytes(b"changed\n")
    elif tampering == "extra-file":
        harness.write_asset("unexpected.whl")
    elif tampering == "symlink":
        manifest = harness.asset_dir / artifact["manifest_name"]
        manifest.unlink()
        manifest.symlink_to(harness.asset_dir / "vexcalibur-1.2.3.tar.gz")
    else:  # pragma: no cover - parametrization is exhaustive
        raise AssertionError(f"unknown tampering case: {tampering}")

    completed = harness.run_release_step(
        "publish-release",
        "Verify validated release assets",
        expression_values={
            "github.token": harness.read_token,
            "needs.validation.outputs.release-assets-artifact": artifact["artifact_name"],
            "needs.validation.outputs.release-assets-artifact-digest": artifact["artifact_digest"],
            "needs.validation.outputs.release-assets-sha256": artifact["checksum_sha256"],
        },
    )

    diagnostics = f"{completed.stdout}\n{completed.stderr}".lower()
    assert completed.returncode != 0, diagnostics
    assert error in diagnostics
    assert harness.calls("release", "create") == []
    assert harness.calls("release", "upload") == []
    assert not any("--method" in call for call in harness.calls("api"))


@pytest.mark.parametrize(
    ("tampering", "error"),
    (
        ("malformed", "digest is malformed"),
        ("handoff", "digests disagree"),
        ("download", "do not match the scanned digest"),
    ),
)
def test_scanned_release_notes_gate_rejects_tampering_before_write_access(
    tmp_path: Path,
    tampering: str,
    error: str,
) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    digest = hashlib.sha256(harness.notes.encode()).hexdigest()
    generated_digest = digest
    scanned_digest = digest
    if tampering == "malformed":
        scanned_digest = "not-a-digest"
    elif tampering == "handoff":
        generated_digest = "e" * 64
    elif tampering == "download":
        harness.notes_path.write_text("changed notes\n", encoding="utf-8")
    else:  # pragma: no cover - parametrization is exhaustive
        raise AssertionError(f"unknown tampering case: {tampering}")

    completed = harness.run_release_step(
        "publish-release",
        "Verify scanned release notes",
        expression_values={
            "needs.generate-release-notes.outputs.notes-sha256": generated_digest,
            "needs.scan-release-notes.outputs.notes-sha256": scanned_digest,
        },
    )

    diagnostics = f"{completed.stdout}\n{completed.stderr}".lower()
    assert completed.returncode != 0, diagnostics
    assert error in diagnostics
    assert harness.state["calls"] == []


def test_recovery_repository_ignores_host_git_credentials_and_signing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hostile_config = tmp_path / "host-gitconfig"
    hostile_config.write_text(
        "[commit]\n\tgpgSign = true\n[tag]\n\tgpgSign = true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(hostile_config))
    monkeypatch.setenv("GIT_DEFAULT_HASH", "sha256")
    monkeypatch.setenv("SSH_AUTH_SOCK", str(tmp_path / "host-agent.sock"))
    harness = ReleaseRecoveryHarness(tmp_path / "harness")

    repository = harness.create_recovery_repository()

    assert len(harness.release_sha) == 40
    assert len(harness.main_sha) == 40
    tag = harness._git(repository, "cat-file", "-p", harness.release_tag)
    assert "tagger Vexcalibur Test <vexcalibur@example.test>" in tag


def test_concurrent_creator_can_win_only_the_exact_release_race(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    harness.update_state(concurrent_create=True)

    release = _run_create(harness)

    assert release == {"id": "123", "published": "false"}
    assert len(harness.calls("release", "create")) == 1
    assert len(harness.calls("api", "graphql")) == 2
    assert harness.state["release"]["draft"] is True


def test_exact_draft_and_assets_are_recovered_idempotently(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    local_asset = harness.write_asset()
    harness.update_state(release=harness.contract_release())
    harness.add_remote_asset(local_asset)

    release = _run_create(harness)
    first = _run_reconcile(harness, release)
    second = _run_reconcile(harness, release)

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert harness.calls("release", "create") == []
    assert harness.calls("release", "upload") == []
    assert [call for call in harness.calls("api") if "DELETE" in call] == []


def test_draft_with_null_immutable_state_is_recovered(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    local_asset = harness.write_asset()
    release_state = harness.contract_release()
    release_state["immutable"] = None
    harness.update_state(release=release_state)
    harness.add_remote_asset(local_asset)

    release = _run_create(harness)
    reconciled = _run_reconcile(harness, release)
    published = harness.run_release_step(
        "publish-release",
        "Publish immutable GitHub Release",
        expression_values=_release_context(harness, release=release),
    )

    assert reconciled.returncode == 0, reconciled.stderr
    assert published.returncode == 0, published.stderr
    assert harness.state["release"]["immutable"] is True


def test_exact_published_release_is_a_no_op_recovery(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    harness.create_recovery_repository()
    local_asset = harness.write_asset()
    harness.update_state(release=harness.contract_release(published=True))
    harness.add_remote_asset(local_asset)

    release = _run_create(harness)
    reconciled = _run_reconcile(harness, release)
    published = harness.run_release_step(
        "publish-release",
        "Publish immutable GitHub Release",
        expression_values=_release_context(harness, release=release),
    )

    assert release["published"] == "true"
    assert reconciled.returncode == 0, reconciled.stderr
    assert published.returncode == 0, published.stderr
    assert [call for call in harness.calls("api") if "PATCH" in call] == []
    assert harness.calls("release", "upload") == []


def test_recovery_rejects_a_release_commit_outside_main(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    harness.create_recovery_repository()
    harness.update_state(
        release=harness.contract_release(),
        comparison_status="behind",
    )

    completed = harness.run_release_step(
        "publish-release",
        "Publish immutable GitHub Release",
        expression_values=_release_context(
            harness,
            release={"id": "123", "published": "false"},
        ),
    )

    assert completed.returncode != 0
    assert "no longer contained in main" in completed.stderr
    assert [call for call in harness.calls("api") if "PATCH" in call] == []


def test_immutable_publication_stops_at_the_retry_bound(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    local_asset = harness.write_asset()
    harness.update_state(
        release=harness.contract_release(),
        publication_completes=False,
    )
    harness.add_remote_asset(local_asset)

    completed = harness.run_release_step(
        "publish-release",
        "Publish immutable GitHub Release",
        expression_values=_release_context(
            harness,
            release={"id": "123", "published": "false"},
        ),
    )

    assert completed.returncode != 0
    assert "did not reach the exact immutable published state" in completed.stderr
    calls = harness.state["calls"]
    patch_calls = [call for call in calls if "PATCH" in call]
    assert len(patch_calls) == 1
    patch_index = calls.index(patch_calls[0])
    release_endpoint = f"repos/{harness.state['repository']}/releases/123"
    assert calls[patch_index + 1 :].count(["api", release_endpoint]) == 6


def test_zero_byte_starter_is_removed_before_bounded_reupload(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    harness.write_asset()
    harness.update_state(
        release=harness.contract_release(),
        upload_mode="starter-once",
        starter_uploads_remaining=1,
    )
    release = _run_create(harness)

    completed = _run_reconcile(harness, release)

    assert completed.returncode == 0, completed.stderr
    assert len(harness.calls("release", "upload")) == 2
    assert len([call for call in harness.calls("api") if "DELETE" in call]) == 1
    assert harness.state["release"]["_assets"][0]["state"] == "uploaded"


def test_asset_recovery_accepts_success_at_the_final_attempt(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    harness.write_asset()
    harness.update_state(
        release=harness.contract_release(),
        upload_mode="starter-once",
        starter_uploads_remaining=2,
    )
    release = _run_create(harness)

    completed = _run_reconcile(harness, release)

    assert completed.returncode == 0, completed.stderr
    assert len(harness.calls("release", "upload")) == 3
    assert len([call for call in harness.calls("api") if "DELETE" in call]) == 2


def test_concurrent_asset_uploader_can_win_with_exact_bytes(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    harness.write_asset()
    harness.update_state(release=harness.contract_release(), upload_exit=1)
    release = _run_create(harness)

    completed = _run_reconcile(harness, release)

    assert completed.returncode == 0, completed.stderr
    assert len(harness.calls("release", "upload")) == 1


def test_asset_reconciliation_stops_at_the_retry_bound(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    harness.write_asset()
    harness.update_state(release=harness.contract_release(), upload_mode="missing", upload_exit=1)
    release = _run_create(harness)

    completed = _run_reconcile(harness, release)

    assert completed.returncode != 0
    assert "after bounded retries" in completed.stderr
    assert len(harness.calls("release", "upload")) == 3


@pytest.mark.parametrize(
    ("remote_contents", "uploader", "error"),
    (
        (b"wrong\n", None, "differs from the validated bytes"),
        (None, "untrusted-user", "was uploaded by untrusted-user"),
    ),
)
def test_published_release_rejects_mismatched_assets(
    tmp_path: Path,
    remote_contents: bytes | None,
    uploader: str | None,
    error: str,
) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    local_asset = harness.write_asset(contents=b"right\n")
    harness.update_state(release=harness.contract_release(published=True))
    harness.add_remote_asset(local_asset, contents=remote_contents, uploader=uploader)
    release = _run_create(harness)

    completed = _run_reconcile(harness, release)

    assert completed.returncode != 0
    assert error in completed.stderr
    assert harness.calls("release", "upload") == []


def test_published_release_rejects_a_missing_immutable_asset(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    harness.write_asset()
    harness.update_state(release=harness.contract_release(published=True))
    release = _run_create(harness)

    completed = _run_reconcile(harness, release)

    assert completed.returncode != 0
    assert "is missing immutable asset" in completed.stderr
    assert harness.calls("release", "upload") == []


@pytest.mark.parametrize(
    ("tampering", "error"),
    (
        ("extra", "asset outside the validated asset set"),
        ("duplicate", "duplicate asset names"),
    ),
)
def test_published_release_rejects_nonexact_remote_asset_sets(
    tmp_path: Path,
    tampering: str,
    error: str,
) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    local_asset = harness.write_asset()
    harness.update_state(release=harness.contract_release(published=True))
    harness.add_remote_asset(local_asset)
    if tampering == "extra":
        extra_asset = tmp_path / "unexpected.txt"
        extra_asset.write_bytes(b"unexpected\n")
        harness.add_remote_asset(extra_asset)
    else:
        harness.add_remote_asset(local_asset)
    release = _run_create(harness)

    completed = _run_reconcile(harness, release)

    assert completed.returncode != 0
    assert error in completed.stderr
    assert harness.calls("release", "upload") == []


def test_release_recovery_rejects_mismatched_identity(tmp_path: Path) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    release = harness.contract_release(published=True)
    release["target_commitish"] = "c" * 40
    harness.update_state(release=release)

    completed = harness.run_release_step(
        "publish-release",
        "Create GitHub Release",
        expression_values=_release_context(harness),
    )

    assert completed.returncode != 0
    assert "differs from the exact release contract" in completed.stderr
    assert harness.calls("release", "create") == []


@pytest.mark.parametrize("boundary", ("release", "asset"))
def test_attestation_retries_stop_at_each_bound(tmp_path: Path, boundary: str) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    local_asset = harness.write_asset()
    harness.update_state(
        release=harness.contract_release(published=True),
        verify_release_failures=100 if boundary == "release" else 0,
        verify_asset_failures=100 if boundary == "asset" else 0,
    )
    harness.add_remote_asset(local_asset)

    completed = harness.run_release_step(
        "publish-release",
        "Verify release and every asset attestation",
        expression_values=_release_context(harness),
    )

    assert completed.returncode != 0
    assert "within the retry bound" in completed.stderr
    if boundary == "release":
        assert len(harness.calls("release", "verify")) == 8
        assert harness.calls("release", "verify-asset") == []
    else:
        assert len(harness.calls("release", "verify")) == 1
        assert len(harness.calls("release", "verify-asset")) == 8


@pytest.mark.parametrize("boundary", ("release", "asset"))
def test_attestation_retries_accept_success_at_the_final_attempt(
    tmp_path: Path,
    boundary: str,
) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    local_asset = harness.write_asset()
    harness.update_state(
        release=harness.contract_release(published=True),
        verify_release_failures=7 if boundary == "release" else 0,
        verify_asset_failures=7 if boundary == "asset" else 0,
    )
    harness.add_remote_asset(local_asset)

    completed = harness.run_release_step(
        "publish-release",
        "Verify release and every asset attestation",
        expression_values=_release_context(harness),
    )

    assert completed.returncode == 0, completed.stderr
    expected_release_calls = 8 if boundary == "release" else 1
    assert len(harness.calls("release", "verify")) == expected_release_calls
    expected_asset_calls = 1 if boundary == "release" else 8
    assert len(harness.calls("release", "verify-asset")) == expected_asset_calls


@pytest.mark.parametrize("boundary", ("release", "asset"))
def test_pypi_attestation_retries_accept_success_at_the_final_attempt(
    tmp_path: Path,
    boundary: str,
) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    local_asset = harness.write_asset()
    harness.update_state(
        release=harness.contract_release(published=True),
        verify_release_failures=4 if boundary == "release" else 0,
        verify_asset_failures=4 if boundary == "asset" else 0,
    )
    harness.add_remote_asset(local_asset)

    completed = harness.run_pypi_step(
        "validation",
        "Verify GitHub release attestations",
        expression_values={
            "github.token": harness.read_token,
            "needs.resolve.outputs.tag": harness.release_tag,
            "steps.assets.outputs.directory": str(harness.asset_dir),
        },
    )

    assert completed.returncode == 0, completed.stderr
    expected_release_calls = 5 if boundary == "release" else 1
    assert len(harness.calls("release", "verify")) == expected_release_calls
    expected_asset_calls = 1 if boundary == "release" else 5
    assert len(harness.calls("release", "verify-asset")) == expected_asset_calls


@pytest.mark.parametrize("boundary", ("release", "asset"))
def test_pypi_attestation_retries_stop_at_each_bound(tmp_path: Path, boundary: str) -> None:
    harness = ReleaseRecoveryHarness(tmp_path)
    local_asset = harness.write_asset()
    harness.update_state(
        release=harness.contract_release(published=True),
        verify_release_failures=100 if boundary == "release" else 0,
        verify_asset_failures=100 if boundary == "asset" else 0,
    )
    harness.add_remote_asset(local_asset)

    completed = harness.run_pypi_step(
        "validation",
        "Verify GitHub release attestations",
        expression_values={
            "github.token": harness.read_token,
            "needs.resolve.outputs.tag": harness.release_tag,
            "steps.assets.outputs.directory": str(harness.asset_dir),
        },
    )

    assert completed.returncode != 0
    assert "failed after 5 attempts" in completed.stdout
    expected_release_calls = 5 if boundary == "release" else 1
    assert len(harness.calls("release", "verify")) == expected_release_calls
    expected_asset_calls = 0 if boundary == "release" else 5
    assert len(harness.calls("release", "verify-asset")) == expected_asset_calls


def _prepare_partial_pypi_recovery(
    tmp_path: Path,
    *,
    verify_publication: bool = True,
) -> tuple[ReleaseRecoveryHarness, Path, dict[str, str], dict[str, str]]:
    harness = ReleaseRecoveryHarness(tmp_path)
    version = harness.release_tag[1:]
    wheel_name = f"vexcalibur-{version}-py3-none-any.whl"
    sdist_name = f"vexcalibur-{version}.tar.gz"
    source_dist = harness.runner_temp / "pypi-source-dist"
    source_dist.mkdir()
    wheel = source_dist / wheel_name
    sdist = source_dist / sdist_name
    wheel.write_bytes(b"wheel\n")
    sdist.write_bytes(b"sdist\n")
    wheel_sha256 = hashlib.sha256(wheel.read_bytes()).hexdigest()
    sdist_sha256 = hashlib.sha256(sdist.read_bytes()).hexdigest()
    harness.update_state(
        release=harness.contract_release(published=True),
        pypi_response={
            "info": {"name": "vexcalibur", "version": version},
            "urls": [
                {
                    "filename": wheel_name,
                    "packagetype": "bdist_wheel",
                    "digests": {"sha256": wheel_sha256},
                }
            ],
        },
    )
    harness.add_remote_asset(wheel)
    harness.add_remote_asset(sdist)

    selected = harness.run_pypi_step(
        "validation",
        "Select exact distributions absent from PyPI",
        cwd=Path(__file__).parents[1],
        expression_values={
            "needs.resolve.outputs.version": version,
            "steps.distributions.outputs.directory": str(source_dist),
        },
    )
    assert selected.returncode == 0, selected.stderr
    selection = harness.outputs()
    assert selection == {
        "publish_needed": "true",
        "missing_count": "1",
        "missing_files": json.dumps([sdist_name], separators=(",", ":")),
    }

    publish_root = harness.runner_temp / "pypi-publish"
    publish_dist = publish_root / "dist"
    publish_dist.mkdir(parents=True)
    shutil.copyfile(
        harness.runner_temp / "verified-pypi-dist" / sdist_name, publish_dist / sdist_name
    )
    publication_context = {
        "needs.validation.outputs.missing_count": selection["missing_count"],
        "needs.validation.outputs.missing_files": selection["missing_files"],
        "needs.validation.outputs.sdist_name": sdist_name,
        "needs.validation.outputs.sdist_sha256": sdist_sha256,
        "needs.validation.outputs.wheel_name": wheel_name,
        "needs.validation.outputs.wheel_sha256": wheel_sha256,
    }
    if verify_publication:
        verified = harness.run_pypi_step(
            "publish",
            "Verify exact publication files",
            cwd=publish_root,
            expression_values=publication_context,
        )
        assert verified.returncode == 0, verified.stderr
    harness.allow_asset_root(publish_dist)

    reresolution_context = {
        "github.token": harness.read_token,
        "needs.validation.outputs.release_id": "123",
        "needs.validation.outputs.sha": harness.release_sha,
        "needs.validation.outputs.tag": harness.release_tag,
    }
    return harness, publish_root, publication_context, reresolution_context


def test_partial_pypi_recovery_executes_selection_handoff_and_reresolution(
    tmp_path: Path,
) -> None:
    harness, publish_root, _, context = _prepare_partial_pypi_recovery(tmp_path)

    reresolved = harness.run_pypi_step(
        "publish",
        "Re-resolve validated release tag",
        cwd=publish_root,
        expression_values=context,
    )
    assert reresolved.returncode == 0, f"{reresolved.stdout}\n{reresolved.stderr}"
    assert len(harness.calls("curl")) == 1
    assert len(harness.calls("release", "verify-asset")) == 1


@pytest.mark.parametrize(
    ("tampering", "error"),
    (
        ("bytes", "distribution hash changed"),
        ("extra", "contains 2 entries"),
        ("subset", "filename subset differs"),
        ("count", "count differs"),
        ("symlink", "nonregular file"),
        ("directory", "nonregular file"),
    ),
)
def test_pypi_publication_gate_rejects_handoff_tampering(
    tmp_path: Path,
    tampering: str,
    error: str,
) -> None:
    harness, publish_root, context, _ = _prepare_partial_pypi_recovery(
        tmp_path,
        verify_publication=False,
    )
    publish_dist = publish_root / "dist"
    distribution = next(publish_dist.iterdir())
    if tampering == "bytes":
        distribution.write_bytes(b"changed\n")
    elif tampering == "extra":
        (publish_dist / "unexpected.whl").write_bytes(b"extra\n")
    elif tampering == "subset":
        context["needs.validation.outputs.missing_files"] = json.dumps(
            [context["needs.validation.outputs.wheel_name"]],
            separators=(",", ":"),
        )
    elif tampering == "count":
        context["needs.validation.outputs.missing_count"] = "2"
    elif tampering == "symlink":
        target = harness.runner_temp / "pypi-source-dist" / distribution.name
        distribution.unlink()
        distribution.symlink_to(target)
    elif tampering == "directory":
        distribution.unlink()
        distribution.mkdir()
    else:  # pragma: no cover - parametrization is exhaustive
        raise AssertionError(f"unknown tampering case: {tampering}")

    completed = harness.run_pypi_step(
        "publish",
        "Verify exact publication files",
        cwd=publish_root,
        expression_values=context,
    )

    diagnostics = f"{completed.stdout}\n{completed.stderr}".lower()
    assert completed.returncode != 0, diagnostics
    assert error in diagnostics
    assert harness.calls("release", "verify-asset") == []


@pytest.mark.parametrize(
    ("drift", "error"),
    (
        ("release-id", "immutable release changed after validation"),
        ("immutable", "no longer an immutable"),
        ("author", "release author changed"),
        ("target", "release target differs"),
        ("sha", "tag contract changed after validation"),
        ("ancestry", "no longer an ancestor of main"),
        ("asset-uploader", "asset uploader or display label changed"),
        ("asset-bytes", "attestation bytes do not match"),
        ("title", "title or body changed"),
        ("body", "protected release notes changed"),
        ("tagger", "tag contract changed after validation"),
        ("tag-ref", "tag contract changed after validation"),
        ("protected-notes", "protected release notes changed"),
    ),
)
def test_pypi_reresolution_rejects_post_validation_drift(
    tmp_path: Path,
    drift: str,
    error: str,
) -> None:
    harness, publish_root, _, context = _prepare_partial_pypi_recovery(tmp_path)
    state = harness.state
    release = state["release"]
    assert release is not None
    if drift == "release-id":
        context["needs.validation.outputs.release_id"] = "456"
    elif drift == "immutable":
        release["immutable"] = False
    elif drift == "author":
        release["author"]["login"] = "untrusted-user"
    elif drift == "target":
        release["target_commitish"] = "c" * 40
    elif drift == "sha":
        context["needs.validation.outputs.sha"] = "c" * 40
    elif drift == "ancestry":
        state["comparison_status"] = "behind"
    elif drift == "asset-uploader":
        release["_assets"][0]["uploader"]["login"] = "untrusted-user"
    elif drift == "asset-bytes":
        release["_assets"][-1]["_bytes"] = base64.b64encode(b"changed\n").decode("ascii")
    elif drift == "title":
        release["name"] = "changed-title"
    elif drift == "body":
        release["body"] = "changed body\n"
    elif drift == "tagger":
        tag_object = state["tag_object"]
        tag_object["tagger"]["name"] = "untrusted-user"
        harness.configure_tag_state(tag_object=tag_object)
    elif drift == "tag-ref":
        tag_ref = state["tag_ref"]
        tag_ref["object"]["type"] = "commit"
        harness.configure_tag_state(tag_ref=tag_ref)
    elif drift == "protected-notes":
        tag_object = state["tag_object"]
        message = json.loads(tag_object["message"])
        message["release_notes"] = "changed protected notes\n"
        tag_object["message"] = json.dumps(message, separators=(",", ":"))
        harness.configure_tag_state(tag_object=tag_object)
    else:  # pragma: no cover - parametrization is exhaustive
        raise AssertionError(f"unknown drift case: {drift}")
    harness.update_state(
        release=release,
        comparison_status=state["comparison_status"],
    )

    completed = harness.run_pypi_step(
        "publish",
        "Re-resolve validated release tag",
        cwd=publish_root,
        expression_values=context,
    )

    diagnostics = f"{completed.stdout}\n{completed.stderr}".lower()
    assert completed.returncode != 0, diagnostics
    assert error in diagnostics
