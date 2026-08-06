"""Security-contract tests for the GitHub release workflow."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.release_workflow_helpers import (
    _job,
    _pypi_text,
    _run_create_release_step,
    _step,
    _validation_text,
    _workflow_text,
)

ROOT = Path(__file__).parents[1]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_EVIDENCE = ROOT / "scripts" / "release_evidence.py"
PYPI_SELECTOR = ROOT / "scripts" / "select-pypi-release-files.py"
PYPI_RELEASE_STATE_QUERY = ".draft == false and .prerelease == false and .immutable == true"
ARTIFACT_EXPIRATION_QUERY = 'if .expired == false then "current" else "invalid" end'


def test_release_publisher_rest_binds_the_downloaded_validation_artifact() -> None:
    publish = _job(_workflow_text(), "publish-release")
    verification = _step(publish, "Verify validated release assets")

    assert "needs.validation.outputs.release-assets-artifact" in publish
    assert "needs.validation.outputs.release-assets-artifact-digest" in publish
    assert "needs.validation.outputs.release-assets-sha256" in publish
    assert "actions/runs/${GITHUB_RUN_ID}/artifacts?per_page=100" in verification
    assert "Expected exactly one current-run artifact" in verification
    assert ARTIFACT_EXPIRATION_QUERY in verification
    assert "sha256sum --check --strict SHA256SUMS" in verification


def test_release_never_clobbers_an_existing_asset() -> None:
    for workflow in (_workflow_text(), _validation_text(), _pypi_text()):
        assert "--clobber" not in workflow

    reconcile = _step(_job(_workflow_text(), "publish-release"), "Reconcile exact release assets")
    assert '"${state}" == "uploaded"' in reconcile
    assert "cmp --silent" in reconcile
    assert '"${RELEASE_PUBLISHED}" == "false"' in reconcile
    assert '"${state}" == "starter"' in reconcile
    assert '"${size}" == "0"' in reconcile
    assert "--method DELETE" in reconcile


def test_normal_release_requires_main_tip_but_recovery_accepts_only_an_ancestor() -> None:
    release = _workflow_text()
    resolve = _job(release, "resolve")
    publisher = _job(release, "publish-release")

    assert "recovery-tag:" in release
    assert '"${current_main_sha}" != "${GITHUB_SHA}"' in resolve
    assert 'git merge-base --is-ancestor "${release_sha}" "${current_main_sha}"' in resolve
    assert "printf 'mode=normal\\n'" in resolve
    assert "printf 'mode=recovery\\n'" in resolve

    preflight = _step(publisher, "Preflight immutable release policy and target")
    assert '"${RELEASE_MODE}" == "normal"' in preflight
    assert '"${current_main_sha}" != "${RELEASE_SHA}"' in preflight
    assert '"${RELEASE_MODE}" == "recovery"' in preflight
    assert "compare/${RELEASE_SHA}...${current_main_sha}" in preflight
    assert '"${comparison}" != "ahead" && "${comparison}" != "identical"' in preflight

    immutable = _step(publisher, "Publish immutable GitHub Release")
    assert '"${RELEASE_MODE}" == "normal"' in immutable
    assert '"${current_main_sha}" != "${RELEASE_SHA}"' in immutable
    assert '"${RELEASE_MODE}" == "recovery"' in immutable
    assert "compare/${RELEASE_SHA}...${current_main_sha}" in immutable
    assert '"${comparison}" != "ahead" && "${comparison}" != "identical"' in immutable


def test_release_state_machine_allows_only_exact_draft_or_immutable_published_state() -> None:
    publish = _job(_workflow_text(), "publish-release")
    create = _step(publish, "Create GitHub Release")
    reconcile = _step(publish, "Reconcile exact release assets")
    immutable = _step(publish, "Publish immutable GitHub Release")

    assert "release(tagName:$tag){databaseId}" in create
    assert "data.repository.release == null" in create
    assert "GitHub returned a malformed release query." in create
    assert 'releases/${release_id}"' in create
    assert "--draft" in create
    assert "--verify-tag" in create
    assert "--target" in create
    assert '--notes-file "${notes_path}"' in create
    assert "resolve_release_by_tag || resolve_status=$?" in create
    assert "releases/tags/${RELEASE_TAG}" not in create
    assert ".draft == true and (.immutable == false or .immutable == null)" in create
    assert ".draft == false and .immutable == true" in create
    assert ".prerelease == false" in create

    assert "Published release ${RELEASE_TAG} is missing immutable asset" in reconcile
    assert '"${RELEASE_PUBLISHED}" == "false"' in reconcile
    assert '"${state}" == "starter"' in reconcile
    assert '"${size}" == "0"' in reconcile

    assert "immutable-publication-transition.json" in immutable
    assert "{tag_name: $tag, target_commitish: $sha, name: $tag, body: $body," in immutable
    assert "draft: false, prerelease: false" in immutable
    assert '--input "${publication_transition}"' in immutable
    assert "-F draft=false" not in immutable
    assert ".draft == false and .prerelease == false" in immutable
    assert ".immutable == true" in immutable
    assert "GitHub Release did not reach the exact immutable published state" in immutable
    assert "Published immutable release asset" in immutable


def test_release_resolver_recovers_an_existing_draft_without_creating(
    tmp_path: Path,
) -> None:
    completed, calls = _run_create_release_step(
        tmp_path,
        graphql_responses=[
            {"data": {"repository": {"release": {"databaseId": 123}}}},
        ],
    )

    assert completed.returncode == 0, completed.stderr
    assert "release create" not in calls


def test_release_resolver_creates_only_after_an_exact_null_lookup(
    tmp_path: Path,
) -> None:
    completed, calls = _run_create_release_step(
        tmp_path,
        graphql_responses=[
            {"data": {"repository": {"release": None}}},
            {"data": {"repository": {"release": {"databaseId": 123}}}},
        ],
    )

    assert completed.returncode == 0, completed.stderr
    assert "release create v1.2.3" in calls
    assert "--verify-tag" in calls
    assert calls.count("api graphql") == 2


def test_release_resolver_rejects_rest_identity_mismatch(tmp_path: Path) -> None:
    completed, calls = _run_create_release_step(
        tmp_path,
        graphql_responses=[
            {"data": {"repository": {"release": {"databaseId": 123}}}},
        ],
        rest_release_id=456,
    )

    assert completed.returncode != 0
    assert "release create" not in calls
    assert "does not match its resolved ID" in completed.stderr


def test_release_resolver_accepts_a_concurrent_create_only_after_exact_resolution(
    tmp_path: Path,
) -> None:
    completed, calls = _run_create_release_step(
        tmp_path,
        graphql_responses=[
            {"data": {"repository": {"release": None}}},
            {"data": {"repository": {"release": {"databaseId": 123}}}},
        ],
        create_exit=1,
    )

    assert completed.returncode == 0, completed.stderr
    assert "release create v1.2.3" in calls
    assert calls.count("api graphql") == 2


@pytest.mark.parametrize(
    "malformed_response",
    (
        {},
        {"data": {}},
        {"data": {"repository": {}}},
        {"data": {"repository": {"release": {}}}},
        {"data": {"repository": {"release": {"databaseId": "123"}}}},
        {
            "data": {"repository": {"release": None}},
            "errors": [{"message": "partial response"}],
        },
    ),
)
def test_release_resolver_rejects_malformed_graphql_before_create(
    tmp_path: Path,
    malformed_response: object,
) -> None:
    completed, calls = _run_create_release_step(
        tmp_path,
        graphql_responses=[malformed_response],
    )

    assert completed.returncode != 0
    assert "release create" not in calls
    assert "malformed release query" in completed.stderr


def test_all_untrusted_assets_and_notes_are_verified_before_write_token() -> None:
    publish = _job(_workflow_text(), "publish-release")

    assets = publish.index("name: Verify validated release assets")
    notes = publish.index("name: Verify scanned release notes")
    token = publish.index("name: Generate app token")
    policy = publish.index("name: Preflight immutable release policy and target")
    tag = publish.index("name: Create release tag")
    assert assets < notes < token < policy < tag

    before_token = publish[:token]
    assert "actions/runs/${GITHUB_RUN_ID}/artifacts" in before_token
    assert "sha256sum --check --strict SHA256SUMS" in before_token
    assert "Publisher release notes do not match the scanned digest" in before_token
    assert "secrets.AUTOMATION_SECRET" not in before_token


def test_immutable_release_policy_preflight_uses_the_scoped_app_token() -> None:
    publish = _job(_workflow_text(), "publish-release")
    token = _step(publish, "Generate app token")
    preflight = _step(publish, "Preflight immutable release policy and target")

    assert "permission-administration: read" in token
    assert "permission-contents: write" in token
    assert "GH_TOKEN: ${{ steps.app-token.outputs.token }}" in preflight
    assert "repos/${GITHUB_REPOSITORY}/immutable-releases" in preflight
    assert ".enabled == true and .enforced_by_owner == true" in preflight
    assert '"verified"' in preflight
    assert "immutable-release preflight deferred" not in preflight.lower()

    immutable = _step(publish, "Publish immutable GitHub Release")
    patch = immutable.index('--input "${publication_transition}"')
    assert "repos/${GITHUB_REPOSITORY}/immutable-releases" in immutable[:patch]
    assert ".enabled == true and .enforced_by_owner == true" in immutable[:patch]
    assert '"verified"' in immutable[:patch]


def test_checkout_free_publisher_invokes_no_repository_scripts() -> None:
    publish = _job(_workflow_text(), "publish-release")

    assert "actions/checkout@" not in publish
    assert "scripts/" not in publish


def test_post_publish_state_and_attestations_are_verified_with_bounded_retries() -> None:
    publish = _job(_workflow_text(), "publish-release")
    immutable = _step(publish, "Publish immutable GitHub Release")
    attestations = _step(publish, "Verify release and every asset attestation")

    assert publish.index("name: Publish immutable GitHub Release") < publish.index(
        "name: Verify release and every asset attestation"
    )
    assert ".immutable == true" in immutable
    assert "cmp --silent" in immutable
    assert "for attempt in 1 2 3 4 5 6 7 8" in attestations
    assert "attempt == 8" in attestations
    assert 'gh release verify "${RELEASE_TAG}"' in attestations
    assert 'gh release verify-asset "${RELEASE_TAG}"' in attestations
    assert "within the retry bound" in attestations


def test_tag_release_and_asset_bytes_are_revalidated_immediately_before_publish() -> None:
    immutable = _step(_job(_workflow_text(), "publish-release"), "Publish immutable GitHub Release")
    patch = immutable.index('--input "${publication_transition}"')

    for contract in (
        "repos/${GITHUB_REPOSITORY}/immutable-releases",
        "validate_tag_contract",
        "pre-publish-assets.json",
        "changed bytes before publication",
        "immediate-pre-publish-assets.json",
        "immediate-pre-publish-release.json",
        "Release metadata changed immediately before publication",
        "/git/ref/heads/main",
    ):
        assert contract in immutable[:patch]
    assert immutable[:patch].count("validate_tag_contract") >= 3
    assert immutable[:patch].count("repos/${GITHUB_REPOSITORY}/immutable-releases") == 1
    assert "current_published" in immutable[:patch]
    assert (
        immutable.index("immediate-pre-publish-release.json")
        < immutable.index("immediate-pre-publish-assets.json")
        < patch
    )


def test_pypi_uses_exact_immutable_release_bytes_and_supports_partial_recovery() -> None:
    pypi = _pypi_text()
    validation = _job(pypi, "validation")
    publish = _job(pypi, "publish")

    assert "gh release download" in validation
    assert "gh release verify" in validation
    assert "gh release verify-asset" in validation
    assert "Copy exact distributions out of the release bundle" in validation
    assert "install -m 0644" in validation
    assert "sha256sum" in validation

    assert "scripts/select-pypi-release-files.py" in validation
    assert "--pypi-response" in validation
    assert "--pypi-missing" in validation
    assert "--output-directory" in validation
    assert "--github-output" in validation
    assert "publish_needed" in validation
    assert "missing_count" in validation
    assert "missing_files" in validation
    assert "Upload only missing verified distributions" in validation

    assert "verified-pypi-dist-${{ needs.validation.outputs.sha }}" in publish
    assert "Verify exact publication files" in publish
    assert "EXPECTED_COUNT" in publish
    assert "MISSING_FILES_JSON" in publish
    assert "WHEEL_SHA256" in publish
    assert "SDIST_SHA256" in publish
    assert "gh release verify-asset" in publish
    assert "pypa/gh-action-pypi-publish@" in publish

    selector = PYPI_SELECTOR.read_text(encoding="utf-8")
    assert 'digest = digests.get("sha256")' in selector
    assert 'expected_record = f"{distribution.package_type}:{distribution.sha256}"' in selector
    assert "published_record != expected_record" in selector
    assert "_copy_distributions_exclusively(missing" in selector
    assert '"missing_files": [distribution.filename for distribution in missing]' in selector


@pytest.mark.parametrize(
    ("release", "accepted"),
    (
        (
            {"draft": False, "prerelease": False, "immutable": True},
            True,
        ),
        (
            {"draft": "false", "prerelease": False, "immutable": True},
            False,
        ),
        (
            {"draft": False, "prerelease": "false", "immutable": True},
            False,
        ),
        (
            {"draft": False, "prerelease": False, "immutable": "true"},
            False,
        ),
        (
            {"draft": None, "prerelease": False, "immutable": True},
            False,
        ),
        (
            {"draft": False, "prerelease": None, "immutable": True},
            False,
        ),
        (
            {"draft": False, "prerelease": False, "immutable": None},
            False,
        ),
        (
            {"prerelease": False, "immutable": True},
            False,
        ),
        (
            {"draft": False, "immutable": True},
            False,
        ),
        (
            {"draft": False, "prerelease": False},
            False,
        ),
    ),
)
def test_pypi_release_state_check_preserves_json_types(
    release: dict[str, object],
    *,
    accepted: bool,
) -> None:
    pypi = _pypi_text()
    assert pypi.count(f"'{PYPI_RELEASE_STATE_QUERY}'") == 2
    jq = shutil.which("jq")
    assert jq is not None

    completed = subprocess.run(  # noqa: S603 - fixed jq command and test-owned input
        [jq, "-e", PYPI_RELEASE_STATE_QUERY],
        check=False,
        capture_output=True,
        input=json.dumps(release),
        text=True,
    )

    assert (completed.returncode == 0) is accepted


@pytest.mark.parametrize(
    ("artifact", "expected"),
    (
        ({"expired": False}, "current"),
        ({"expired": True}, "invalid"),
        ({"expired": "false"}, "invalid"),
        ({"expired": "true"}, "invalid"),
        ({"expired": None}, "invalid"),
        ({}, "invalid"),
    ),
)
def test_artifact_expiration_check_preserves_json_types(
    artifact: dict[str, object],
    expected: str,
) -> None:
    workflows = _workflow_text() + _validation_text()
    assert workflows.count(ARTIFACT_EXPIRATION_QUERY) == 2
    jq = shutil.which("jq")
    assert jq is not None

    completed = subprocess.run(  # noqa: S603 - fixed jq command and test-owned input
        [jq, "--raw-output", ARTIFACT_EXPIRATION_QUERY],
        check=True,
        capture_output=True,
        input=json.dumps(artifact),
        text=True,
    )

    assert completed.stdout == f"{expected}\n"


def test_pypi_oidc_publisher_has_no_build_or_toolchain_bootstrap() -> None:
    pypi = _pypi_text()
    validation = _job(pypi, "validation")
    publish = _job(pypi, "publish")

    assert pypi.count("id-token: write") == 1
    assert "id-token: write" not in validation
    assert "id-token: write" in publish
    assert "contents: read" in publish
    assert "environment:\n      name: pypi" in publish

    uses = re.findall(r"(?m)^        uses: ([^\s]+)", publish)
    assert len(uses) == 2
    assert uses[0].startswith("actions/download-artifact@")
    assert uses[1].startswith("pypa/gh-action-pypi-publish@")
    for forbidden in (
        "actions/checkout@",
        "actions/setup-",
        "astral-sh/setup-uv@",
        "jdx/mise-action@",
        "enable-cache:",
        "cache:",
        "uv sync",
        "uv run",
        "uv build",
        "pip install",
        "python scripts/",
        "scripts/",
        "make ",
    ):
        assert forbidden not in publish
