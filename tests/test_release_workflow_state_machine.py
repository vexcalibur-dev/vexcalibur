"""Security-contract tests for the GitHub release workflow."""

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
RELEASE_VALIDATION_WORKFLOW = ROOT / ".github" / "workflows" / "release-validation.yml"
PYPI_WORKFLOW = ROOT / ".github" / "workflows" / "pypi.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_EVIDENCE = ROOT / "scripts" / "release_evidence.py"
PYPI_SELECTOR = ROOT / "scripts" / "select-pypi-release-files.py"


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


def test_release_publisher_rest_binds_the_downloaded_validation_artifact() -> None:
    publish = _job(_workflow_text(), "publish-release")
    verification = _step(publish, "Verify validated release assets")

    assert "needs.validation.outputs.release-assets-artifact" in publish
    assert "needs.validation.outputs.release-assets-artifact-digest" in publish
    assert "needs.validation.outputs.release-assets-sha256" in publish
    assert "actions/runs/${GITHUB_RUN_ID}/artifacts?per_page=100" in verification
    assert "Expected exactly one current-run artifact" in verification
    assert ".name, .expired, .digest" in verification
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
