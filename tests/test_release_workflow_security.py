"""Security-contract tests for the GitHub release workflow."""

from __future__ import annotations

import re
from pathlib import Path

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


def _validation_text() -> str:
    return RELEASE_VALIDATION_WORKFLOW.read_text(encoding="utf-8")


def _pypi_text() -> str:
    return PYPI_WORKFLOW.read_text(encoding="utf-8")


def _workflow_call_outputs(text: str) -> set[str]:
    start = text.index("    outputs:\n")
    end = text.index("\npermissions:\n", start)
    return set(re.findall(r"(?m)^      ([a-z][a-z0-9-]*):\n", text[start:end]))


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


def test_release_note_recovery_uses_the_protected_tag_as_its_trust_anchor() -> None:
    generate = _step(_job(_workflow_text(), "generate-release-notes"), "Generate release notes")

    tag_recovery = generate.index("recover_tag_notes")
    release_body = generate.index("existing-release-body.md")
    regenerate = generate.index('"repos/${GITHUB_REPOSITORY}/releases/generate-notes"')
    assert tag_recovery < release_body < regenerate
    assert ".draft == true and (.immutable == false or .immutable == null)" in generate
    assert ".draft == false and .immutable == true" in generate
    assert ".target_commitish == $sha" in generate
    assert ".author.login == $author" in generate
    assert "($message | keys) ==" in generate
    assert '["release_notes", "release_notes_sha256", "schema_version", "tag"]' in generate
    assert ".tagger.name == $name and .tagger.email == $email" in generate
    assert 'cmp --silent "${notes_path}" "${release_body}"' in generate
    assert "Existing release notes differ from the protected tag payload." in generate


def test_scanned_release_notes_are_embedded_in_every_annotated_tag_contract() -> None:
    publish = _job(_workflow_text(), "publish-release")
    create_tag = _step(publish, "Create release tag")
    immutable = _step(publish, "Publish immutable GitHub Release")

    for boundary in (create_tag, immutable):
        assert "(.message | fromjson) as $message" in boundary
        assert "$message.release_notes_sha256 == $notes_sha256" in boundary
        assert "$message.release_notes == $release_notes" in boundary
        assert '--rawfile release_notes "${notes_path}"' in boundary
    assert "release_notes_sha256: $notes_sha256" in create_tag
    assert "release_notes: $release_notes" in create_tag
    assert '--rawfile message "${tag_message_path}"' in create_tag


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
    assert '.object.type == "tag"' in boundary
    assert "(.message | fromjson) as $message" in boundary
    assert "Protected release notes changed after validation." in boundary


def test_pypi_manual_recovery_is_bound_to_the_exact_dispatch_tag() -> None:
    resolve = _job(_pypi_text(), "resolve")

    assert "WORKFLOW_REF: ${{ github.ref }}" in resolve
    assert 'expected_ref="refs/tags/${tag}"' in resolve
    assert '"${WORKFLOW_REF}" != "${expected_ref}"' in resolve
    assert "dispatch with --ref ${tag} and release-tag=${tag}" in resolve


def test_release_and_pypi_bind_every_asset_to_the_automation_uploader() -> None:
    release = _job(_workflow_text(), "publish-release")
    reconcile = _step(release, "Reconcile exact release assets")
    immutable = _step(release, "Publish immutable GitHub Release")

    assert "APP_SLUG: ${{ steps.app-token.outputs.app-slug }}" in reconcile
    assert 'expected_uploader="${APP_SLUG}[bot]"' in reconcile
    assert ".uploader.login" in reconcile
    assert '.label // ""' in reconcile
    assert "unexpected uploader or display label" in reconcile
    assert "uploader: .uploader.login" in immutable
    assert "label: .label" in immutable
    assert '(.label == null or .label == "")' in immutable
    assert immutable.count(".uploader == $uploader") >= 1
    assert immutable.count(".uploader.login == $uploader") >= 1

    pypi = _pypi_text()
    resolve = _step(_job(pypi, "resolve"), "Resolve release, tag, and main ancestry")
    download = _step(
        _job(pypi, "validation"),
        "Download exact GitHub Release assets",
    )
    re_resolve = _step(
        _job(pypi, "publish"),
        "Re-resolve validated release tag",
    )
    for boundary in (resolve, download, re_resolve):
        assert "/assets?per_page=100" in boundary
        assert "AUTOMATION_BOT_LOGIN" in boundary
        assert ".uploader.login == $uploader" in boundary
        assert '(.label == null or .label == "")' in boundary


def test_distributions_are_built_once_and_never_rebuilt_for_pypi() -> None:
    validation = _validation_text()
    pypi = _pypi_text()

    assert len(re.findall(r"(?<![\w-])uv\s+build(?=\s|$)", validation)) == 1
    for build_command in (
        r"(?<![\w-])uv\s+build(?=\s|$)",
        r"python(?:3)?\s+-m\s+build(?=\s|$)",
        r"(?<![\w-])pip\s+wheel(?=\s|$)",
        r"(?<![\w-])hatch\s+build(?=\s|$)",
        r"(?<![\w-])poetry\s+build(?=\s|$)",
    ):
        assert re.search(build_command, pypi) is None


def test_reusable_validation_exposes_exact_byte_and_artifact_bindings() -> None:
    validation = _validation_text()

    assert _workflow_call_outputs(validation) == {
        "sha",
        "tag",
        "version",
        "wheel-sha256",
        "sdist-sha256",
        "dist-artifact",
        "dist-artifact-digest",
        "release-assets-artifact",
        "release-assets-sha256",
        "release-assets-artifact-digest",
    }
    assert "value: ${{ jobs.build.outputs.wheel-sha256 }}" in validation
    assert "value: ${{ jobs.build.outputs.sdist-sha256 }}" in validation
    assert "value: ${{ jobs.build.outputs.artifact-digest }}" in validation
    assert "value: ${{ jobs.publication-assets.outputs.artifact-digest }}" in validation


def test_ci_requires_the_credentialless_publication_contract() -> None:
    ci = CI_WORKFLOW.read_text(encoding="utf-8")
    publication = _job(ci, "publication-contract")
    result = _job(ci, "ci")

    assert "uses: ./.github/workflows/release-validation.yml" in publication
    assert "actions: read" in publication
    assert "contents: read" in publication
    assert "release-sha: ${{ github.sha }}" in publication
    assert "release-tag: v0.0.0" in publication
    assert "release-version: 0.0.0" in publication
    assert "publication-only: true" in publication
    assert "synthetic-ci-version: true" in publication
    assert "id-token: write" not in publication
    assert "secrets:" not in publication

    assert "publication-contract" in result
    assert "needs.publication-contract.result" in result


def test_publication_jobs_keep_oracle_and_candidate_execution_isolated() -> None:
    validation = _validation_text()
    build = _job(validation, "build")
    inventory = _job(validation, "publication-inventory")
    direct = _job(validation, "direct-vex")
    action = _job(validation, "action-vex")
    finalizer = _job(validation, "publication-assets")

    assert "needs:" not in build
    assert "contents: read" in build
    assert "actions: write" not in build
    assert "id-token: write" not in build
    assert "actions/checkout@" in build
    assert "persist-credentials: false" in build
    assert "scripts/prepare-local-release-tag.sh" in build
    assert "inputs.synthetic-ci-version" in build
    assert "scripts/normalize-sdist.py" in build
    assert "normalized-sdist-second-pass.tar.gz" in build
    assert 'cmp -- "${normalized_once}" "${normalized_twice}"' in build

    assert "needs: build" in inventory
    assert "contents: read" in inventory
    assert "actions: write" not in inventory
    assert "id-token: write" not in inventory
    assert "actions/checkout@" in inventory
    assert "persist-credentials: false" in inventory
    assert "prepare-publication-inventory" in inventory
    assert "verify-publication-inventory" in inventory
    helper_sync = "uv sync --frozen --no-install-project --group dev"
    assert helper_sync in inventory

    assert "needs: [build, publication-inventory]" in direct
    assert "permissions: {}" in direct
    assert "actions/checkout@" not in direct
    assert "vexcalibur-action@" not in direct
    assert "Install the exact locked wheel" in direct
    assert "Upload only direct VEX output" in direct

    assert "needs: [build, publication-inventory]" in action
    assert "permissions: {}" in action
    assert "actions/checkout@" not in action
    assert "vexcalibur-dev/vexcalibur-action@" in action
    assert "Upload only Action VEX output" in action

    for producer in ("build", "publication-inventory", "direct-vex", "action-vex"):
        assert f"      - {producer}" in finalizer
    assert finalizer.count("actions/download-artifact@") == 4
    assert "finalize-publication" in finalizer
    assert "verify-publication" in finalizer
    assert helper_sync in finalizer


def test_publication_inventory_never_consumes_or_executes_the_candidate() -> None:
    inventory = _job(_validation_text(), "publication-inventory")

    for forbidden in (
        "actions/download-artifact@",
        "vexcalibur-action@",
        "uv build",
        "finalize-publication",
        ".whl",
        ".tar.gz",
        "package-spec",
    ):
        assert forbidden not in inventory
    assert "uv sync --frozen --no-install-project --group dev" in inventory
    assert "uv.lock" in inventory
    assert "release-evidence/review.json" in inventory
    assert "release-evidence/findings.json" in inventory


def test_transient_archives_are_rest_verified_but_not_manifest_provenance() -> None:
    validation = _validation_text()
    finalizer = _job(validation, "publication-assets")
    evidence = RELEASE_EVIDENCE.read_text(encoding="utf-8")

    for producer_name in ("build", "publication-inventory", "direct-vex", "action-vex"):
        producer = _job(validation, producer_name)
        assert "artifact-id: ${{ steps.upload.outputs.artifact-id }}" in producer
        assert "artifact-digest: ${{ steps.upload.outputs.artifact-digest }}" in producer

    rest_verification = _step(finalizer, "Verify producer artifact identities and upload digests")
    assert "actions/artifacts/${expected_id}" in rest_verification
    assert "[.id, .name, .digest, (.expired | tostring), .workflow_run.id]" in rest_verification
    assert "actions/artifacts/${expected_id}/zip" in rest_verification
    assert 'test "${run_id}" = "${GITHUB_RUN_ID}"' in rest_verification
    assert "sha256sum --check --strict" in rest_verification

    assembly = _step(finalizer, "Assemble and verify the flat schema-v2 asset set")
    assert "ARTIFACT_DIGEST" not in assembly
    assert "artifact-digest" not in assembly
    assert '"payload_sha256"' in evidence
    assert '"payload_digest_algorithm"' in evidence
    assert '"actions_artifact_name"' in evidence
    assert "actions_artifact_digest" not in evidence
    assert "actions_artifact_id" not in evidence


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

    assert "--draft" in create
    assert "--verify-tag" in create
    assert "--target" in create
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


def test_all_untrusted_assets_and_notes_are_verified_before_write_token() -> None:
    publish = _job(_workflow_text(), "publish-release")

    assets = publish.index("name: Verify validated release assets")
    notes = publish.index("name: Verify scanned release notes")
    policy = publish.index("name: Preflight immutable release policy and target")
    token = publish.index("name: Generate app token")
    tag = publish.index("name: Create release tag")
    assert assets < notes < policy < token < tag

    before_token = publish[:token]
    assert "actions/runs/${GITHUB_RUN_ID}/artifacts" in before_token
    assert "sha256sum --check --strict SHA256SUMS" in before_token
    assert "Publisher release notes do not match the scanned digest" in before_token
    assert "secrets.AUTOMATION_SECRET" not in before_token


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
