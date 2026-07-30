"""Security-contract tests for the GitHub release workflow."""

from __future__ import annotations

import json
import os
import re
import subprocess
import textwrap
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

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
    assert '--notes-file "${notes_path}"' in publish


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


def test_installed_cli_checks_wheel_and_sdist_on_every_supported_python() -> None:
    installed = _job(_validation_text(), "installed-cli")

    assert 'python-version: ["3.10", "3.11", "3.12", "3.13", "3.14"]' in installed
    assert 'distribution: ["wheel", "sdist"]' in installed
    assert "python-version: ${{ matrix.python-version }}" in installed
    assert "VEXCALIBUR_DISTRIBUTION:" in installed
    assert "VEXCALIBUR_EXPECTED_PYTHON: ${{ matrix.python-version }}" in installed
    assert "steps.dist.outputs[matrix.distribution]" in installed
    assert "VEXCALIBUR_WHEEL:" not in installed
    assert "make installed-cli-check" in installed


def test_sdist_validation_hash_locks_build_tools_and_builds_offline() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    build_requirements = pyproject["build-system"]["requires"]
    locked_build_requirements = pyproject["dependency-groups"]["sdist-build"]
    installer = (ROOT / "scripts" / "install-locked-distribution.sh").read_text(encoding="utf-8")

    assert locked_build_requirements == build_requirements
    assert "VEXCALIBUR_EXPECTED_PYTHON" in installer
    assert 'python find "${python_find_args[@]}"' in installer
    export = installer.index("--only-group sdist-build")
    build_sync = installer.index("pip sync", export)
    build = installer.index('"$uv_bin" build', build_sync)
    runtime_sync = installer.rindex("pip sync")
    assert export < build_sync < build < runtime_sync
    assert "--require-hashes" in installer[build_sync:build]
    assert "--only-binary :all:" in installer[build_sync:build]
    assert "--no-build-isolation" in installer[build:runtime_sync]
    assert "--offline" in installer[build:runtime_sync]
    assert "mapfile" not in installer
    assert "shopt -s nullglob" in installer
    assert 'distribution="${built_wheels[0]}"' in installer[build:runtime_sync]
    assert '"$uv_bin" venv --python "$python_bin" "$venv_dir"' in installer
    assert "--only-binary :all:" in installer[runtime_sync:]


def test_canonical_release_build_hash_locks_the_backend_and_builds_offline() -> None:
    build = _job(_validation_text(), "build")
    export = build.index("--only-group sdist-build")
    sync = build.index("uv pip sync", export)
    package_build = build.index("uv build", sync)

    assert export < sync < package_build
    assert "--require-hashes" in build[sync:package_build]
    assert "--only-binary :all:" in build[sync:package_build]
    assert "--no-build-isolation" in build[package_build:]
    assert "--offline" in build[package_build:]
    assert "--no-create-gitignore" in build[package_build:]
    for required_file in (
        "docs/execution-report-v1.schema.json",
        "docs/examples/generate_custom_execution_report.py",
        "docs/examples/generate_execution_report.py",
        "docs/examples/validate_execution_report.py",
    ):
        assert f"--required-sdist-file {required_file}" in build


def test_ci_runs_the_unprivileged_publication_contract_with_explicit_consent() -> None:
    ci = CI_WORKFLOW.read_text(encoding="utf-8")
    result = _job(ci, "ci")
    publication = _job(ci, "publication-contract")

    assert "uses: ./.github/workflows/release-validation.yml" in publication
    assert "release-sha: ${{ github.sha }}" in publication
    assert "release-tag: v0.0.0" in publication
    assert "release-version: 0.0.0" in publication
    assert "publication-only: true" in publication
    assert "unprivileged-ci-contract: true" in publication
    assert "allow-public-evidence-upload: true" in publication
    assert "needs.publication-contract.result" in result


def test_release_requires_explicit_public_evidence_upload_consent() -> None:
    validation = _validation_text()
    consent = _job(validation, "consent")
    release_validation = _job(_workflow_text(), "validation")

    assert "allow-public-evidence-upload:" in validation
    assert "required: true" in validation
    assert "ALLOW_PUBLIC_EVIDENCE_UPLOAD" in consent
    assert "explicit consent to upload public evidence" in consent
    assert "needs: consent" in _job(validation, "build")
    assert "allow-public-evidence-upload: true" in release_validation
    assert "UNPRIVILEGED_CI_CONTRACT" in consent
    assert "synthetic version v0.0.0" in consent


def test_every_reusable_workflow_uploader_descends_from_explicit_consent() -> None:
    validation = _validation_text()
    jobs_text = validation.partition("\njobs:\n")[2]
    dependencies = _workflow_job_dependencies(validation)
    uploaders = {
        job_name
        for job_name in dependencies
        if "actions/upload-artifact@" in _job(jobs_text, job_name)
    }

    assert uploaders == {
        "build",
        "publication-inventory",
        "direct-vex",
        "action-vex",
        "publication-assets",
    }
    assert all(
        _has_job_ancestor(
            dependencies,
            job_name=job_name,
            ancestor="consent",
        )
        for job_name in uploaders
    )


def test_uploader_consent_graph_check_rejects_an_ungated_job() -> None:
    dependencies = {
        "consent": set(),
        "build": {"consent"},
        "safe-upload": {"build"},
        "unsafe-upload": set(),
    }

    assert _has_job_ancestor(
        dependencies,
        job_name="safe-upload",
        ancestor="consent",
    )
    assert not _has_job_ancestor(
        dependencies,
        job_name="unsafe-upload",
        ancestor="consent",
    )


def test_windows_installs_wheel_and_sdist_with_locked_offline_builds() -> None:
    windows = _job(CI_WORKFLOW.read_text(encoding="utf-8"), "execution-report-windows")
    checkout = _step(windows, "Checkout")
    installed = _step(windows, "Verify installed-distribution Windows behavior")

    assert 'python-version: ["3.10", "3.14"]' in windows
    assert "python-version: ${{ matrix.python-version }}" in windows
    assert "fetch-depth: 0" in checkout
    assert '$ErrorActionPreference = "Stop"' in installed
    assert "$PSNativeCommandUseErrorActionPreference = $true" in installed
    assert 'if ($PSVersionTable.PSVersion -lt [Version]"7.3")' in installed
    assert "dist -Filter *.whl" in installed
    assert "dist -Filter *.tar.gz" in installed
    build_export = installed.index("--only-group sdist-build")
    build_sync = installed.index("uv pip sync", build_export)
    sdist_build = installed.index("uv build", build_sync)
    append = installed.index("append_locked_distribution_requirement.py", sdist_build)
    runtime_sync = installed.index("uv pip sync", append)
    assert build_export < build_sync < sdist_build < append < runtime_sync
    assert "--require-hashes" in installed[build_sync:sdist_build]
    assert "--only-binary :all:" in installed[build_sync:sdist_build]
    assert "--no-build-isolation" in installed[sdist_build:append]
    assert "--offline" in installed[sdist_build:append]
    assert "--require-hashes" in installed[runtime_sync:]
    assert "--only-binary :all:" in installed[runtime_sync:]
    assert "VEXCALIBUR_EXPECTED_PYTHON" in installed
    assert "VEXCALIBUR_EXPECTED_VERSION" in installed
    assert "uv pip install" not in installed


def test_macos_runs_native_lock_and_concurrency_contracts() -> None:
    macos = _job(CI_WORKFLOW.read_text(encoding="utf-8"), "execution-report-macos")
    native = _step(macos, "Verify native POSIX report transactions")
    installed = _step(macos, "Verify installed-distribution report generation")

    assert 'python-version: ["3.10", "3.14"]' in macos
    assert "tests/test_execution_report_destination_locks.py" in native
    assert "tests/test_generation_output_concurrency.py" in native
    assert "dist-macos/*.whl" in installed
    assert "dist-macos/*.tar.gz" in installed
    assert "VEXCALIBUR_DISTRIBUTION=" in installed


def test_candidate_publication_contract_runs_installed_distribution_matrix() -> None:
    installed = _job(_validation_text(), "installed-cli")

    assert "needs.build.result == 'success'" in installed
    assert "!inputs.publication-only" not in installed


def test_csaf_conformance_covers_wheel_and_sdist_on_boundary_pythons() -> None:
    csaf_checker = (ROOT / "scripts" / "check-installed-csaf.sh").read_text(encoding="utf-8")
    assert "VEXCALIBUR_DISTRIBUTION:-${VEXCALIBUR_WHEEL:-}" in csaf_checker
    assert '"$repo_root/scripts/install-locked-distribution.sh"' in csaf_checker
    for workflow in (
        CI_WORKFLOW.read_text(encoding="utf-8"),
        _validation_text(),
    ):
        csaf = _job(workflow, "csaf-conformance")
        assert 'python-version: ["3.10", "3.14"]' in csaf
        assert 'distribution: ["wheel", "sdist"]' in csaf
        assert "python-version: ${{ matrix.python-version }}" in csaf
        assert "VEXCALIBUR_DISTRIBUTION:" in csaf
        assert "VEXCALIBUR_EXPECTED_PYTHON: ${{ matrix.python-version }}" in csaf
        assert "make installed-csaf-check" in csaf
        assert "VEXCALIBUR_WHEEL:" not in csaf


def test_pinned_action_consumer_validates_success_and_failure_reports() -> None:
    validation = _validation_text()
    direct = _job(validation, "direct-vex")
    action = _job(validation, "action-vex")
    finalizer = _job(validation, "publication-assets")
    direct_validation = _step(direct, "Validate direct execution reports")
    action_validation = _step(action, "Validate Action execution reports")
    failed_validation = _step(
        action,
        "Require failed generation to leave no success artifacts",
    )
    synthetic_validation = _step(
        action,
        "Validate synthetic Action report conformance",
    )
    final_validation = _step(finalizer, "Verify downloaded artifact bindings")

    assert direct.count("--execution-report") == 3
    assert action.count("--execution-report") == 7
    for job, metadata_step_name in (
        (direct, "Record direct VEX artifact name"),
        (action, "Record Action VEX artifact name"),
    ):
        assert "vex.cdx.execution.json" in job
        assert "vex.openvex.execution.json" in job
        assert "vexcalibur-vex.execution.json" in job
        metadata = _step(job, metadata_step_name)
        assert ".vexcalibur-locks" in metadata
        assert "directory.lock" in metadata
        assert 'test "$(stat --format=%a -- "${lock_dir}")" = 700' in metadata
        assert 'test "$(stat --format=%a -- "${lock_dir}/directory.lock")" = 600' in metadata
        assert '! -type f ! -path "${lock_dir}"' in metadata
    for validation_step in (direct_validation, action_validation):
        assert "-m vexcalibur.execution_report_validation" in validation_step
        assert "--format cyclonedx" in validation_step
        assert "formats+=(--format openvex --format csaf)" in validation_step
        assert '--finding-count "${ASSERTION_COUNT}"' in validation_step
    assert "failed-generation-action.outcome" in failed_validation
    assert 'test "${FAILED_GENERATION_OUTCOME}" = failure' in failed_validation
    assert "failed.execution.json" in failed_validation
    for output_format in ("cyclonedx", "openvex", "csaf"):
        assert f"--format {output_format}" in synthetic_validation
    assert "-m vexcalibur.execution_report_validation" in synthetic_validation
    assert "--finding-count 1" in synthetic_validation
    for step_name in (
        "Generate synthetic CycloneDX report through the pinned Action",
        "Generate synthetic OpenVEX report through the pinned Action",
        "Generate synthetic CSAF report through the pinned Action",
    ):
        assert "if:" not in _step(action, step_name)
    assert final_validation.count("expected_vex_files=") == 2
    assert final_validation.count("vex.cdx.execution.json") == 2
    assert final_validation.count("vex.openvex.execution.json") == 1
    assert final_validation.count("vexcalibur-vex.execution.json") == 1
    assert 'test "${actual_vex_files}" = "${expected_vex_files}"' in final_validation


def test_publication_jobs_keep_oracle_and_candidate_execution_isolated() -> None:
    validation = _validation_text()
    build = _job(validation, "build")
    inventory = _job(validation, "publication-inventory")
    direct = _job(validation, "direct-vex")
    action = _job(validation, "action-vex")
    finalizer = _job(validation, "publication-assets")

    assert "needs: consent" in build
    assert "contents: read" in build
    assert "actions: write" not in build
    assert "id-token: write" not in build
    assert "actions/checkout@" in build
    assert "persist-credentials: false" in build
    assert "scripts/prepare-local-release-tag.sh" in build
    assert "RELEASE_SHA: ${{ inputs.release-sha }}" in build
    assert "SETUPTOOLS_SCM_PRETEND_VERSION" not in build
    assert "SETUPTOOLS_SCM_PRETEND_METADATA" not in build
    assert "--no-create-gitignore" in build
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
    assert "action-validator-venv" in action
    assert "Upload only Action VEX output" in action

    for producer in ("build", "publication-inventory", "direct-vex", "action-vex"):
        assert f"      - {producer}" in finalizer
    assert finalizer.count("actions/download-artifact@") == 4
    assert "finalize-publication" in finalizer
    assert "verify-publication" in finalizer
    assert "uv sync --frozen --group dev" in finalizer
    assert "--no-install-project" not in finalizer


def test_action_validation_and_evidence_use_one_exact_action_commit() -> None:
    validation = _validation_text()
    action = _job(validation, "action-vex")
    finalizer = _job(validation, "publication-assets")
    evidence = RELEASE_EVIDENCE.read_text(encoding="utf-8")
    expected_match = re.search(
        r'^PUBLICATION_ACTION_COMMIT = "([0-9a-f]{40})"',
        evidence,
        flags=re.MULTILINE,
    )
    assert expected_match is not None
    expected = expected_match.group(1)

    action_commits = set(
        re.findall(r"uses: vexcalibur-dev/vexcalibur-action@([0-9a-f]{40})", action)
    )
    finalizer_commits = set(re.findall(r"--action-commit ([0-9a-f]{40})", finalizer))

    assert action_commits == {expected}
    assert finalizer_commits == {expected}


def test_publication_only_finalizer_requires_the_installed_matrix() -> None:
    finalizer = _job(_validation_text(), "publication-assets")
    condition = finalizer[: finalizer.index("    steps:\n")]
    mode_branch = condition[condition.index("      (") :]

    assert "needs.installed-cli.result == 'success'" in condition
    assert condition.index("needs.installed-cli.result == 'success'") < condition.index(
        "inputs.publication-only"
    )
    assert (
        "needs.installed-cli.result"
        not in mode_branch[mode_branch.index("inputs.publication-only") :]
    )


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
