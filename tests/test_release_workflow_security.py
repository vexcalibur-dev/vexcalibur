"""Security-contract tests for the GitHub release workflow."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

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
EXECUTION_REPORT_ORACLE = ROOT / "scripts" / "execution_report_oracle.py"
POSIX_PLATFORM_CONTRACT = ROOT / "scripts" / "check-execution-report-posix.sh"
WINDOWS_PLATFORM_CONTRACT = ROOT / "scripts" / "check-execution-report-windows.ps1"
PYPI_SELECTOR = ROOT / "scripts" / "select-pypi-release-files.py"
DIST_METADATA_WRAPPER = ROOT / "scripts" / "run-dist-metadata-verifier.sh"


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


def test_release_note_schema_versions_use_type_preserving_checks() -> None:
    release = _workflow_text()
    pypi = _pypi_text()
    exact_type_check = 'type(message.get("schema_version")) is int'

    assert release.count("has_exact_tag_schema_version() {") == 3
    assert release.count(exact_type_check) == 3
    assert release.count('has_exact_tag_schema_version "${tag_path}"') == 3
    assert pypi.count("has_exact_tag_schema_version() {") == 2
    assert pypi.count(exact_type_check) == 2
    assert pypi.count('has_exact_tag_schema_version "${tag_path}"') == 2


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


def test_canonical_distributions_are_built_once_and_never_rebuilt_for_pypi() -> None:
    validation = _validation_text()
    pypi = _pypi_text()
    build = _job(validation, "build")

    assert len(re.findall(r"(?<![\w-])uv\s+build(?=\s|$)", build)) == 1
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
    runtime_install = installer.rindex("pip install")
    assert export < build_sync < build < runtime_install
    assert "--require-hashes" in installer[build_sync:build]
    assert "--only-binary :all:" in installer[build_sync:build]
    assert "--no-build-isolation" in installer[build:runtime_install]
    assert "--offline" in installer[build:runtime_install]
    assert "mapfile" not in installer
    assert "shopt -s nullglob" in installer
    assert 'distribution="${built_wheels[0]}"' in installer[build:runtime_install]
    assert '"$uv_bin" venv --python "$python_bin" "$venv_dir"' in installer
    assert "--constraint" in installer[runtime_install:]
    assert "--requirements" in installer[runtime_install:]
    assert "--only-binary :all:" in installer[runtime_install:]
    assert 'constraints_file="${requirements_file}.constraints"' in installer
    assert ': >"$requirements_file"' in installer


def test_canonical_release_build_hash_locks_the_backend_and_builds_offline() -> None:
    build = _job(_validation_text(), "build")
    export = build.index("--only-group sdist-build")
    sync = build.index("uv pip sync", export)
    prepare = build.index("scripts/prepare-local-release-tag.sh", sync)
    package_build = build.index("uv build", sync)

    assert export < sync < prepare < package_build
    assert "--require-hashes" in build[sync:package_build]
    assert "--only-binary :all:" in build[sync:package_build]
    assert '"${VEXCALIBUR_BUILD_PYTHON}"' in build[prepare:package_build]
    assert "--no-build-isolation" in build[package_build:]
    assert "--offline" in build[package_build:]
    assert "--no-create-gitignore" in build[package_build:]
    assert "scripts/run-dist-metadata-verifier.sh dist" in build
    for required_file in (
        "pyproject.toml",
        "docs/execution-report-v1.schema.json",
        "docs/examples/generate_custom_execution_report.py",
        "docs/examples/generate_execution_report.py",
        "docs/examples/validate_execution_report.py",
    ):
        assert f"--required-sdist-file {required_file}" in build


def test_distribution_metadata_checks_use_one_isolated_locked_wrapper() -> None:
    validation = _validation_text()
    wrapper = DIST_METADATA_WRAPPER.read_text(encoding="utf-8")
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert validation.count("scripts/run-dist-metadata-verifier.sh dist") == 3
    assert "python scripts/verify-dist-metadata.py" not in validation
    assert "scripts/run-dist-metadata-verifier.sh" in PYPI_WORKFLOW.read_text(encoding="utf-8")
    assert "--isolated" in wrapper
    assert "--frozen" in wrapper
    assert "--only-group dist-verify" in wrapper
    assert "python -I -c" in wrapper
    assert 'sys.path.insert(0, str(repo_root / "scripts"))' in wrapper
    assert 'str(repo_root / "scripts" / "verify-dist-metadata.py")' in wrapper
    assert pyproject["tool"]["uv"]["default-groups"] == ["dev"]
    assert {"include-group": "dist-verify"} in pyproject["dependency-groups"]["dev"]
    assert pyproject["dependency-groups"]["dist-verify"] == [
        "packaging>=24,<27",
        "tomli>=2.4.0,<3; python_version < '3.11'",
    ]


def test_distribution_verifier_dependencies_do_not_enter_runtime_export(
    tmp_path: Path,
) -> None:
    uv = shutil.which("uv")
    assert uv is not None
    result = subprocess.run(  # noqa: S603 - resolved developer tool and reviewed project lock.
        [
            uv,
            "export",
            "--quiet",
            "--frozen",
            "--no-dev",
            "--no-emit-project",
            "--no-annotate",
            "--no-header",
            "--python",
            sys.executable,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "UV_CACHE_DIR": str(tmp_path / "uv-cache")},
    )

    assert re.search(r"(?m)^httpx==", result.stdout) is not None
    assert re.search(r"(?m)^(?:packaging|tomli)(?:==| @ )", result.stdout) is None


def test_ci_bounds_execution_report_jobs() -> None:
    ci = CI_WORKFLOW.read_text(encoding="utf-8")

    for job_name in (
        "execution-report-windows",
        "execution-report-macos",
        "installed-cli",
        "publication-version",
    ):
        assert "timeout-minutes:" in _job(ci, job_name)

    validation = _validation_text()
    for job_name in ("build", "installed-cli", "direct-vex", "action-vex", "publication-assets"):
        assert "timeout-minutes:" in _job(validation, job_name)


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
        "action-python-matrix",
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
    invocation = _step(windows, "Verify Windows platform contract")
    contract = WINDOWS_PLATFORM_CONTRACT.read_text(encoding="utf-8")

    assert 'python-version: ["3.10", "3.14"]' in windows
    assert "python-version: ${{ matrix.python-version }}" in windows
    assert "fetch-depth: 0" in checkout
    assert "scripts/check-execution-report-windows.ps1" in invocation
    assert '-ExpectedPython "${{ matrix.python-version }}"' in invocation
    assert '$ErrorActionPreference = "Stop"' in contract
    assert "$PSNativeCommandUseErrorActionPreference = $true" in contract
    assert 'if ($PSVersionTable.PSVersion -lt [Version]"7.3")' in contract
    assert "test_consumer_example_opens_inputs_in_binary_mode" in contract
    assert "Get-ChildItem -LiteralPath $resolvedDistributionDirectory -Filter *.whl" in contract
    assert "Get-ChildItem -LiteralPath $resolvedDistributionDirectory -Filter *.tar.gz" in contract
    build_export = contract.index("--only-group sdist-build")
    build_sync = contract.index("uv pip sync", build_export)
    sdist_build = contract.index("uv build", build_sync)
    append = contract.index("append_locked_distribution_requirement.py", sdist_build)
    runtime_install = contract.index("uv pip install", append)
    assert build_export < build_sync < sdist_build < append < runtime_install
    assert "--require-hashes" in contract[build_sync:sdist_build]
    assert "--only-binary :all:" in contract[build_sync:sdist_build]
    assert "--no-build-isolation" in contract[sdist_build:append]
    assert "--offline" in contract[sdist_build:append]
    assert "--require-hashes" in contract[runtime_install:]
    assert "--only-binary :all:" in contract[runtime_install:]
    assert "--constraint $constraints" in contract[runtime_install:]
    assert "--requirements $requirements" in contract[runtime_install:]
    assert "[System.IO.File]::WriteAllText(" in contract
    assert "VEXCALIBUR_EXPECTED_PYTHON" in contract
    assert "VEXCALIBUR_EXPECTED_VERSION" in contract


def test_macos_runs_native_lock_and_concurrency_contracts() -> None:
    macos = _job(CI_WORKFLOW.read_text(encoding="utf-8"), "execution-report-macos")
    invocation = _step(macos, "Verify POSIX platform contract")
    contract = POSIX_PLATFORM_CONTRACT.read_text(encoding="utf-8")

    assert 'python-version: ["3.10", "3.14"]' in macos
    assert "scripts/check-execution-report-posix.sh" in invocation
    assert "tests/test_execution_report_destination_locks.py" in contract
    assert "tests/test_generation_output_concurrency.py" in contract
    assert '"${dist_dir}"/*.whl' in contract
    assert '"${dist_dir}"/*.tar.gz' in contract
    assert "VEXCALIBUR_DISTRIBUTION=" in contract


def test_release_reruns_exact_commit_platform_contracts_before_finalizing() -> None:
    validation = _validation_text()
    release = _job(_workflow_text(), "validation")
    windows = _job(validation, "execution-report-windows")
    macos = _job(validation, "execution-report-macos")
    action_producer = _job(validation, "action-python-matrix")
    action_verifier = _job(validation, "action-python-matrix-verification")
    finalizer = _job(validation, "publication-assets")
    finalizer_condition = finalizer[: finalizer.index("    steps:\n")]

    assert "require-release-platform-contracts:" in validation
    assert (
        "default: false"
        in validation[
            validation.index("require-release-platform-contracts:") : validation.index(
                "unprivileged-ci-contract:"
            )
        ]
    )
    assert "require-release-platform-contracts: true" in release

    for native_job in (windows, macos):
        checkout = _step(native_job, "Checkout exact release source")
        download = _step(native_job, "Download exact release distributions")
        assert "inputs.require-release-platform-contracts" in native_job
        assert 'python-version: ["3.10", "3.14"]' in native_job
        assert "needs: [consent, build]" in native_job
        assert "ref: ${{ inputs.release-sha }}" in checkout
        assert "persist-credentials: false" in checkout
        assert "needs.build.outputs.artifact-name" in download
        assert "EXPECTED_WHEEL_SHA256" in native_job
        assert "EXPECTED_SDIST_SHA256" in native_job
        assert "needs.build.outputs.wheel-sha256" in native_job
        assert "needs.build.outputs.sdist-sha256" in native_job
        assert "-ExpectedVersion" in native_job or '"${EXPECTED_VERSION}"' in native_job
    assert "scripts/check-execution-report-windows.ps1" in windows
    assert "scripts/check-execution-report-posix.sh" in macos

    for matrix_job in (action_producer, action_verifier):
        assert 'python-version: ["3.10", "3.11", "3.12", "3.13", "3.14"]' in matrix_job
        assert "inputs.require-release-platform-contracts" in matrix_job
    assert "python-version: ${{ matrix.python-version }}" in action_producer
    assert 'allow-development-package-spec: "true"' in action_producer
    assert "runtime-constraints.txt" in action_producer
    assert "action-matrix-install-constraints.txt" in action_producer
    assert "printf '%s\\n' \"-r ${requirements_uri}\"" in action_producer
    assert (
        "constraints-file: ${{ runner.temp }}/action-matrix-install-constraints.txt"
        in action_producer
    )
    assert "EXPECTED_WHEEL_SHA256" in action_producer
    assert "sha256sum --check --strict" in action_producer
    assert "action-matrix-execution.json" in action_producer
    assert "action-matrix-vex.json" in action_producer
    assert "action-matrix-runtime.json" not in action_producer
    assert "vexcalibur-action.*/venv/bin/python" not in action_producer
    assert "Upload untrusted candidate Action outputs" in action_producer
    assert "Independently verify the generated report" not in action_producer

    assert "needs.action-python-matrix.result == 'success'" in action_verifier
    assert "Checkout exact release oracle" in action_verifier
    assert "ref: ${{ inputs.release-sha }}" in action_verifier
    assert "Download fresh publication inventory" in action_verifier
    assert "Download untrusted candidate Action outputs" in action_verifier
    assert "sha256sum --check --strict SHA256SUMS" in action_verifier
    assert "action-matrix-runtime.json" not in action_verifier
    assert "python3 -I scripts/execution_report_oracle.py" in action_verifier
    assert "--manifest" in action_verifier
    assert "--expected-sha" in action_verifier
    assert "--expected-version" in action_verifier
    assert "--expected-timestamp" in action_verifier

    for required_job in (
        "execution-report-windows",
        "execution-report-macos",
        "action-python-matrix-verification",
    ):
        assert f"      - {required_job}" in finalizer
        assert f"needs.{required_job}.result == 'success'" in finalizer_condition
    assert "!inputs.require-release-platform-contracts" in finalizer_condition


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
    assert "fetch-depth: ${{ inputs.release-tag-is-synthetic && 1 || 0 }}" in build
    assert "fetch-tags: ${{ !inputs.release-tag-is-synthetic }}" in build
    assert "scripts/prepare-local-release-tag.sh" in build
    assert "RELEASE_SHA: ${{ inputs.release-sha }}" in build
    assert "SETUPTOOLS_SCM_PRETEND_VERSION" not in build
    assert "SETUPTOOLS_SCM_PRETEND_METADATA" not in build
    assert "--no-create-gitignore" in build
    assert "scripts/normalize-sdist.py" in build
    assert "normalized-sdist-second-pass.tar.gz" in build
    assert 'cmp -- "${normalized_once}" "${normalized_twice}"' in build
    release_evidence = RELEASE_EVIDENCE.read_text(encoding="utf-8")
    execution_report_oracle = EXECUTION_REPORT_ORACLE.read_text(encoding="utf-8")
    assert "Draft202012Validator" in execution_report_oracle
    assert 'docs" / "execution-report-v1.schema.json' in release_evidence
    assert "vexcalibur.execution_report_validation" not in execution_report_oracle
    assert "parse_generation_execution_report" not in execution_report_oracle

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
    assert "scripts/" not in direct
    assert 'constraints="${RUNNER_TEMP}/direct-inventory/runtime-constraints.txt"' in direct
    assert '--constraint "${constraints}"' in direct
    assert '--requirements "${requirements}"' in direct
    assert "--require-hashes" in direct
    assert "--only-binary :all:" in direct
    assert "uv pip sync" not in direct
    assert "Upload only direct VEX output" in direct

    assert "needs: [build, publication-inventory]" in action
    assert "permissions: {}" in action
    assert "actions/checkout@" not in action
    assert "vexcalibur-dev/vexcalibur-action@" in action
    assert "action-validator-venv" in action
    assert "scripts/" not in action
    assert 'constraints="${inventory_dir}/runtime-constraints.txt"' in action
    assert "action-install-constraints.txt" in action
    assert "printf '%s\\n' \"-r ${constraints_uri}\"" in action
    assert action.count("constraints-file: ${{ runner.temp }}/action-install-constraints.txt") == 10
    assert '--constraint "${constraints}"' in action
    assert '--requirements "${requirements}"' in action
    assert "--require-hashes" in action
    assert "--only-binary :all:" in action
    assert "uv pip sync" not in action
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
    action_matrix = _job(validation, "action-python-matrix")
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
        re.findall(
            r"uses: vexcalibur-dev/vexcalibur-action@([0-9a-f]{40})",
            action + action_matrix,
        )
    )
    finalizer_commits = set(re.findall(r"--action-commit ([0-9a-f]{40})", finalizer))

    assert action_commits == {expected}
    assert finalizer_commits == {expected}


def test_negative_action_package_cases_use_a_known_success_command() -> None:
    action = _job(_validation_text(), "action-vex")

    for step_name in (
        "Reject a missing wheel URI hash",
        "Reject an incorrect wheel URI hash",
        "Reject an unhashed source-distribution fallback",
    ):
        step = _step(action, step_name)
        assert "args: --help" in step
        assert "args: --version" not in step


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
    assert 'if .expired == false then "current" else "invalid" end' in rest_verification
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
