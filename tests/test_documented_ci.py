import os
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")
VERSION_BODY_PATTERN = (
    r"(0|[1-9][0-9]{0,5})\."
    r"(0|[1-9][0-9]{0,5})\."
    r"(0|[1-9][0-9]{0,5})"
)
RELEASE_VERSION_PATTERN = f"^{VERSION_BODY_PATTERN}$"
RECOVERY_TAG_PATTERN = f"^v{VERSION_BODY_PATTERN}$"


def test_windows_documentation_uses_the_canonical_platform_contract() -> None:
    documentation = (ROOT / "docs/development/ci.md").read_text(encoding="utf-8")
    contract = (ROOT / "scripts/check-execution-report-windows.ps1").read_text(encoding="utf-8")
    assignment = contract.index("$env:VEXCALIBUR_EXPECTED_PYTHON = $ExpectedPython")
    installed_check = contract.index("& $python tests/integration/check_installed_windows.py")

    assert "scripts/check-execution-report-windows.ps1" in documentation
    assert assignment < installed_check


def test_windows_platform_contract_references_existing_pytest_nodes() -> None:
    contract = (ROOT / "scripts/check-execution-report-windows.ps1").read_text(encoding="utf-8")
    node_ids = re.findall(
        r"(?m)^\s+(tests/[A-Za-z0-9_./-]+[.]py::test_[A-Za-z0-9_]+)",
        contract,
    )

    assert node_ids
    for node_id in node_ids:
        relative_path, test_name = node_id.split("::", maxsplit=1)
        test_module = (ROOT / relative_path).read_text(encoding="utf-8")
        assert re.search(rf"(?m)^def {re.escape(test_name)}\(", test_module), node_id


def test_execution_report_schema_checkout_bytes_are_pinned_to_lf() -> None:
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()

    assert "docs/execution-report-v1.schema.json text eol=lf" in attributes


def test_release_recovery_guide_preflights_before_dispatch() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    documentation = (ROOT / "docs/how-to/publish-to-pypi.md").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    pypi_workflow = (ROOT / ".github/workflows/pypi.yml").read_text(encoding="utf-8")
    section = documentation.split("## Recover an interrupted GitHub Release", maxsplit=1)[1]
    section = section.split("\n## ", maxsplit=1)[0]

    assert RECOVERY_TAG_PATTERN in section
    assert RECOVERY_TAG_PATTERN in workflow
    assert RECOVERY_TAG_PATTERN in pypi_workflow
    assert readme.count(RELEASE_VERSION_PATTERN) == 2
    contracts = (
        "Release tag must look like v1.2.3 without leading zeros.",
        "git pull --ff-only origin main",
        '"refs/tags/${RELEASE_TAG}:${RECOVERY_REF}"',
        'git cat-file -t "$RECOVERY_REF"',
        'git merge-base --is-ancestor "$RELEASE_SHA" "$MAIN_SHA"',
        'scripts/check-recovery-contract.py --ref "$RELEASE_SHA"',
        'read -r -p "Type ${RELEASE_TAG}',
        "gh workflow run release.yml",
    )

    positions = [section.index(contract) for contract in contracts]
    assert positions == sorted(positions)

    for version in ("0.0.0", "1.2.3", "999999.999999.999999"):
        assert re.fullmatch(RELEASE_VERSION_PATTERN, version) is not None
        tag = f"v{version}"
        assert re.fullmatch(RECOVERY_TAG_PATTERN, tag) is not None
    for version in ("01.2.3", "1.02.3", "1.2.03", "1000000.0.0", "1.2.3-rc1"):
        assert re.fullmatch(RELEASE_VERSION_PATTERN, version) is None
        tag = f"v{version}"
        assert re.fullmatch(RECOVERY_TAG_PATTERN, tag) is None


def test_release_recovery_guide_requires_exact_tag_schema_version() -> None:
    documentation = (ROOT / "docs/how-to/publish-to-pypi.md").read_text(encoding="utf-8")

    assert documentation.count("has_exact_tag_schema_version() {") == 1
    assert 'type(message.get("schema_version")) is int' in documentation
    assert 'has_exact_tag_schema_version "$TAG_OBJECT"' in documentation


def test_release_recovery_guide_fails_closed_when_status_cannot_run(tmp_path: Path) -> None:
    if BASH is None:
        raise RuntimeError("bash is required to test documented recovery")
    documentation = (ROOT / "docs/how-to/publish-to-pypi.md").read_text(encoding="utf-8")
    section = documentation.split("## Recover an interrupted GitHub Release", maxsplit=1)[1]
    script = section.split("```bash\n", maxsplit=1)[1].split("\n```", maxsplit=1)[0]
    script = script.replace("REPLACE_WITH_RELEASE_TAG", "v1.2.3")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "gh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (fake_bin / "git").write_text(
        '#!/bin/sh\nif [ "$1" = "status" ]; then\n  exit 73\nfi\nexit 74\n',
        encoding="utf-8",
    )
    (fake_bin / "gh").chmod(0o755)
    (fake_bin / "git").chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"

    completed = subprocess.run(  # noqa: S603
        [BASH, "-c", script],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
        env=env,
    )

    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == "Could not inspect the worktree before recovery.\n"


def test_publication_verification_guide_stops_after_a_failed_fetch(tmp_path: Path) -> None:
    if BASH is None:
        raise RuntimeError("bash is required to test publication verification")
    documentation = (ROOT / "docs/reference/release-evidence.md").read_text(encoding="utf-8")
    section = documentation.split(
        "Verify a schema-2 publication bundle against an exact tag and commit:",
        maxsplit=1,
    )[1]
    script = section.split("```bash\n", maxsplit=1)[1].split("\n```", maxsplit=1)[0]
    script = script.replace("REPLACE_WITH_RELEASE_TAG", "v1.2.3")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    rev_parse_marker = tmp_path / "rev-parse-ran"
    (fake_bin / "git").write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "fetch" ]; then\n'
        "  exit 73\n"
        "fi\n"
        'if [ "$1" = "update-ref" ]; then\n'
        "  exit 0\n"
        "fi\n"
        'if [ "$1" = "rev-parse" ]; then\n'
        '  : > "$REV_PARSE_MARKER"\n'
        "fi\n"
        "exit 74\n",
        encoding="utf-8",
    )
    (fake_bin / "git").chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["REV_PARSE_MARKER"] = str(rev_parse_marker)

    completed = subprocess.run(  # noqa: S603
        [BASH, "-c", script],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
        env=env,
    )

    assert completed.returncode == 73
    assert not rev_parse_marker.exists()
