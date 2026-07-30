import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
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
