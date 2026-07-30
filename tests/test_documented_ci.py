from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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
