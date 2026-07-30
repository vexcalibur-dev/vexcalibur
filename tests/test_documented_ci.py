from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_windows_installed_check_documents_expected_python() -> None:
    documentation = (ROOT / "docs/development/ci.md").read_text(encoding="utf-8")
    assignment = documentation.index("$env:VEXCALIBUR_EXPECTED_PYTHON")
    installed_check = documentation.index("& $python tests/integration/check_installed_windows.py")

    assert assignment < installed_check
