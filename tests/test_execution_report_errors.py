from __future__ import annotations

from vexcalibur.execution_report_errors import _retain_cleanup_failures


def test_cleanup_failures_exclude_primary_and_normalize_existing_values() -> None:
    primary = RuntimeError("primary")
    first = RuntimeError("first cleanup")
    second = RuntimeError("second cleanup")
    primary.vexcalibur_cleanup_failures = (first, first, primary)  # type: ignore[attr-defined]

    _retain_cleanup_failures(primary, (primary, second, first))

    assert primary.vexcalibur_cleanup_failures == (first, second)  # type: ignore[attr-defined]


def test_cleanup_failures_remove_empty_existing_diagnostics() -> None:
    primary = RuntimeError("primary")
    primary.vexcalibur_cleanup_failures = (primary,)  # type: ignore[attr-defined]

    _retain_cleanup_failures(primary, (primary,))

    assert "vexcalibur_cleanup_failures" not in primary.__dict__
