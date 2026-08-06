"""Errors raised while binding and publishing execution-report files."""

from __future__ import annotations


class BoundFileDestinationError(Exception):
    """Raised when a destination cannot be prepared or published safely."""


class DestinationLockError(BoundFileDestinationError):
    """Raised when one bound destination cannot be locked."""

    def __init__(
        self,
        destination: object,
        cause: BoundFileDestinationError,
    ) -> None:
        super().__init__(str(cause))
        self.destination = destination


def _retain_cleanup_failures(
    primary: BaseException,
    failures: tuple[BaseException, ...],
) -> None:
    """Attach distinct cleanup failures without changing exception chaining."""
    retained = primary.__dict__.get("vexcalibur_cleanup_failures", ())
    if not isinstance(retained, tuple) or not all(
        isinstance(failure, BaseException) for failure in retained
    ):
        retained = ()
    merged: list[BaseException] = []
    for failure in (*retained, *failures):
        if failure is not primary and all(failure is not existing for existing in merged):
            merged.append(failure)
    if merged:
        primary.__dict__["vexcalibur_cleanup_failures"] = tuple(merged)
    else:
        primary.__dict__.pop("vexcalibur_cleanup_failures", None)
