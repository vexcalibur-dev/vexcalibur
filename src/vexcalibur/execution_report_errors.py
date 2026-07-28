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
