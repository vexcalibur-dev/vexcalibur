"""Generation output preparation, staging, and publication."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import ExitStack, nullcontext, suppress
from pathlib import Path
from types import TracebackType
from typing import BinaryIO, NoReturn

from vexcalibur.execution_report_destination import (
    BoundFileDestination,
    BoundFileDestinationError,
    DestinationLockError,
    StagedFileWrite,
    acquire_destination_locks,
    acquire_stdout_sequence_lock,
)
from vexcalibur.execution_report_staging import PublishedFileRollback
from vexcalibur.generation_result import GenerationResult


class GenerationOutputError(Exception):
    """Base class for a failed generation output transaction."""


class GenerationOutputPreparationError(GenerationOutputError):
    """Raised when output destinations cannot be bound before generation."""

    def __init__(
        self,
        destination: Path,
        role: str,
        cause: BoundFileDestinationError,
    ) -> None:
        super().__init__(_label_destination_error(cause, role=role))
        self.destination = destination
        self.role = role


class GenerationReportConstructionError(GenerationOutputError):
    """Raised before publication when a result cannot form a report."""


class GenerationDocumentWriteError(GenerationOutputError):
    """Raised when the generated VEX document cannot be written."""

    def __init__(self, destination: Path | None, cause: BaseException) -> None:
        super().__init__(str(cause))
        self.destination = destination


class GenerationReportWriteError(GenerationOutputError):
    """Raised when a staged report cannot be published."""

    def __init__(self, destination: Path, cause: BaseException) -> None:
        super().__init__(str(cause))
        self.destination = destination


class GenerationOutputCleanupError(GenerationOutputError):
    """Raised when a completed or aborted output transaction cannot close."""


def write_generation_document(
    result: GenerationResult,
    *,
    output_path: Path | None,
    write_text_stdout: Callable[[str], None],
) -> None:
    """Write one generated document without execution-report staging."""
    if output_path is None:
        try:
            write_text_stdout(result.rendered_document)
        except OSError as exc:
            raise GenerationDocumentWriteError(None, exc) from exc
        return
    try:
        output_path.write_text(result.rendered_document, encoding="utf-8")
    except OSError as exc:
        raise GenerationDocumentWriteError(output_path, exc) from exc


_GENERATION_OUTPUT_TRANSACTION_TOKEN = object()


class GenerationOutputTransaction:
    """Prepared VEX and report destinations with one-shot publication state."""

    __slots__ = (
        "_closed",
        "_consumed",
        "_discard_report_on_close",
        "_report_rollback",
        "output_destination",
        "output_path",
        "protected_descriptors",
        "report_destination",
    )

    def __init__(
        self,
        construction_token: object,
        *,
        output_path: Path | None,
        report_destination: BoundFileDestination,
        output_destination: BoundFileDestination | None,
        protected_descriptors: tuple[tuple[int, str], ...],
    ) -> None:
        if construction_token is not _GENERATION_OUTPUT_TRANSACTION_TOKEN:
            raise TypeError("use GenerationOutputTransaction.prepare()")
        self.output_path = output_path
        self.report_destination = report_destination
        self.output_destination = output_destination
        self.protected_descriptors = protected_descriptors
        self._consumed = False
        self._closed = False
        self._discard_report_on_close = False
        self._report_rollback: PublishedFileRollback | None = None

    @classmethod
    def _create(
        cls,
        *,
        output_path: Path | None,
        report_destination: BoundFileDestination,
        output_destination: BoundFileDestination | None,
        protected_descriptors: tuple[tuple[int, str], ...],
    ) -> GenerationOutputTransaction:
        return cls(
            _GENERATION_OUTPUT_TRANSACTION_TOKEN,
            output_path=output_path,
            report_destination=report_destination,
            output_destination=output_destination,
            protected_descriptors=protected_descriptors,
        )

    @property
    def closed(self) -> bool:
        """Return whether every retained destination has been closed."""
        return self._closed

    @classmethod
    def prepare(
        cls,
        *,
        output_path: Path | None,
        report_path: Path,
        protected_paths: tuple[Path | None, ...],
        protected_descriptors: tuple[tuple[int, str], ...] = (),
    ) -> GenerationOutputTransaction:
        """Bind paths and durably remove a stale report before generation."""
        with ExitStack() as destinations:
            try:
                report_destination = BoundFileDestination.prepare(
                    report_path,
                    protected_paths=(*protected_paths, output_path),
                    protected_descriptors=protected_descriptors,
                    remove_existing=True,
                )
            except BoundFileDestinationError as exc:
                raise GenerationOutputPreparationError(
                    report_path,
                    "execution report",
                    exc,
                ) from exc
            _register_destination_close(destinations, report_destination)

            try:
                output_destination = (
                    BoundFileDestination.prepare(output_path) if output_path is not None else None
                )
            except BoundFileDestinationError as exc:
                if output_path is None:
                    raise AssertionError("VEX output path is unavailable") from exc
                raise GenerationOutputPreparationError(
                    output_path,
                    "VEX output",
                    exc,
                ) from exc
            if output_destination is not None:
                _register_destination_close(destinations, output_destination)

            if output_destination is not None and report_destination.aliases(output_destination):
                cause = BoundFileDestinationError(
                    "--execution-report must not replace an input or VEX output file",
                )
                raise GenerationOutputPreparationError(
                    report_path,
                    "execution report",
                    cause,
                )

            transaction = cls._create(
                output_path=output_path,
                report_destination=report_destination,
                output_destination=output_destination,
                protected_descriptors=protected_descriptors,
            )
            destinations.pop_all()
            return transaction

    def commit(
        self,
        result: GenerationResult,
        *,
        binary_stdout: BinaryIO | None = None,
    ) -> None:
        """Publish VEX, then publish its staged report as the success marker."""
        if self.closed:
            raise GenerationOutputError("generation output transaction is already closed")
        if self._consumed:
            raise GenerationOutputError("generation output transaction is already consumed")
        self._consumed = True
        self._commit(
            result,
            binary_stdout=binary_stdout,
        )

    def _commit(
        self,
        result: GenerationResult,
        *,
        binary_stdout: BinaryIO | None,
    ) -> None:
        try:
            report_bytes = result.execution_report().to_json().encode("utf-8")
        except (UnicodeError, ValueError) as exc:
            raise GenerationReportConstructionError(str(exc)) from exc

        staged_report: StagedFileWrite | None = None
        report_rollback: PublishedFileRollback | None = None
        pending_failure: BaseException | None = None
        pending_traceback: TracebackType | None = None
        pending_cause: BaseException | None = None
        try:
            with ExitStack() as stack:
                try:
                    staged_report = stack.enter_context(
                        self.report_destination.stage_bytes(report_bytes)
                    )
                    self.report_destination.verify_parent_path()
                except BoundFileDestinationError as exc:
                    raise GenerationReportWriteError(
                        self.report_destination.requested_path,
                        exc,
                    ) from exc

                try:
                    staged_output = (
                        stack.enter_context(
                            self.output_destination.stage_bytes(result.rendered_bytes)
                        )
                        if self.output_destination is not None
                        else None
                    )
                    if self.output_destination is not None:
                        self.output_destination.verify_parent_path()
                except BoundFileDestinationError as exc:
                    raise GenerationDocumentWriteError(self.output_path, exc) from exc

                try:
                    stdout_sequence = (
                        acquire_stdout_sequence_lock(self.report_destination)
                        if staged_output is None
                        else nullcontext()
                    )
                    with stdout_sequence:
                        if staged_output is None:
                            with acquire_destination_locks((self.report_destination,)):
                                self._remove_existing_report()
                            try:
                                if binary_stdout is None:
                                    raise OSError("binary standard output is unavailable")
                                _write_all(binary_stdout, result.rendered_bytes)
                                binary_stdout.flush()
                            except (OSError, TypeError, ValueError) as exc:
                                with acquire_destination_locks((self.report_destination,)):
                                    self._remove_existing_report()
                                raise GenerationDocumentWriteError(None, exc) from exc

                        with acquire_destination_locks(
                            (self.output_destination, self.report_destination)
                        ):
                            self._remove_existing_report()

                            if staged_output is not None:
                                try:
                                    staged_output.commit(destination_lock_held=True)
                                except BoundFileDestinationError as exc:
                                    raise GenerationDocumentWriteError(
                                        self.output_path,
                                        exc,
                                    ) from exc

                            try:
                                self._verify_report_still_distinct()
                            except BoundFileDestinationError as exc:
                                raise GenerationReportWriteError(
                                    self.report_destination.requested_path,
                                    exc,
                                ) from exc

                            try:
                                report_rollback = staged_report._prepare_rollback()
                                self._report_rollback = report_rollback
                                object.__setattr__(self, "_discard_report_on_close", True)
                                staged_report.commit(destination_lock_held=True)
                                object.__setattr__(self, "_discard_report_on_close", False)
                            except BoundFileDestinationError as exc:
                                raise GenerationReportWriteError(
                                    self.report_destination.requested_path,
                                    exc,
                                ) from exc
                except DestinationLockError as exc:
                    if exc.destination is self.output_destination:
                        raise GenerationDocumentWriteError(self.output_path, exc) from exc
                    raise GenerationReportWriteError(
                        self.report_destination.requested_path,
                        exc,
                    ) from exc
        except BaseException as failure:
            cleanup_failure: BaseException | None = None
            retained_rollback = self._report_rollback
            if retained_rollback is not None:
                object.__setattr__(self, "_discard_report_on_close", True)
                try:
                    self._discard_published_report()
                except BaseException as exc:
                    cleanup_failure = exc
            elif report_rollback is not None:
                try:
                    report_rollback.close()
                except BaseException as exc:
                    cleanup_failure = exc

            primary_failure = _generation_primary_failure(failure)
            if primary_failure is not None:
                secondary_failures = _generation_cleanup_failures(
                    failure,
                    primary=primary_failure,
                    final_cleanup_failure=cleanup_failure,
                )
                if secondary_failures:
                    primary_failure.__dict__["vexcalibur_cleanup_failures"] = secondary_failures
                pending_failure = primary_failure
                pending_traceback = primary_failure.__traceback__
            elif isinstance(failure, Exception):
                pending_failure = GenerationOutputCleanupError(str(failure))
                pending_cause = cleanup_failure if cleanup_failure is not None else failure
            else:  # pragma: no cover - every non-Exception is a primary failure
                pending_failure = failure
                pending_traceback = failure.__traceback__

        if pending_failure is None:
            return
        if pending_cause is not None:
            raise pending_failure.with_traceback(pending_traceback) from pending_cause
        raise pending_failure.with_traceback(pending_traceback)

    def _remove_existing_report(self) -> None:
        try:
            self.report_destination.remove_existing(
                destination_lock_held=True,
            )
        except BoundFileDestinationError as exc:
            raise GenerationReportWriteError(
                self.report_destination.requested_path,
                exc,
            ) from exc

    def close(self) -> None:
        """Close every retained destination descriptor."""
        if self.closed:
            return
        failure: BaseException | None = None
        for destination in (self.output_destination, self.report_destination):
            if destination is None:
                continue
            try:
                destination.close()
            except BaseException as exc:
                if failure is None:
                    failure = exc
                object.__setattr__(self, "_discard_report_on_close", True)
        if not self._discard_report_on_close and failure is None:
            try:
                self._release_report_rollback()
            except BaseException as exc:
                failure = exc
                object.__setattr__(self, "_discard_report_on_close", True)
        if self._discard_report_on_close:
            try:
                self._discard_published_report()
            except BaseException as exc:
                if failure is None:
                    failure = exc
        if failure is not None:
            if isinstance(failure, GenerationOutputError):
                raise failure
            if isinstance(failure, Exception):
                raise GenerationOutputCleanupError(str(failure)) from failure
            raise failure
        object.__setattr__(self, "_closed", True)

    def abort(self) -> None:
        """Remove a published report, then close every retained descriptor."""
        if self.closed:
            return
        object.__setattr__(self, "_discard_report_on_close", True)
        self.close()

    def __copy__(self) -> GenerationOutputTransaction:
        raise TypeError("generation output transactions cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> GenerationOutputTransaction:
        del memo
        raise TypeError("generation output transactions cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("generation output transactions cannot be serialized")

    def __enter__(self) -> GenerationOutputTransaction:
        if self.closed:
            raise GenerationOutputError("generation output transaction is already closed")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if exc_type is None:
            self.close()
        else:
            with suppress(BaseException):
                self.abort()

    def __del__(self) -> None:
        with suppress(Exception):
            self.close()

    def _verify_report_still_distinct(self) -> None:
        if self.output_destination is not None and self.report_destination.aliases(
            self.output_destination
        ):
            self.report_destination.remove_existing(destination_lock_held=True)
            raise BoundFileDestinationError(
                "--execution-report became an alias of the VEX output file"
            )
        for descriptor, description in self.protected_descriptors:
            if self.report_destination.aliases_descriptor(descriptor):
                self.report_destination.remove_existing(destination_lock_held=True)
                raise BoundFileDestinationError(
                    f"--execution-report became an alias of redirected {description}"
                )

    def _discard_published_report(self) -> None:
        rollback = self._report_rollback
        if rollback is None:
            object.__setattr__(self, "_discard_report_on_close", False)
            return
        if not rollback.can_discard:
            rollback.close()
            object.__setattr__(self, "_report_rollback", None)
            object.__setattr__(self, "_discard_report_on_close", False)
            return
        failure: BaseException | None = None
        for _ in range(2):
            try:
                if rollback.discard():
                    break
            except BaseException as exc:
                failure = exc
        else:
            error = GenerationOutputError("could not remove the published execution report")
            if failure is not None:
                raise error from failure
            raise error
        try:
            rollback.close()
            object.__setattr__(self, "_report_rollback", None)
            object.__setattr__(self, "_discard_report_on_close", False)
        except BaseException:
            if rollback.closed:
                object.__setattr__(self, "_report_rollback", None)
                object.__setattr__(self, "_discard_report_on_close", False)
                return
            raise

    def _release_report_rollback(self) -> None:
        rollback = self._report_rollback
        if rollback is None:
            return
        try:
            rollback.close()
            object.__setattr__(self, "_report_rollback", None)
        except BaseException:
            if rollback.closed:
                object.__setattr__(self, "_report_rollback", None)
                return
            raise


def _label_destination_error(
    error: BoundFileDestinationError,
    *,
    role: str,
) -> str:
    message = str(error)
    if message.startswith("destination "):
        return f"{role} {message.removeprefix('destination ')}"
    return message


def _generation_primary_failure(error: BaseException) -> BaseException | None:
    """Return a typed or interrupting primary hidden by cleanup."""
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, GenerationOutputError) or not isinstance(current, Exception):
            return current
        current = current.__context__
    return None


def _generation_cleanup_failures(
    error: BaseException,
    *,
    primary: BaseException,
    final_cleanup_failure: BaseException | None,
) -> tuple[BaseException, ...]:
    """Return cleanup failures without changing either exception chain."""
    failures: list[BaseException] = []
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and current is not primary and id(current) not in seen:
        seen.add(id(current))
        failures.append(current)
        current = current.__context__
    if final_cleanup_failure is not None and all(
        final_cleanup_failure is not failure for failure in failures
    ):
        failures.append(final_cleanup_failure)
    return tuple(failures)


def _register_destination_close(
    stack: ExitStack,
    destination: BoundFileDestination,
) -> None:
    try:
        stack.callback(destination.close)
    except BaseException:
        destination.close()
        raise


def _write_all(stream: BinaryIO, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = stream.write(view)
        if type(written) is not int or written <= 0 or written > len(view):
            raise OSError("standard output returned an invalid write count")
        view = view[written:]
