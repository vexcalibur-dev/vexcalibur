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
from vexcalibur.execution_report_errors import _retain_cleanup_failures
from vexcalibur.execution_report_filesystem import _defer_keyboard_interrupt
from vexcalibur.execution_report_lifecycle import (
    GenerationOutputState,
    PublishedRollbackState,
    require_generation_output_transition,
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
        "_report_rollback",
        "_state",
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
        self._report_rollback = PublishedFileRollback._create()
        self._state = GenerationOutputState.PREPARED

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
        return self._state is GenerationOutputState.CLOSED

    @property
    def state(self) -> GenerationOutputState:
        """Return the transaction's current lifecycle state."""
        return self._state

    def _transition(self, target: GenerationOutputState) -> None:
        object.__setattr__(
            self,
            "_state",
            require_generation_output_transition(self._state, target),
        )

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
        cleanup_failures: list[BaseException] = []
        try:
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
                _register_destination_close(
                    destinations,
                    report_destination,
                    cleanup_failures,
                )

                try:
                    output_destination = (
                        BoundFileDestination.prepare(output_path)
                        if output_path is not None
                        else None
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
                    _register_destination_close(
                        destinations,
                        output_destination,
                        cleanup_failures,
                    )

                if output_destination is not None and report_destination.aliases(
                    output_destination
                ):
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
        except BaseException as primary:
            _retain_cleanup_failures(primary, tuple(cleanup_failures))
            raise

    def commit(
        self,
        result: GenerationResult,
        *,
        binary_stdout: BinaryIO | None = None,
    ) -> None:
        """Publish VEX, then publish its staged report as the success marker."""
        if self.closed:
            raise GenerationOutputError("generation output transaction is already closed")
        if self._state is not GenerationOutputState.PREPARED:
            raise GenerationOutputError("generation output transaction is already consumed")
        self._transition(GenerationOutputState.COMMITTING)
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
        report_bytes = self._serialize_report(result)
        pending_failure: (
            tuple[
                BaseException,
                TracebackType | None,
                BaseException | None,
            ]
            | None
        ) = None
        try:
            with ExitStack() as stack:
                staged_report = self._stage_report(stack, report_bytes)
                staged_output = self._stage_document(stack, result.rendered_bytes)
                self._publish_staged_outputs(
                    staged_report,
                    staged_output,
                    rendered_bytes=result.rendered_bytes,
                    binary_stdout=binary_stdout,
                )
        except BaseException as failure:
            pending_failure = self._finalize_failed_commit(failure)

        if pending_failure is None:
            return
        pending_exception, traceback, cause = pending_failure
        if cause is not None:
            raise pending_exception.with_traceback(traceback) from cause
        raise pending_exception.with_traceback(traceback)

    @staticmethod
    def _serialize_report(result: GenerationResult) -> bytes:
        try:
            return result.execution_report().to_json().encode("utf-8")
        except (UnicodeError, ValueError) as exc:
            raise GenerationReportConstructionError(str(exc)) from exc

    def _stage_report(self, stack: ExitStack, report_bytes: bytes) -> StagedFileWrite:
        try:
            staged_report = stack.enter_context(self.report_destination.stage_bytes(report_bytes))
            self.report_destination.verify_parent_path()
            return staged_report
        except BoundFileDestinationError as exc:
            raise GenerationReportWriteError(
                self.report_destination.requested_path,
                exc,
            ) from exc

    def _stage_document(
        self,
        stack: ExitStack,
        rendered_bytes: bytes,
    ) -> StagedFileWrite | None:
        if self.output_destination is None:
            return None
        try:
            staged_output = stack.enter_context(self.output_destination.stage_bytes(rendered_bytes))
            self.output_destination.verify_parent_path()
            return staged_output
        except BoundFileDestinationError as exc:
            raise GenerationDocumentWriteError(self.output_path, exc) from exc

    def _publish_staged_outputs(
        self,
        staged_report: StagedFileWrite,
        staged_output: StagedFileWrite | None,
        *,
        rendered_bytes: bytes,
        binary_stdout: BinaryIO | None,
    ) -> None:
        try:
            stdout_sequence = (
                acquire_stdout_sequence_lock(self.report_destination)
                if staged_output is None
                else nullcontext()
            )
            with stdout_sequence:
                if staged_output is None:
                    self._publish_standard_output(rendered_bytes, binary_stdout)
                with acquire_destination_locks((self.output_destination, self.report_destination)):
                    self._publish_under_destination_locks(staged_report, staged_output)
        except DestinationLockError as exc:
            if exc.destination is self.output_destination:
                raise GenerationDocumentWriteError(self.output_path, exc) from exc
            raise GenerationReportWriteError(
                self.report_destination.requested_path,
                exc,
            ) from exc

    def _publish_standard_output(
        self,
        rendered_bytes: bytes,
        binary_stdout: BinaryIO | None,
    ) -> None:
        with acquire_destination_locks((self.report_destination,)):
            self._remove_existing_report()
        try:
            if binary_stdout is None:
                raise OSError("binary standard output is unavailable")
            _write_all(binary_stdout, rendered_bytes)
            binary_stdout.flush()
        except (OSError, TypeError, ValueError) as exc:
            failure = GenerationDocumentWriteError(None, exc)
            try:
                with acquire_destination_locks((self.report_destination,)):
                    self._remove_existing_report()
            except BaseException as cleanup_failure:
                _retain_cleanup_failures(failure, (cleanup_failure,))
            raise failure from exc

    def _publish_under_destination_locks(
        self,
        staged_report: StagedFileWrite,
        staged_output: StagedFileWrite | None,
    ) -> None:
        self._remove_existing_report()
        if staged_output is not None:
            try:
                staged_output.commit(destination_lock_held=True)
            except BoundFileDestinationError as exc:
                raise GenerationDocumentWriteError(self.output_path, exc) from exc

        try:
            self._verify_report_still_distinct()
            self._verify_published_output(staged_output)
            self._transition(GenerationOutputState.REPORT_GUARD_ARMING)
            staged_report._prepare_rollback(self._report_rollback)
            self._transition(GenerationOutputState.REPORT_GUARDED)
            self._report_rollback.begin_publication()
            staged_report.commit(destination_lock_held=True)
            self._verify_published_output(staged_output)
            self._report_rollback.publication_succeeded()
            self._transition(GenerationOutputState.COMMITTED)
        except BoundFileDestinationError as exc:
            raise GenerationReportWriteError(
                self.report_destination.requested_path,
                exc,
            ) from exc

    def _verify_published_output(self, staged_output: StagedFileWrite | None) -> None:
        if staged_output is None:
            return
        try:
            staged_output.verify_publication()
        except BoundFileDestinationError as exc:
            raise GenerationDocumentWriteError(self.output_path, exc) from exc

    def _finalize_failed_commit(
        self,
        failure: BaseException,
    ) -> tuple[BaseException, TracebackType | None, BaseException | None]:
        cleanup_failure: BaseException | None = None
        try:
            self.abort()
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
                _retain_cleanup_failures(primary_failure, secondary_failures)
            return primary_failure, primary_failure.__traceback__, None
        if isinstance(failure, Exception):
            cause = cleanup_failure if cleanup_failure is not None else failure
            return GenerationOutputCleanupError(str(failure)), None, cause
        return failure, failure.__traceback__, None

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
        self._cleanup(abort=False)

    def abort(self) -> None:
        """Remove a published report, then close every retained descriptor."""
        self._cleanup(abort=True)

    def abort_after(self, failure: BaseException) -> BaseException | None:
        """Abort while retaining any cleanup failure on an active exception."""
        try:
            self.abort()
        except BaseException as cleanup_failure:
            _retain_cleanup_failures(failure, (cleanup_failure,))
            return cleanup_failure
        return None

    def _cleanup(self, *, abort: bool) -> None:
        if self.closed:
            return
        finalizing_publication = self._state in {
            GenerationOutputState.COMMITTED,
            GenerationOutputState.FINALIZING,
        }
        try:
            with _defer_keyboard_interrupt() if finalizing_publication else nullcontext():
                self._cleanup_guarded(abort=abort)
        except BaseException:
            if self._finish_irreversible_publication():
                return
            raise

    def _cleanup_guarded(self, *, abort: bool) -> None:
        if (abort and self._state is not GenerationOutputState.FINALIZING) or self._state in {
            GenerationOutputState.COMMITTING,
            GenerationOutputState.REPORT_GUARD_ARMING,
            GenerationOutputState.REPORT_GUARDED,
        }:
            self._require_abort()

        failures: list[BaseException] = []
        for destination in (self.output_destination, self.report_destination):
            if destination is None:
                continue
            try:
                destination.close()
            except BaseException as exc:
                failures.append(exc)

        if failures and self._state is not GenerationOutputState.FINALIZING:
            self._require_abort()

        if self._state is GenerationOutputState.ABORT_REQUIRED:
            try:
                self._discard_published_report()
            except BaseException as exc:
                failures.append(exc)
        else:
            if self._state is GenerationOutputState.COMMITTED:
                self._transition(GenerationOutputState.FINALIZING)
            try:
                rollback_released = self._release_report_rollback()
            except BaseException as exc:
                if self._finish_irreversible_publication():
                    return
                failures.append(exc)
                self._require_abort()
                try:
                    self._discard_published_report()
                except BaseException as discard_exc:
                    failures.append(discard_exc)
            else:
                if not rollback_released:
                    return

        destinations_closed = all(
            destination is None or destination.closed
            for destination in (self.output_destination, self.report_destination)
        )
        if not failures and destinations_closed and self._report_rollback.closed:
            self._transition(GenerationOutputState.CLOSED)

        if failures:
            self._raise_cleanup_failures(failures)
        if self._state is GenerationOutputState.FINALIZING:
            return
        if not self.closed:
            raise GenerationOutputCleanupError(
                "generate output cleanup did not reach a final state"
            )

    def _finish_irreversible_publication(self) -> bool:
        """Finish success after an interruption beyond rollback authority."""
        if self._report_rollback.state is not PublishedRollbackState.PUBLICATION_RELEASED:
            return False
        destinations_closed = all(
            destination is None or destination.closed
            for destination in (self.output_destination, self.report_destination)
        )
        if not destinations_closed:
            return False
        if self._state is GenerationOutputState.FINALIZING:
            self._transition(GenerationOutputState.CLOSED)
        return self.closed

    def _require_abort(self) -> None:
        if self._state in {
            GenerationOutputState.ABORT_REQUIRED,
            GenerationOutputState.CLOSED,
        }:
            return
        self._transition(GenerationOutputState.ABORT_REQUIRED)

    @staticmethod
    def _raise_cleanup_failures(failures: list[BaseException]) -> NoReturn:
        primary = failures[0]
        secondary = tuple(failures[1:])
        if isinstance(primary, GenerationOutputError) or not isinstance(primary, Exception):
            error: BaseException = primary
        else:
            error = GenerationOutputCleanupError(str(primary))
        if secondary:
            _retain_cleanup_failures(error, secondary)
        if error is primary:
            raise error
        raise error from primary

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
            if exc_value is None:
                raise RuntimeError("context manager received an exception type without a value")
            self.abort_after(exc_value)

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
        if rollback.state in {
            PublishedRollbackState.UNARMED,
            PublishedRollbackState.ARMING,
            PublishedRollbackState.ARMED,
            PublishedRollbackState.DISCARDED,
            PublishedRollbackState.DISCARDED_RELEASED,
            PublishedRollbackState.RELEASED,
        }:
            rollback.close()
            return
        if rollback.state is PublishedRollbackState.PUBLICATION_RELEASED:
            raise GenerationOutputCleanupError(
                "published execution report can no longer be removed safely"
            )
        if not rollback.can_discard:
            raise GenerationOutputCleanupError(
                "published execution report can no longer be removed safely"
            )
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
        rollback.close()

    def _release_report_rollback(self) -> bool:
        first_failure: BaseException | None = None
        for _ in range(2):
            try:
                self._report_rollback.close()
                return True
            except BaseException as exc:
                if self._report_rollback.closed:
                    return True
                if not isinstance(exc, Exception):
                    if self._can_discard_retaining_release_failure(exc):
                        raise
                    return False
                if first_failure is None:
                    first_failure = exc
        if first_failure is None:
            raise RuntimeError("rollback release failed without an exception")
        if not self._can_discard_retaining_release_failure(first_failure):
            return False
        raise first_failure

    def _can_discard_retaining_release_failure(self, failure: BaseException) -> bool:
        """Probe rollback authority without replacing the release failure."""
        try:
            return self._report_rollback.can_discard
        except BaseException as probe_failure:
            _retain_cleanup_failures(failure, (probe_failure,))
            raise failure.with_traceback(failure.__traceback__) from None


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
    cleanup_failures: list[BaseException],
) -> None:
    try:
        stack.callback(
            _close_destination_retaining_failure,
            destination,
            cleanup_failures,
        )
    except BaseException:
        _close_destination_retaining_failure(destination, cleanup_failures)
        raise


def _close_destination_retaining_failure(
    destination: BoundFileDestination,
    cleanup_failures: list[BaseException],
) -> None:
    try:
        destination.close()
    except BaseException as cleanup_failure:
        cleanup_failures.append(cleanup_failure)


def _write_all(stream: BinaryIO, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = stream.write(view)
        if type(written) is not int or written <= 0 or written > len(view):
            raise OSError("standard output returned an invalid write count")
        view = view[written:]
