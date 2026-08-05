"""Private staging and atomic publication for bound destinations."""

from __future__ import annotations

import errno
import os
import secrets
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext, suppress
from types import TracebackType
from typing import NoReturn, Protocol

import vexcalibur.execution_report_locks as lock_module
from vexcalibur.execution_report_errors import (
    BoundFileDestinationError,
    _retain_cleanup_failures,
)
from vexcalibur.execution_report_filesystem import (
    _close_descriptor,
    _close_descriptor_retryable,
    _remove_matching_destination,
    _require_path_identity,
    _require_private_regular_file,
    _same_identity,
)
from vexcalibur.execution_report_lifecycle import (
    DescriptorOwnership,
    PublishedRollbackState,
    require_published_rollback_transition,
)


class _StagingDestination(Protocol):
    """The bound-destination operations needed to stage and publish bytes."""

    _name_bytes: bytes

    def _open_parent(self) -> int: ...

    def _create_temporary_file(self, parent_fd: int) -> tuple[int, str]: ...

    def _require_parent_descriptor(self) -> int: ...

    def _verify_replaceable_leaf(self, parent_fd: int) -> None: ...

    def verify_parent_path(self) -> None: ...


_STAGED_FILE_WRITE_TOKEN = object()


def _close_owned_descriptor(owner: object, attribute: str) -> None:
    ownership_attribute = f"_{attribute}_ownership"
    ownership = getattr(owner, ownership_attribute)
    if ownership is DescriptorOwnership.RELEASED:
        return
    if ownership is DescriptorOwnership.AMBIGUOUS:
        raise BoundFileDestinationError(
            f"{attribute.removesuffix('_fd').replace('_', ' ')} descriptor release is ambiguous"
        )
    descriptor = getattr(owner, attribute)
    if descriptor < 0:
        raise RuntimeError(f"owned {attribute} has no descriptor")
    try:
        outcome = _close_descriptor_retryable(descriptor)
    except BaseException:
        object.__setattr__(owner, attribute, -1)
        object.__setattr__(owner, ownership_attribute, DescriptorOwnership.AMBIGUOUS)
        raise
    if outcome.released:
        object.__setattr__(owner, attribute, -1)
        object.__setattr__(owner, ownership_attribute, DescriptorOwnership.RELEASED)
        return
    if outcome.unchanged:
        if outcome.failure is not None:
            raise outcome.failure
        raise RuntimeError("descriptor release returned unchanged without a failure")
    object.__setattr__(owner, attribute, -1)
    object.__setattr__(owner, ownership_attribute, DescriptorOwnership.AMBIGUOUS)
    if outcome.failure is not None:
        raise outcome.failure
    raise RuntimeError("descriptor release returned an ambiguous final state")


class StagedFileWrite:
    """Flushed bytes with one-shot publication state."""

    __slots__ = (
        "_closed",
        "_committed",
        "_parent_fd_ownership",
        "_retain_publication",
        "_temporary_fd_ownership",
        "destination",
        "parent_fd",
        "temporary_fd",
        "temporary_name",
        "temporary_stat",
    )

    def __init__(
        self,
        construction_token: object,
        *,
        destination: _StagingDestination,
        parent_fd: int,
        temporary_name: str,
        temporary_fd: int,
        temporary_stat: os.stat_result,
    ) -> None:
        if construction_token is not _STAGED_FILE_WRITE_TOKEN:
            raise TypeError("staged file writes require a bound destination")
        self.destination = destination
        self.parent_fd = parent_fd
        self.temporary_name = temporary_name
        self.temporary_fd = temporary_fd
        self.temporary_stat = temporary_stat
        self._committed = False
        self._closed = False
        self._retain_publication = False
        self._parent_fd_ownership = DescriptorOwnership.OWNED
        self._temporary_fd_ownership = DescriptorOwnership.OWNED

    @classmethod
    def _create(
        cls,
        *,
        destination: _StagingDestination,
        parent_fd: int,
        temporary_name: str,
        temporary_fd: int,
        temporary_stat: os.stat_result,
    ) -> StagedFileWrite:
        return cls(
            _STAGED_FILE_WRITE_TOKEN,
            destination=destination,
            parent_fd=parent_fd,
            temporary_name=temporary_name,
            temporary_fd=temporary_fd,
            temporary_stat=temporary_stat,
        )

    @property
    def committed(self) -> bool:
        return self._committed

    @property
    def closed(self) -> bool:
        return self._closed

    def commit(self, *, destination_lock_held: bool = False) -> None:
        """Publish the staged bytes and durably flush the directory entry."""
        if self.closed:
            raise BoundFileDestinationError("staged file is already closed")
        if self.committed:
            raise BoundFileDestinationError("staged file is already committed")

        try:
            lock = (
                nullcontext()
                if destination_lock_held
                else lock_module._exclusive_destination_lock(self.parent_fd)
            )
            with lock:
                self.destination.verify_parent_path()
                self.destination._verify_replaceable_leaf(self.parent_fd)
                staged_stat = os.fstat(self.temporary_fd)
                _require_private_regular_file(staged_stat)
                _require_path_identity(
                    parent_fd=self.parent_fd,
                    name=self.temporary_name,
                    expected=staged_stat,
                    role="staged file",
                )
                try:
                    self._committed = True
                    os.replace(
                        self.temporary_name,
                        self.destination._name_bytes,
                        src_dir_fd=self.parent_fd,
                        dst_dir_fd=self.parent_fd,
                    )
                    _require_path_identity(
                        parent_fd=self.parent_fd,
                        name=self.destination._name_bytes,
                        expected=staged_stat,
                        role="published file",
                    )
                    os.fsync(self.parent_fd)
                    self.destination.verify_parent_path()
                    _require_path_identity(
                        parent_fd=self.parent_fd,
                        name=self.destination._name_bytes,
                        expected=staged_stat,
                        role="published file",
                    )
                    self._retain_publication = True
                except BaseException:
                    self._rollback_publication()
                    raise
        except BaseException as exc:
            self._rollback_publication()
            if isinstance(exc, (BoundFileDestinationError, OSError)):
                raise BoundFileDestinationError(str(exc)) from exc
            raise

    def discard_committed(self) -> bool:
        """Remove this staged file only when it is still the published destination."""
        if not self.committed:
            return True
        self._retain_publication = False
        parent_fd = -1
        try:
            parent_fd = os.dup(self.destination._require_parent_descriptor())
            removed = _remove_matching_destination(
                parent_fd=parent_fd,
                name=self.destination._name_bytes,
                expected=self.temporary_stat,
            )
        except (BoundFileDestinationError, OSError):
            return False
        finally:
            _close_descriptor(parent_fd)
        if removed:
            self._committed = False
        return removed

    def retain_rollback(self) -> PublishedFileRollback:
        """Retain an independent handle that can remove this publication."""
        if not self.committed or not self._retain_publication:
            raise BoundFileDestinationError("staged file is not published")
        rollback = PublishedFileRollback._create()
        retained = self._prepare_rollback(rollback)
        retained.begin_publication()
        retained.publication_succeeded()
        return retained

    def _prepare_rollback(
        self,
        rollback: PublishedFileRollback | None = None,
    ) -> PublishedFileRollback:
        """Retain rollback ownership before the staged file is published."""
        retained = PublishedFileRollback._create() if rollback is None else rollback
        retained._arm(
            expected=self.temporary_stat,
            parent_fd=self.parent_fd,
            published_fd=self.temporary_fd,
            name=self.destination._name_bytes,
        )
        return retained

    def _rollback_publication(self) -> bool:
        if not self.committed:
            return True
        self._retain_publication = False
        return self.discard_committed()

    def close(self) -> None:
        """Remove unpublished temporary bytes and close the parent handle."""
        if self.closed:
            return
        if self.committed and not self._retain_publication:
            if not self.discard_committed():
                raise BoundFileDestinationError("could not remove the published staged file")
        elif not self.committed:
            try:
                expected = os.fstat(self.temporary_fd)
            except OSError:
                pass
            else:
                if not _remove_matching_destination(
                    parent_fd=self.parent_fd,
                    name=self.temporary_name,
                    expected=expected,
                ):
                    raise BoundFileDestinationError("could not remove the unpublished staged file")
        failures: list[BaseException] = []
        try:
            _close_owned_descriptor(self, "temporary_fd")
        except BaseException as exc:
            failures.append(exc)
        if self._temporary_fd_ownership is not DescriptorOwnership.OWNED:
            try:
                _close_owned_descriptor(self, "parent_fd")
            except BaseException as exc:
                failures.append(exc)
        if (
            self._temporary_fd_ownership is DescriptorOwnership.RELEASED
            and self._parent_fd_ownership is DescriptorOwnership.RELEASED
        ):
            object.__setattr__(self, "_closed", True)
        if failures:
            primary = failures[0]
            if len(failures) > 1:
                _retain_cleanup_failures(primary, tuple(failures[1:]))
            raise primary

    def __copy__(self) -> StagedFileWrite:
        raise TypeError("staged file writes cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> StagedFileWrite:
        del memo
        raise TypeError("staged file writes cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("staged file writes cannot be serialized")

    def __enter__(self) -> StagedFileWrite:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        with suppress(Exception):
            self.close()


_PUBLISHED_FILE_ROLLBACK_TOKEN = object()


class PublishedFileRollback:
    """Independent identity-bound handle for removing one published file."""

    __slots__ = (
        "_lock_fd_ownership",
        "_parent_fd_ownership",
        "_published_fd_ownership",
        "_state",
        "expected",
        "lock_fd",
        "name",
        "parent_fd",
        "published_fd",
    )

    def __init__(
        self,
        construction_token: object,
    ) -> None:
        if construction_token is not _PUBLISHED_FILE_ROLLBACK_TOKEN:
            raise TypeError("published rollback handles require a staged file")
        self.expected: os.stat_result | None = None
        self.lock_fd = -1
        self.parent_fd = -1
        self.published_fd = -1
        self.name: str | bytes = b""
        self._lock_fd_ownership = DescriptorOwnership.RELEASED
        self._parent_fd_ownership = DescriptorOwnership.RELEASED
        self._published_fd_ownership = DescriptorOwnership.RELEASED
        self._state = PublishedRollbackState.UNARMED

    @classmethod
    def _create(cls) -> PublishedFileRollback:
        return cls(_PUBLISHED_FILE_ROLLBACK_TOKEN)

    @property
    def state(self) -> PublishedRollbackState:
        """Return the rollback guard's current lifecycle state."""
        return self._state

    def _transition(self, target: PublishedRollbackState) -> None:
        object.__setattr__(
            self,
            "_state",
            require_published_rollback_transition(self._state, target),
        )

    def _arm(
        self,
        *,
        expected: os.stat_result,
        parent_fd: int,
        published_fd: int,
        name: str | bytes,
    ) -> None:
        """Acquire rollback descriptors after a transaction owns this guard."""
        self._transition(PublishedRollbackState.ARMING)
        object.__setattr__(self, "expected", expected)
        object.__setattr__(self, "name", name)
        try:
            lock_fd = lock_module._open_private_destination_lock(parent_fd)
            object.__setattr__(self, "lock_fd", lock_fd)
            object.__setattr__(self, "_lock_fd_ownership", DescriptorOwnership.OWNED)
            retained_parent_fd = os.dup(parent_fd)
            object.__setattr__(self, "parent_fd", retained_parent_fd)
            object.__setattr__(self, "_parent_fd_ownership", DescriptorOwnership.OWNED)
            retained_published_fd = os.dup(published_fd)
            object.__setattr__(self, "published_fd", retained_published_fd)
            object.__setattr__(
                self,
                "_published_fd_ownership",
                DescriptorOwnership.OWNED,
            )
        except BaseException as exc:
            cleanup_failure: BaseException | None = None
            try:
                self.close()
            except BaseException as cleanup_exc:
                cleanup_failure = cleanup_exc
            if cleanup_failure is not None:
                _retain_cleanup_failures(exc, (cleanup_failure,))
            if isinstance(exc, OSError):
                raise BoundFileDestinationError(
                    "could not retain the published file rollback handle"
                ) from exc
            raise
        self._transition(PublishedRollbackState.ARMED)

    def discard(self) -> bool:
        """Remove the publication only if it still has the retained identity."""
        if self._state is PublishedRollbackState.DISCARDED:
            return True
        if not self.can_discard:
            return False
        expected = self.expected
        if expected is None:
            raise RuntimeError("armed rollback guard has no expected identity")
        with lock_module._exclusive_open_lock(self.lock_fd):
            if self._state in {
                PublishedRollbackState.ARMED,
                PublishedRollbackState.PUBLISHED,
            }:
                try:
                    actual = os.stat(
                        self.name,
                        dir_fd=self.parent_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    self._transition(PublishedRollbackState.DISCARDED)
                    return True
                except OSError:
                    return False
                if not _same_identity(actual, expected):
                    self._transition(PublishedRollbackState.DISCARDED)
                    return True
                self._transition(PublishedRollbackState.REMOVAL_PENDING)
            elif self._state is PublishedRollbackState.PUBLICATION_PENDING:
                self._transition(PublishedRollbackState.REMOVAL_PENDING)

            try:
                actual = os.stat(
                    self.name,
                    dir_fd=self.parent_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            except OSError:
                return False
            else:
                if _same_identity(actual, expected):
                    try:
                        os.unlink(self.name, dir_fd=self.parent_fd)
                    except FileNotFoundError:
                        pass
                    except OSError:
                        return False
            try:
                os.fsync(self.parent_fd)
            except OSError:
                return False
            self._transition(PublishedRollbackState.DISCARDED)
            return True

    @property
    def can_discard(self) -> bool:
        """Return whether the retained descriptor still pins the publication."""
        if self._state not in {
            PublishedRollbackState.ARMED,
            PublishedRollbackState.PUBLICATION_PENDING,
            PublishedRollbackState.PUBLISHED,
            PublishedRollbackState.REMOVAL_PENDING,
        }:
            return False
        if self._published_fd_ownership is not DescriptorOwnership.OWNED:
            return False
        try:
            retained = os.fstat(self.published_fd)
        except OSError as exc:
            if exc.errno == errno.EBADF:
                return False
            raise BoundFileDestinationError(
                "could not inspect the published execution report"
            ) from exc
        expected = self.expected
        return expected is not None and _same_identity(retained, expected)

    def begin_publication(self) -> None:
        """Record a publication attempt before the replace operation starts."""
        self._transition(PublishedRollbackState.PUBLICATION_PENDING)

    def publication_succeeded(self) -> None:
        """Record that the guarded file was published and flushed."""
        self._transition(PublishedRollbackState.PUBLISHED)

    def close(self) -> None:
        """Release the retained file and directory descriptors."""
        if self._state is PublishedRollbackState.RELEASED:
            return
        failures: list[BaseException] = []
        for attribute in ("published_fd", "parent_fd", "lock_fd"):
            try:
                _close_owned_descriptor(self, attribute)
            except BaseException as exc:
                failures.append(exc)

        ownerships = (
            self._published_fd_ownership,
            self._parent_fd_ownership,
            self._lock_fd_ownership,
        )
        if all(ownership is DescriptorOwnership.RELEASED for ownership in ownerships):
            self._transition(PublishedRollbackState.RELEASED)

        if failures:
            primary = failures[0]
            if len(failures) > 1:
                _retain_cleanup_failures(primary, tuple(failures[1:]))
            raise primary

    @property
    def closed(self) -> bool:
        """Return whether every retained descriptor was released."""
        return self._state is PublishedRollbackState.RELEASED

    def __copy__(self) -> PublishedFileRollback:
        raise TypeError("published rollback handles cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> PublishedFileRollback:
        del memo
        raise TypeError("published rollback handles cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("published rollback handles cannot be serialized")

    def __del__(self) -> None:
        with suppress(Exception):
            self.close()


@contextmanager
def stage_destination_bytes(
    destination: _StagingDestination,
    serialized: bytes,
) -> Iterator[StagedFileWrite]:
    """Yield flushed private temporary bytes and reclaim their handles."""
    try:
        parent_fd = destination._open_parent()
    except OSError as exc:
        msg = "destination parent directory changed before write"
        raise BoundFileDestinationError(msg) from exc

    temporary_name = ""
    file_descriptor = -1
    try:
        file_descriptor, temporary_name = destination._create_temporary_file(parent_fd)
        with os.fdopen(file_descriptor, "wb", closefd=False) as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        temporary_stat = os.fstat(file_descriptor)
        _require_private_regular_file(temporary_stat)
        staged = StagedFileWrite._create(
            destination=destination,
            parent_fd=parent_fd,
            temporary_name=temporary_name,
            temporary_fd=file_descriptor,
            temporary_stat=temporary_stat,
        )
    except BaseException as exc:
        cleanup_failures: list[BaseException] = []
        try:
            _cleanup_staged_file(parent_fd, temporary_name, file_descriptor)
        except BaseException as cleanup_failure:
            cleanup_failures.append(cleanup_failure)
        try:
            _close_descriptor(file_descriptor)
        except BaseException as cleanup_failure:
            if all(cleanup_failure is not failure for failure in cleanup_failures):
                cleanup_failures.append(cleanup_failure)
        if isinstance(exc, BoundFileDestinationError):
            primary_failure: BaseException = exc
        elif isinstance(exc, OSError):
            primary_failure = BoundFileDestinationError(str(exc))
        else:
            primary_failure = exc
        if cleanup_failures:
            _retain_cleanup_failures(primary_failure, tuple(cleanup_failures))
        if primary_failure is exc:
            raise
        raise primary_failure from exc
    try:
        yield staged
    except BaseException as primary_failure:
        try:
            staged.close()
        except BaseException as cleanup_failure:
            _retain_cleanup_failures(primary_failure, (cleanup_failure,))
        raise
    else:
        staged.close()


def _create_temporary_file(parent_fd: int) -> tuple[int, str]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    for _ in range(128):
        name = f".vexcalibur-{secrets.token_hex(16)}.tmp"
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=parent_fd)
        except FileExistsError:
            continue
        try:
            os.fchmod(descriptor, 0o600)
            return _temporary_file_result(descriptor, name)
        except BaseException as exc:
            cleanup_failures: list[BaseException] = []
            try:
                _remove_temporary_file(parent_fd, name, descriptor)
            except BaseException as cleanup_failure:
                cleanup_failures.append(cleanup_failure)
            try:
                _close_descriptor(descriptor)
            except BaseException as cleanup_failure:
                if all(cleanup_failure is not failure for failure in cleanup_failures):
                    cleanup_failures.append(cleanup_failure)
            if isinstance(exc, BoundFileDestinationError):
                primary_failure: BaseException = exc
            elif isinstance(exc, OSError):
                primary_failure = BoundFileDestinationError(str(exc))
            else:
                primary_failure = exc
            _retain_cleanup_failures(primary_failure, tuple(cleanup_failures))
            if primary_failure is exc:
                raise
            raise primary_failure from exc
    raise BoundFileDestinationError("could not allocate a unique temporary file")


def _temporary_file_result(descriptor: int, name: str) -> tuple[int, str]:
    return descriptor, name


def _cleanup_staged_file(
    parent_fd: int,
    temporary_name: str,
    temporary_fd: int,
) -> None:
    try:
        if temporary_name:
            _remove_temporary_file(parent_fd, temporary_name, temporary_fd)
    except BaseException as primary_failure:
        try:
            _close_descriptor(parent_fd)
        except BaseException as cleanup_failure:
            _retain_cleanup_failures(primary_failure, (cleanup_failure,))
        raise
    else:
        _close_descriptor(parent_fd)


def _remove_temporary_file(
    parent_fd: int,
    temporary_name: str,
    temporary_fd: int,
) -> None:
    try:
        expected = os.fstat(temporary_fd)
    except OSError as exc:
        raise BoundFileDestinationError("could not inspect the staged temporary file") from exc
    if not _remove_matching_destination(
        parent_fd=parent_fd,
        name=temporary_name,
        expected=expected,
    ):
        raise BoundFileDestinationError("could not remove the staged temporary file")
