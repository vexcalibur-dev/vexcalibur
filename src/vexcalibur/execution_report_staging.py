"""Private staging and atomic publication for bound destinations."""

from __future__ import annotations

import os
import secrets
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext, suppress
from types import TracebackType
from typing import NoReturn, Protocol

import vexcalibur.execution_report_locks as lock_module
from vexcalibur.execution_report_errors import BoundFileDestinationError
from vexcalibur.execution_report_filesystem import (
    _close_descriptor,
    _close_descriptor_retryable,
    _remove_matching_destination,
    _require_path_identity,
    _require_private_regular_file,
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


class StagedFileWrite:
    """Flushed bytes with one-shot publication state."""

    __slots__ = (
        "_closed",
        "_committed",
        "_retain_publication",
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
        parent_fd = -1
        try:
            parent_fd = os.dup(self.parent_fd)
            return PublishedFileRollback._create(
                parent_fd=parent_fd,
                name=self.destination._name_bytes,
                expected=self.temporary_stat,
            )
        except BaseException as exc:
            _close_descriptor(parent_fd)
            if isinstance(exc, OSError):
                raise BoundFileDestinationError(
                    "could not retain the published file rollback handle"
                ) from exc
            raise

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
        self._close_owned_descriptor("temporary_fd")
        self._close_owned_descriptor("parent_fd")
        object.__setattr__(self, "_closed", True)

    def _close_owned_descriptor(self, attribute: str) -> None:
        descriptor = getattr(self, attribute)
        _close_descriptor_retryable(descriptor)
        object.__setattr__(self, attribute, -1)

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

    __slots__ = ("_closed", "expected", "name", "parent_fd")

    def __init__(
        self,
        construction_token: object,
        *,
        parent_fd: int,
        name: str | bytes,
        expected: os.stat_result,
    ) -> None:
        if construction_token is not _PUBLISHED_FILE_ROLLBACK_TOKEN:
            raise TypeError("published rollback handles require a staged file")
        self.parent_fd = parent_fd
        self.name = name
        self.expected = expected
        self._closed = False

    @classmethod
    def _create(
        cls,
        *,
        parent_fd: int,
        name: str | bytes,
        expected: os.stat_result,
    ) -> PublishedFileRollback:
        return cls(
            _PUBLISHED_FILE_ROLLBACK_TOKEN,
            parent_fd=parent_fd,
            name=name,
            expected=expected,
        )

    def discard(self) -> bool:
        """Remove the publication only if it still has the retained identity."""
        if self._closed:
            return False
        return _remove_matching_destination(
            parent_fd=self.parent_fd,
            name=self.name,
            expected=self.expected,
        )

    def close(self) -> None:
        """Release the retained directory descriptor."""
        if self._closed:
            return
        _close_descriptor_retryable(self.parent_fd)
        object.__setattr__(self, "_closed", True)

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
        try:
            _cleanup_staged_file(parent_fd, temporary_name, file_descriptor)
        finally:
            _close_descriptor(file_descriptor)
        if isinstance(exc, BoundFileDestinationError):
            raise
        if isinstance(exc, OSError):
            raise BoundFileDestinationError(str(exc)) from exc
        raise
    try:
        yield staged
    finally:
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
        except BaseException:
            try:
                try:
                    expected = os.fstat(descriptor)
                except OSError:
                    pass
                else:
                    _remove_matching_destination(
                        parent_fd=parent_fd,
                        name=name,
                        expected=expected,
                    )
            finally:
                _close_descriptor(descriptor)
            raise
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
            try:
                expected = os.fstat(temporary_fd)
            except OSError:
                pass
            else:
                _remove_matching_destination(
                    parent_fd=parent_fd,
                    name=temporary_name,
                    expected=expected,
                )
    finally:
        _close_descriptor(parent_fd)
