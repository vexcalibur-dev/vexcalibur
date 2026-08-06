"""Path binding for descriptor-relative execution-report publication."""

from __future__ import annotations

import errno
import os
import stat
import unicodedata
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext, suppress
from pathlib import Path
from types import TracebackType
from typing import NoReturn

import vexcalibur.execution_report_locks as lock_module
import vexcalibur.execution_report_staging as staging_module
from vexcalibur.execution_report_errors import (
    BoundFileDestinationError as BoundFileDestinationError,
)
from vexcalibur.execution_report_errors import DestinationLockError as DestinationLockError
from vexcalibur.execution_report_errors import _retain_cleanup_failures
from vexcalibur.execution_report_filesystem import (
    _close_descriptor,
    _defer_keyboard_interrupt,
    _require_replaceable_leaf,
    _same_identity,
)
from vexcalibur.execution_report_lifecycle import DescriptorOwnership, DescriptorState
from vexcalibur.execution_report_locks import (
    DESTINATION_LOCK_RETRY_SECONDS as DESTINATION_LOCK_RETRY_SECONDS,
)
from vexcalibur.execution_report_locks import (
    DESTINATION_LOCK_TIMEOUT_SECONDS as DESTINATION_LOCK_TIMEOUT_SECONDS,
)
from vexcalibur.execution_report_locks import LOCK_DIRECTORY_NAME as LOCK_DIRECTORY_NAME
from vexcalibur.execution_report_locks import LOCK_FILE_NAME as LOCK_FILE_NAME
from vexcalibur.execution_report_locks import (
    acquire_destination_locks as acquire_destination_locks,
)
from vexcalibur.execution_report_locks import (
    acquire_stdout_sequence_lock as acquire_stdout_sequence_lock,
)
from vexcalibur.execution_report_staging import StagedFileWrite as StagedFileWrite

_exclusive_destination_lock = lock_module._exclusive_destination_lock
_open_private_destination_lock = lock_module._open_private_destination_lock
_FINALIZER_CLOSE_DESCRIPTOR = os.close
_BOUND_DESTINATION_TOKEN = object()


class BoundFileDestination:
    """A descriptor-bound file destination with one close-state transition."""

    __slots__ = (
        "_name",
        "_name_bytes",
        "_parent_descriptor_state",
        "access_parent_path",
        "parent_path",
        "requested_path",
    )

    def __init__(
        self,
        construction_token: object,
        *,
        requested_path: Path,
        access_parent_path: Path,
        parent_path: Path,
        name: str,
        name_bytes: bytes,
        parent_descriptor: int,
    ) -> None:
        if construction_token is not _BOUND_DESTINATION_TOKEN:
            raise TypeError("use BoundFileDestination.prepare()")
        if (
            not name
            or name_bytes in {b".", b".."}
            or b"/" in name_bytes
            or b"\0" in name_bytes
            or os.fsencode(name) != name_bytes
        ):
            raise ValueError("bound destination name must be one filesystem leaf")
        self.requested_path = requested_path
        self.access_parent_path = access_parent_path
        self.parent_path = parent_path
        self._name = name
        self._name_bytes = name_bytes
        self._parent_descriptor_state = DescriptorState.owned(parent_descriptor)

    @classmethod
    def _create(
        cls,
        *,
        requested_path: Path,
        access_parent_path: Path,
        parent_path: Path,
        name: str,
        name_bytes: bytes,
        parent_descriptor: int,
    ) -> BoundFileDestination:
        return cls(
            _BOUND_DESTINATION_TOKEN,
            requested_path=requested_path,
            access_parent_path=access_parent_path,
            parent_path=parent_path,
            name=name,
            name_bytes=name_bytes,
            parent_descriptor=parent_descriptor,
        )

    @property
    def name(self) -> str:
        """Return the display form of the bound filesystem leaf."""
        return self._name

    @property
    def closed(self) -> bool:
        """Return whether the retained parent descriptor is closed."""
        return self._parent_descriptor_state.ownership is DescriptorOwnership.RELEASED

    @property
    def _parent_descriptor(self) -> int:
        return self._parent_descriptor_state.descriptor

    @property
    def _parent_descriptor_ownership(self) -> DescriptorOwnership:
        return self._parent_descriptor_state.ownership

    @classmethod
    def prepare(
        cls,
        path: Path,
        *,
        protected_paths: tuple[Path | None, ...] = (),
        protected_descriptors: tuple[tuple[int, str], ...] = (),
        remove_existing: bool = False,
    ) -> BoundFileDestination:
        """Validate, bind, and optionally remove one existing destination."""
        if os.name == "nt":
            raise BoundFileDestinationError("execution reports are not supported on Windows")
        try:
            encoded_path = os.fsencode(path)
        except (TypeError, UnicodeError, ValueError) as exc:
            raise BoundFileDestinationError("destination path is not valid on this system") from exc
        if b"\0" in encoded_path:
            raise BoundFileDestinationError("destination path must not contain a NUL byte")
        name = path.name
        name_bytes = os.fsencode(name)
        if not name or name_bytes in {b".", b".."}:
            raise BoundFileDestinationError("destination must name a file")
        if _filename_key(name) == _filename_key(LOCK_DIRECTORY_NAME):
            raise BoundFileDestinationError(
                f"destination filename {LOCK_DIRECTORY_NAME!r} is reserved"
            )
        if _contains_reserved_lock_namespace(path.parent):
            raise BoundFileDestinationError(
                f"destination directory {LOCK_DIRECTORY_NAME!r} is reserved"
            )
        parent_descriptor = -1
        try:
            access_parent_path = path.absolute().parent
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_DIRECTORY", 0)
            with _defer_keyboard_interrupt():
                parent_descriptor = os.open(access_parent_path, flags)
            parent_stat = os.fstat(parent_descriptor)
            parent_path = access_parent_path.resolve(strict=True)
            if _contains_reserved_lock_namespace(parent_path):
                raise BoundFileDestinationError(
                    f"destination directory {LOCK_DIRECTORY_NAME!r} is reserved"
                )
            resolved_parent_stat = parent_path.stat()
            if (
                resolved_parent_stat.st_dev != parent_stat.st_dev
                or resolved_parent_stat.st_ino != parent_stat.st_ino
            ):
                raise OSError("destination parent directory changed during preparation")
        except BaseException as exc:
            if isinstance(exc, (OSError, RuntimeError)):
                failure: BaseException = BoundFileDestinationError(
                    _parent_preparation_error(path=path, error=exc)
                )
            else:
                failure = exc
            _retain_descriptor_cleanup_failure(failure, parent_descriptor)
            if failure is exc:
                raise
            raise failure from exc
        if not stat.S_ISDIR(parent_stat.st_mode):
            failure = BoundFileDestinationError("destination parent must be a directory")
            _retain_descriptor_cleanup_failure(failure, parent_descriptor)
            raise failure

        destination: BoundFileDestination | None = None
        try:
            destination = cls._create(
                requested_path=path,
                access_parent_path=access_parent_path,
                parent_path=parent_path,
                name=name,
                name_bytes=name_bytes,
                parent_descriptor=parent_descriptor,
            )
            for protected_path in protected_paths:
                if protected_path is not None and destination.aliases(protected_path):
                    raise BoundFileDestinationError(
                        "--execution-report must not replace an input or VEX output file"
                    )
            for protected_descriptor, description in protected_descriptors:
                if destination.aliases_descriptor(protected_descriptor):
                    raise BoundFileDestinationError(
                        f"--execution-report must not replace redirected {description}"
                    )
            destination.verify_replaceable_leaf()
            if remove_existing:
                destination.remove_existing()
        except BaseException as exc:
            try:
                if destination is None:
                    _close_descriptor(parent_descriptor)
                else:
                    destination.close()
            except BaseException as cleanup_failure:
                _retain_cleanup_failures(exc, (cleanup_failure,))
            raise
        return destination

    def aliases(self, other: Path | BoundFileDestination) -> bool:
        """Return whether another path can name this destination."""
        parent_stat = self._bound_parent_stat()
        if isinstance(other, BoundFileDestination):
            other_parent_stat = other._bound_parent_stat()
            same_parent = (
                parent_stat.st_dev == other_parent_stat.st_dev
                and parent_stat.st_ino == other_parent_stat.st_ino
            )
            if same_parent and _filename_key(self.name) == _filename_key(other.name):
                return True
            return self._same_existing_destination(other)

        other_path = Path(other)
        if self._same_existing_path(other_path):
            return True
        try:
            other_parent = other_path.parent.resolve(strict=True)
            other_parent_stat = other_parent.stat()
            same_parent = (
                parent_stat.st_dev == other_parent_stat.st_dev
                and parent_stat.st_ino == other_parent_stat.st_ino
            )
        except (OSError, RuntimeError):
            try:
                other_parent = other_path.parent.resolve(strict=False)
            except (OSError, RuntimeError):
                return False
            same_parent = other_parent == self.parent_path
        return same_parent and _filename_key(self.name) == _filename_key(other_path.name)

    def aliases_descriptor(self, descriptor: int) -> bool:
        """Return whether the current destination aliases one open file."""
        try:
            destination_stat = os.stat(
                self._name_bytes,
                dir_fd=self._require_parent_descriptor(),
            )
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise BoundFileDestinationError(
                "could not inspect the execution report destination"
            ) from exc
        try:
            descriptor_stat = os.fstat(descriptor)
        except OSError as exc:
            raise BoundFileDestinationError(
                "could not inspect a protected output descriptor"
            ) from exc
        return (
            destination_stat.st_dev == descriptor_stat.st_dev
            and destination_stat.st_ino == descriptor_stat.st_ino
        )

    def remove_existing(self, *, destination_lock_held: bool = False) -> None:
        """Remove and durably clear a non-directory destination."""
        parent_fd = -1
        try:
            try:
                with _defer_keyboard_interrupt():
                    parent_fd = self._open_parent()
                lock = (
                    nullcontext()
                    if destination_lock_held
                    else lock_module._exclusive_destination_lock(parent_fd)
                )
                with lock:
                    try:
                        destination_stat = os.stat(
                            self._name_bytes,
                            dir_fd=parent_fd,
                            follow_symlinks=False,
                        )
                    except FileNotFoundError:
                        return
                    _require_replaceable_leaf(destination_stat)
                    os.unlink(self._name_bytes, dir_fd=parent_fd)
                    os.fsync(parent_fd)
            finally:
                _close_descriptor(parent_fd)
        except BoundFileDestinationError:
            raise
        except OSError as exc:
            msg = f"could not remove stale execution report {self.requested_path}"
            raise BoundFileDestinationError(msg) from exc

    @contextmanager
    def stage_bytes(
        self,
        serialized: bytes,
    ) -> Iterator[StagedFileWrite]:
        """Yield flushed private temporary bytes and always reclaim their handles."""
        with staging_module.stage_destination_bytes(self, serialized) as staged:
            yield staged

    def write_bytes(self, serialized: bytes) -> None:
        """Stage and atomically replace this destination with exact bytes."""
        try:
            with self.stage_bytes(serialized) as staged:
                staged.commit()
        except BaseException as primary_failure:
            try:
                self.close()
            except BaseException as cleanup_failure:
                _retain_cleanup_failures(primary_failure, (cleanup_failure,))
            raise
        else:
            self.close()

    def verify_parent_path(self) -> None:
        """Require the bound parent to remain at its original path."""
        descriptor = -1
        try:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_DIRECTORY", 0)
            with _defer_keyboard_interrupt():
                descriptor = os.open(self.access_parent_path, flags)
            parent_stat = os.fstat(descriptor)
            bound_parent_stat = self._bound_parent_stat()
            if (
                not stat.S_ISDIR(parent_stat.st_mode)
                or parent_stat.st_dev != bound_parent_stat.st_dev
                or parent_stat.st_ino != bound_parent_stat.st_ino
            ):
                raise OSError("destination parent directory changed")
        except (BoundFileDestinationError, OSError) as exc:
            msg = "destination parent directory changed before publication"
            raise BoundFileDestinationError(msg) from exc
        finally:
            _close_descriptor(descriptor)

    def verify_replaceable_leaf(self) -> None:
        """Require an existing leaf to be a regular file or symbolic link."""
        parent_fd = -1
        try:
            with _defer_keyboard_interrupt():
                parent_fd = self._open_parent()
            self._verify_replaceable_leaf(parent_fd)
        finally:
            _close_descriptor(parent_fd)

    def _verify_replaceable_leaf(self, parent_fd: int) -> None:
        try:
            destination_stat = os.stat(
                self._name_bytes,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        except OSError as exc:
            raise BoundFileDestinationError("could not inspect the destination file") from exc
        _require_replaceable_leaf(destination_stat)

    def _same_existing_destination(self, other: BoundFileDestination) -> bool:
        try:
            destination_stat = os.stat(
                self._name_bytes,
                dir_fd=self._require_parent_descriptor(),
            )
            other_stat = os.stat(
                other._name_bytes,
                dir_fd=other._require_parent_descriptor(),
            )
        except OSError:
            return False
        return _same_identity(destination_stat, other_stat)

    def _same_existing_path(self, other: Path) -> bool:
        try:
            destination_stat = os.stat(
                self._name_bytes,
                dir_fd=self._require_parent_descriptor(),
            )
            other_stat = os.stat(other)
        except OSError:
            return False
        return _same_identity(destination_stat, other_stat)

    def _open_parent(self) -> int:
        self.verify_parent_path()
        return os.dup(self._require_parent_descriptor())

    def _bound_parent_stat(self) -> os.stat_result:
        try:
            return os.fstat(self._require_parent_descriptor())
        except OSError as exc:
            raise BoundFileDestinationError("bound parent directory is unavailable") from exc

    def _coordination_key(self) -> bytes:
        return _filename_key(self.name).encode("utf-8", errors="surrogatepass")

    def _require_parent_descriptor(self) -> int:
        if self.closed:
            raise BoundFileDestinationError("bound parent directory is already closed")
        return self._parent_descriptor

    def _create_temporary_file(self, parent_fd: int) -> tuple[int, str]:
        return staging_module._create_temporary_file(parent_fd)

    def close(self) -> None:
        """Close the retained parent directory descriptor."""
        state = getattr(self, "_parent_descriptor_state", DescriptorState.released())
        if state.ownership is DescriptorOwnership.RELEASED:
            return
        staging_module._close_owned_descriptor(self, "parent_descriptor")

    def __copy__(self) -> BoundFileDestination:
        raise TypeError("bound file destinations cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> BoundFileDestination:
        del memo
        raise TypeError("bound file destinations cannot be copied")

    def __reduce__(self) -> NoReturn:
        raise TypeError("bound file destinations cannot be serialized")

    def __enter__(self) -> BoundFileDestination:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def __del__(self) -> None:
        state = getattr(self, "_parent_descriptor_state", DescriptorState.released())
        descriptor = state.descriptor
        object.__setattr__(self, "_parent_descriptor_state", DescriptorState.released())
        if descriptor < 0:
            return
        with suppress(Exception):
            _FINALIZER_CLOSE_DESCRIPTOR(descriptor)


def _retain_descriptor_cleanup_failure(
    primary: BaseException,
    descriptor: int,
) -> None:
    try:
        _close_descriptor(descriptor)
    except BaseException as cleanup_failure:
        _retain_cleanup_failures(primary, (cleanup_failure,))


def _parent_preparation_error(*, path: Path, error: OSError | RuntimeError) -> str:
    if isinstance(error, RuntimeError):
        return f"could not resolve destination parent directory: {path.parent}"
    if error.errno == errno.ELOOP:
        return f"could not resolve destination parent directory: {path.parent}"
    if isinstance(error, PermissionError) or error.errno in {errno.EACCES, errno.EPERM}:
        return f"destination parent directory is not accessible: {path.parent}"
    if isinstance(error, FileNotFoundError) or error.errno in {errno.ENOENT, errno.ENOTDIR}:
        return f"destination parent directory does not exist: {path.parent}"
    if str(error) == "destination parent directory changed during preparation":
        return "destination parent directory changed during preparation"
    return f"could not open destination parent directory: {path.parent}"


def _filename_key(name: str) -> str:
    return unicodedata.normalize("NFC", name).casefold()


def _contains_reserved_lock_namespace(path: Path) -> bool:
    reserved = _filename_key(LOCK_DIRECTORY_NAME)
    return any(_filename_key(part) == reserved for part in path.parts)
