"""Explicit lifecycle states for execution-report publication."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from types import MappingProxyType
from typing import TypeVar


class DescriptorOwnership(Enum):
    """Whether a numeric descriptor remains safe for this process to release."""

    OWNED = auto()
    RELEASED = auto()
    AMBIGUOUS = auto()


@dataclass(frozen=True, slots=True)
class DescriptorState:
    """One atomic descriptor value and ownership assertion."""

    descriptor: int
    ownership: DescriptorOwnership

    def __post_init__(self) -> None:
        if self.ownership is DescriptorOwnership.OWNED:
            if self.descriptor < 0:
                raise ValueError("an owned descriptor must be non-negative")
            return
        if self.descriptor != -1:
            raise ValueError("a released or ambiguous descriptor must be -1")

    @classmethod
    def owned(cls, descriptor: int) -> DescriptorState:
        """Return an owned descriptor state."""
        return cls(descriptor, DescriptorOwnership.OWNED)

    @classmethod
    def released(cls) -> DescriptorState:
        """Return a definitively released descriptor state."""
        return cls(-1, DescriptorOwnership.RELEASED)

    @classmethod
    def ambiguous(cls) -> DescriptorState:
        """Return a descriptor state that must not be retried by number."""
        return cls(-1, DescriptorOwnership.AMBIGUOUS)


class StagedFileState(Enum):
    """Lifecycle of one private staged file and its publication."""

    STAGED = auto()
    PUBLISHING = auto()
    PUBLISHED = auto()
    ROLLBACK_REQUIRED = auto()
    ROLLED_BACK = auto()
    RELEASED = auto()


class PublishedRollbackState(Enum):
    """Lifecycle of the transaction-owned published-file rollback guard."""

    UNARMED = auto()
    ARMING = auto()
    ARMED = auto()
    PUBLICATION_PENDING = auto()
    PUBLISHED = auto()
    REMOVAL_PENDING = auto()
    DISCARDED = auto()
    RELEASED = auto()


class GenerationOutputState(Enum):
    """Lifecycle of one VEX-and-execution-report output transaction."""

    PREPARED = auto()
    COMMITTING = auto()
    REPORT_GUARD_ARMING = auto()
    REPORT_GUARDED = auto()
    COMMITTED = auto()
    ABORT_REQUIRED = auto()
    CLOSED = auto()


_PUBLISHED_ROLLBACK_TRANSITIONS = MappingProxyType(
    {
        PublishedRollbackState.UNARMED: frozenset(
            {PublishedRollbackState.ARMING, PublishedRollbackState.RELEASED}
        ),
        PublishedRollbackState.ARMING: frozenset(
            {
                PublishedRollbackState.ARMED,
                PublishedRollbackState.RELEASED,
            }
        ),
        PublishedRollbackState.ARMED: frozenset(
            {
                PublishedRollbackState.PUBLICATION_PENDING,
                PublishedRollbackState.REMOVAL_PENDING,
                PublishedRollbackState.DISCARDED,
                PublishedRollbackState.RELEASED,
            }
        ),
        PublishedRollbackState.PUBLICATION_PENDING: frozenset(
            {
                PublishedRollbackState.PUBLISHED,
                PublishedRollbackState.REMOVAL_PENDING,
                PublishedRollbackState.RELEASED,
            }
        ),
        PublishedRollbackState.PUBLISHED: frozenset(
            {
                PublishedRollbackState.REMOVAL_PENDING,
                PublishedRollbackState.DISCARDED,
                PublishedRollbackState.RELEASED,
            }
        ),
        PublishedRollbackState.REMOVAL_PENDING: frozenset(
            {
                PublishedRollbackState.DISCARDED,
                PublishedRollbackState.RELEASED,
            }
        ),
        PublishedRollbackState.DISCARDED: frozenset({PublishedRollbackState.RELEASED}),
        PublishedRollbackState.RELEASED: frozenset(),
    }
)

_STAGED_FILE_TRANSITIONS = MappingProxyType(
    {
        StagedFileState.STAGED: frozenset(
            {StagedFileState.PUBLISHING, StagedFileState.ROLLED_BACK}
        ),
        StagedFileState.PUBLISHING: frozenset(
            {StagedFileState.PUBLISHED, StagedFileState.ROLLBACK_REQUIRED}
        ),
        StagedFileState.PUBLISHED: frozenset(
            {StagedFileState.ROLLBACK_REQUIRED, StagedFileState.RELEASED}
        ),
        StagedFileState.ROLLBACK_REQUIRED: frozenset({StagedFileState.ROLLED_BACK}),
        StagedFileState.ROLLED_BACK: frozenset({StagedFileState.RELEASED}),
        StagedFileState.RELEASED: frozenset(),
    }
)

_GENERATION_OUTPUT_TRANSITIONS = MappingProxyType(
    {
        GenerationOutputState.PREPARED: frozenset(
            {
                GenerationOutputState.COMMITTING,
                GenerationOutputState.ABORT_REQUIRED,
                GenerationOutputState.CLOSED,
            }
        ),
        GenerationOutputState.COMMITTING: frozenset(
            {
                GenerationOutputState.REPORT_GUARD_ARMING,
                GenerationOutputState.ABORT_REQUIRED,
            }
        ),
        GenerationOutputState.REPORT_GUARD_ARMING: frozenset(
            {
                GenerationOutputState.REPORT_GUARDED,
                GenerationOutputState.ABORT_REQUIRED,
            }
        ),
        GenerationOutputState.REPORT_GUARDED: frozenset(
            {
                GenerationOutputState.COMMITTED,
                GenerationOutputState.ABORT_REQUIRED,
            }
        ),
        GenerationOutputState.COMMITTED: frozenset(
            {GenerationOutputState.ABORT_REQUIRED, GenerationOutputState.CLOSED}
        ),
        GenerationOutputState.ABORT_REQUIRED: frozenset({GenerationOutputState.CLOSED}),
        GenerationOutputState.CLOSED: frozenset(),
    }
)

_State = TypeVar(
    "_State",
    StagedFileState,
    PublishedRollbackState,
    GenerationOutputState,
)


def _require_transition(
    current: _State,
    target: _State,
    *,
    transitions: MappingProxyType[_State, frozenset[_State]],
    lifecycle: str,
) -> _State:
    if target not in transitions[current]:
        raise RuntimeError(
            f"invalid {lifecycle} lifecycle transition: {current.name} -> {target.name}"
        )
    return target


def require_published_rollback_transition(
    current: PublishedRollbackState,
    target: PublishedRollbackState,
) -> PublishedRollbackState:
    """Validate and return one rollback lifecycle transition."""
    return _require_transition(
        current,
        target,
        transitions=_PUBLISHED_ROLLBACK_TRANSITIONS,
        lifecycle="published rollback",
    )


def require_staged_file_transition(
    current: StagedFileState,
    target: StagedFileState,
) -> StagedFileState:
    """Validate and return one staged-file lifecycle transition."""
    return _require_transition(
        current,
        target,
        transitions=_STAGED_FILE_TRANSITIONS,
        lifecycle="staged file",
    )


def require_generation_output_transition(
    current: GenerationOutputState,
    target: GenerationOutputState,
) -> GenerationOutputState:
    """Validate and return one generation-output lifecycle transition."""
    return _require_transition(
        current,
        target,
        transitions=_GENERATION_OUTPUT_TRANSITIONS,
        lifecycle="generation output",
    )
