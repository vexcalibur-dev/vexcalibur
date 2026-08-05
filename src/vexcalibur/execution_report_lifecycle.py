"""Explicit lifecycle states for execution-report publication."""

from __future__ import annotations

from enum import Enum, auto
from types import MappingProxyType
from typing import TypeVar


class DescriptorOwnership(Enum):
    """Whether a numeric descriptor remains safe for this process to release."""

    OWNED = auto()
    RELEASED = auto()
    AMBIGUOUS = auto()


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

_State = TypeVar("_State", PublishedRollbackState, GenerationOutputState)


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
