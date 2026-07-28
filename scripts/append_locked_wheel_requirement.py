"""Compatibility entry point for the renamed distribution-locking helper."""

from __future__ import annotations

if __package__:
    from .append_locked_distribution_requirement import (
        append_locked_distribution_requirement,
    )
else:
    from append_locked_distribution_requirement import (
        append_locked_distribution_requirement,
    )


append_locked_wheel_requirement = append_locked_distribution_requirement


if __name__ == "__main__":
    if __package__:
        from .append_locked_distribution_requirement import main
    else:
        from append_locked_distribution_requirement import main

    main()
