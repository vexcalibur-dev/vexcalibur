#!/usr/bin/env python3
"""Allow only the Python commands used by the release recovery workflows."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

UNMODELED_EXIT = 96
ROOT = Path(__file__).parents[2]
RECOVERY_CHECKER = ROOT / "scripts" / "check-recovery-contract.py"
TAG_SCHEMA_SCRIPT = """import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    tag = json.load(stream)
message = json.loads(tag["message"])
raise SystemExit(
    not (
        type(message.get("schema_version")) is int
        and message["schema_version"] == 1
    )
)
"""


def _load_state() -> tuple[Path, dict[str, Any]]:
    path = Path(os.environ["GH_TEST_STATE"])
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError("fake GitHub state must be a JSON object")
    return path, cast(dict[str, Any], value)


def _save_state(path: Path, state: dict[str, Any]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def _reject(arguments: list[str]) -> int:
    path, state = _load_state()
    state["unmodeled_calls"].append(["python3", *arguments])
    _save_state(path, state)
    print(f"unmodeled python3 command: {arguments!r}", file=sys.stderr)
    return UNMODELED_EXIT


def _run(arguments: list[str], *, standard_input: str | None = None) -> int:
    completed = subprocess.run(  # noqa: S603 - exact, test-owned Python command
        [sys.executable, *arguments],
        check=False,
        input=standard_input,
        text=True,
    )
    return completed.returncode


def main() -> int:
    arguments = sys.argv[1:]
    if len(arguments) == 3 and arguments[:2] == ["-I", "-"]:
        script = sys.stdin.read()
        candidate = Path(arguments[2])
        if script != TAG_SCHEMA_SCRIPT or not candidate.is_file() or candidate.is_symlink():
            return _reject(arguments)
        return _run(arguments, standard_input=script)

    if (
        len(arguments) == 4
        and arguments[:2] == ["-I", "scripts/check-recovery-contract.py"]
        and arguments[2] == "--ref"
        and re.fullmatch(r"[0-9a-f]{40}", arguments[3]) is not None
    ):
        candidate = Path.cwd() / arguments[1]
        try:
            exact_checker = (
                candidate.resolve(strict=True) != RECOVERY_CHECKER.resolve(strict=True)
                and candidate.read_bytes() == RECOVERY_CHECKER.read_bytes()
            )
        except OSError:
            exact_checker = False
        if exact_checker and candidate.is_file() and not candidate.is_symlink():
            return _run(arguments)

    return _reject(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
