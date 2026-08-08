#!/usr/bin/env python3
"""Fake curl with an exact command contract for PyPI workflow tests."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, cast

UNMODELED_EXIT = 96


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


def _reject(path: Path, state: dict[str, Any], tool: str, arguments: list[str]) -> int:
    state["unmodeled_calls"].append([tool, *arguments])
    _save_state(path, state)
    print(f"unmodeled {tool} command: {arguments!r}", file=sys.stderr)
    return UNMODELED_EXIT


def _handle_curl(path: Path, state: dict[str, Any], arguments: list[str]) -> int:
    version = state["release_tag"][1:]
    output = Path(os.environ["RUNNER_TEMP"]) / "pypi-response.json"
    expected = [
        "--silent",
        "--show-error",
        "--location",
        "--proto",
        "=https",
        "--tlsv1.2",
        "--connect-timeout",
        "10",
        "--max-time",
        "60",
        "--max-filesize",
        "8388608",
        "--retry",
        "4",
        "--retry-all-errors",
        "--retry-max-time",
        "45",
        "--output",
        str(output),
        "--write-out",
        "%{http_code}",
        f"https://pypi.org/pypi/vexcalibur/{version}/json",
    ]
    if arguments != expected:
        return _reject(path, state, "curl", arguments)
    if state["pypi_http_status"] == 200:
        output.write_text(json.dumps(state["pypi_response"]), encoding="utf-8")
    print(state["pypi_http_status"], end="")
    _save_state(path, state)
    return 0


def main() -> int:
    path, state = _load_state()
    if len(sys.argv) < 2:
        return _reject(path, state, "", [])
    tool = sys.argv[1]
    arguments = sys.argv[2:]
    state["calls"].append([tool, *arguments])
    _save_state(path, state)
    if tool == "curl":
        return _handle_curl(path, state, arguments)
    return _reject(path, state, tool, arguments)


if __name__ == "__main__":
    raise SystemExit(main())
