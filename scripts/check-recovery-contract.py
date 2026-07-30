#!/usr/bin/env python3
"""Require a release tag to declare the current recovery contract."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys

CONTRACT_PATH = "release-evidence/recovery-contract.json"
EXPECTED_SCHEMA_VERSION = 1
MAX_CONTRACT_BYTES = 1024


class RecoveryContractError(ValueError):
    """Raised when a release cannot use the current recovery workflow."""


def _git(*arguments: str) -> bytes:
    git_path = shutil.which("git")
    if git_path is None:
        raise RecoveryContractError("the Git executable is unavailable")
    try:
        completed = subprocess.run(  # noqa: S603 - resolved Git with fixed subcommands
            [git_path, *arguments],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise RecoveryContractError("could not read the tagged recovery contract") from error
    return completed.stdout


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RecoveryContractError(f"duplicate recovery-contract field: {key}")
        result[key] = value
    return result


def read_contract_at_ref(ref: str) -> dict[str, object]:
    """Read and validate the bounded recovery contract stored at one Git ref."""
    commit = (
        _git("rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}")
        .decode("ascii")
        .strip()
    )
    blob = (
        _git(
            "rev-parse",
            "--verify",
            "--end-of-options",
            f"{commit}:{CONTRACT_PATH}",
        )
        .decode("ascii")
        .strip()
    )
    raw_size = _git("cat-file", "-s", blob).decode("ascii").strip()
    if not raw_size.isdecimal() or int(raw_size) > MAX_CONTRACT_BYTES:
        raise RecoveryContractError(f"{CONTRACT_PATH} exceeds the {MAX_CONTRACT_BYTES} byte limit")
    raw = _git("cat-file", "blob", blob)
    if len(raw) > MAX_CONTRACT_BYTES:
        raise RecoveryContractError(f"{CONTRACT_PATH} exceeds the {MAX_CONTRACT_BYTES} byte limit")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RecoveryContractError(f"{CONTRACT_PATH} is not valid UTF-8 JSON") from error
    if type(value) is not dict or set(value) != {"schema_version"}:
        raise RecoveryContractError(f"{CONTRACT_PATH} has invalid fields")
    schema_version = value["schema_version"]
    if type(schema_version) is not int or schema_version != EXPECTED_SCHEMA_VERSION:
        raise RecoveryContractError("the tagged release uses an unsupported recovery contract")
    return value


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ref", required=True)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    try:
        read_contract_at_ref(args.ref)
    except RecoveryContractError as error:
        print(f"recovery contract error: {error}", file=sys.stderr)
        return 2
    print(f"recovery contract {EXPECTED_SCHEMA_VERSION} verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
