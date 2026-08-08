#!/usr/bin/env python3
"""Fake GitHub CLI that records and validates each release command."""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

UNMODELED_EXIT = 96
AUTHENTICATION_EXIT = 97
GRAPHQL_QUERY_ARGUMENT = (
    "query=query($owner:String!,$repository:String!,$tag:String!){\n"
    "      repository(owner:$owner,name:$repository){\n"
    "        release(tagName:$tag){databaseId}\n"
    "      }\n"
    "    }"
)
IMMUTABLE_POLICY_QUERIES = {
    "if (.enabled == true and .enforced_by_owner == true)\n"
    '          then "verified" else "rejected" end',
    "if (.enabled == true and .enforced_by_owner == true)\n"
    '            then "verified" else "rejected" end',
}
ARTIFACT_QUERY = (
    ".artifacts[] |\n"
    "          [.name,\n"
    '           (if .expired == false then "current" else "invalid" end),\n'
    "           .digest] | @tsv"
)


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


def _write_json(value: object) -> None:
    json.dump(value, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")


def _reject(path: Path, state: dict[str, Any], arguments: list[str]) -> int:
    state["unmodeled_calls"].append(arguments)
    _save_state(path, state)
    print(f"unmodeled gh command: {arguments!r}", file=sys.stderr)
    return UNMODELED_EXIT


def _reject_authentication(path: Path, state: dict[str, Any]) -> int:
    state["authentication_failures"] += 1
    _save_state(path, state)
    print("invalid fake GitHub token", file=sys.stderr)
    return AUTHENTICATION_EXIT


def _reject_verification(path: Path, state: dict[str, Any], message: str) -> int:
    _save_state(path, state)
    print(message, file=sys.stderr)
    return 1


def _public_release(release: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in release.items() if not key.startswith("_")}


def _public_asset(asset: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in asset.items() if not key.startswith("_")}


def _is_mutable_draft(release: dict[str, Any]) -> bool:
    return release.get("draft") is True and release.get("immutable") is not True


def _graphql_arguments_are_exact(arguments: list[str], state: dict[str, Any]) -> bool:
    if len(arguments) != 10 or arguments[:3] != ["api", "graphql", "-f"]:
        return False
    if arguments[4] != "-F" or arguments[6] != "-F" or arguments[8] != "-F":
        return False
    owner, repository = state["repository"].split("/", maxsplit=1)
    return (
        arguments[3] == GRAPHQL_QUERY_ARGUMENT
        and arguments[5] == f"owner={owner}"
        and arguments[7] == f"repository={repository}"
        and arguments[9] == f"tag={state['release_tag']}"
    )


def _handle_graphql(path: Path, state: dict[str, Any], arguments: list[str]) -> int:
    if not _graphql_arguments_are_exact(arguments, state):
        return _reject(path, state, arguments)
    responses = state["graphql_responses"]
    if responses:
        response = responses.pop(0)
    elif state["graphql_scripted"]:
        return _reject(path, state, arguments)
    else:
        release = state["release"]
        resolved = None if release is None else {"databaseId": release["id"]}
        response = {"data": {"repository": {"release": resolved}}}
    _write_json(response)
    _save_state(path, state)
    return 0


def _release_for_endpoint(state: dict[str, Any], endpoint: str) -> dict[str, Any] | None:
    release = state["release"]
    if release is None:
        return None
    repository = state["repository"]
    if endpoint == f"repos/{repository}/releases/tags/{state['release_tag']}":
        return cast(dict[str, Any], release)
    accepted_ids = {release["id"]}
    if state["rest_lookup_id"] is not None:
        accepted_ids.add(state["rest_lookup_id"])
    if endpoint in {f"repos/{repository}/releases/{release_id}" for release_id in accepted_ids}:
        if (
            release["draft"] is False
            and release["immutable"] is not True
            and state["publication_completes"]
        ):
            remaining = state["publication_polls_remaining"]
            state["publication_polls_remaining"] = max(0, remaining - 1)
            if remaining <= 1:
                release["immutable"] = True
        return cast(dict[str, Any], release)
    return None


def _handle_api(path: Path, state: dict[str, Any], arguments: list[str]) -> int:
    if len(arguments) > 1 and arguments[1] == "graphql":
        return _handle_graphql(path, state, arguments)

    repository = state["repository"]
    release = state["release"]
    main_endpoint = f"repos/{repository}/git/ref/heads/main"
    compare_endpoint = f"repos/{repository}/compare/{state['release_sha']}...{state['main_sha']}"
    user_endpoint = f"/users/{state['app_slug']}%5Bbot%5D"
    tag_ref_endpoint = f"repos/{repository}/git/ref/tags/{state['release_tag']}"
    tag_object_endpoint = f"repos/{repository}/git/tags/{state['tag_object_sha']}"
    policy_endpoint = f"repos/{repository}/immutable-releases"
    artifact_endpoint = f"repos/{repository}/actions/runs/{state['run_id']}/artifacts?per_page=100"

    if arguments == ["api", main_endpoint, "--jq", ".object.sha"]:
        print(state["main_sha"])
    elif arguments == ["api", compare_endpoint, "--jq", ".status"]:
        print(state["comparison_status"])
    elif arguments == ["api", user_endpoint, "--jq", ".id"]:
        print(state["bot_user_id"])
    elif arguments == ["api", tag_ref_endpoint]:
        _write_json(state["tag_ref"])
    elif arguments == ["api", tag_object_endpoint]:
        _write_json(state["tag_object"])
    elif arguments == ["api", "--paginate", artifact_endpoint, "--jq", ARTIFACT_QUERY]:
        for artifact in state["run_artifacts"]:
            expiration = "invalid" if artifact["expired"] else "current"
            print(f"{artifact['name']}\t{expiration}\tsha256:{artifact['digest']}")
    elif (
        len(arguments) == 8
        and arguments[:5]
        == [
            "api",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "X-GitHub-Api-Version: 2026-03-10",
        ]
        and arguments[5] == policy_endpoint
        and arguments[6] == "--jq"
        and arguments[7] in IMMUTABLE_POLICY_QUERIES
    ):
        failures = state["policy_failures"]
        if failures and failures.pop(0):
            _save_state(path, state)
            print("simulated policy request failure", file=sys.stderr)
            return 1
        responses = state["policy_responses"]
        if responses:
            response = responses.pop(0)
        else:
            response = {
                "enabled": state["immutable_policy"],
                "enforced_by_owner": state["immutable_policy"],
            }
        jq = shutil.which("jq")
        if jq is None:
            return _reject(path, state, arguments)
        completed = subprocess.run(  # noqa: S603 - resolved jq with a validated query
            [jq, "-r", arguments[7]],
            check=False,
            capture_output=True,
            input=json.dumps(response),
            text=True,
        )
        if completed.returncode != 0:
            _save_state(path, state)
            sys.stderr.write(completed.stderr)
            return completed.returncode
        sys.stdout.write(completed.stdout)
    elif len(arguments) == 2 and (resolved := _release_for_endpoint(state, arguments[1])):
        _write_json(_public_release(resolved))
    elif release is not None and arguments == [
        "api",
        "--paginate",
        f"repos/{repository}/releases/{release['id']}/assets?per_page=100",
        "--jq",
        ".[]",
    ]:
        for asset in release["_assets"]:
            _write_json(_public_asset(asset))
    elif (
        release is not None
        and _is_mutable_draft(release)
        and len(arguments) == 4
        and arguments[:3] == ["api", "--method", "DELETE"]
        and arguments[3]
        in {f"repos/{repository}/releases/assets/{asset['id']}" for asset in release["_assets"]}
    ):
        asset_id = arguments[3].rsplit("/", maxsplit=1)[1]
        matching = [asset for asset in release["_assets"] if str(asset["id"]) == asset_id]
        if len(matching) != 1:
            return _reject(path, state, arguments)
        release["_assets"].remove(matching[0])
    elif (
        release is not None
        and len(arguments) == 4
        and arguments[:3] == ["api", "-H", "Accept: application/octet-stream"]
        and arguments[3]
        in {f"repos/{repository}/releases/assets/{asset['id']}" for asset in release["_assets"]}
    ):
        asset_id = arguments[3].rsplit("/", maxsplit=1)[1]
        matching = [asset for asset in release["_assets"] if str(asset["id"]) == asset_id]
        if len(matching) != 1:
            return _reject(path, state, arguments)
        sys.stdout.buffer.write(base64.b64decode(matching[0]["_bytes"]))
    elif (
        release is not None
        and _is_mutable_draft(release)
        and len(arguments) == 6
        and arguments[:3] == ["api", "--method", "PATCH"]
        and arguments[3] == f"repos/{repository}/releases/{release['id']}"
        and arguments[4] == "--input"
    ):
        expected_input = Path(os.environ["RUNNER_TEMP"]) / "immutable-publication-transition.json"
        if not _is_exact_file(arguments[5], expected_input):
            return _reject(path, state, arguments)
        payload = json.loads(expected_input.read_text(encoding="utf-8"))
        if set(payload) != {
            "tag_name",
            "target_commitish",
            "name",
            "body",
            "draft",
            "prerelease",
        }:
            return _reject(path, state, arguments)
        release.update(payload)
        if (
            release.get("draft") is False
            and state["publication_completes"]
            and state["publication_polls_remaining"] == 0
        ):
            release["immutable"] = True
        _write_json(_public_release(release))
    else:
        return _reject(path, state, arguments)

    _save_state(path, state)
    return 0


def _is_allowed_file(state: dict[str, Any], raw_path: str) -> bool:
    path = Path(raw_path)
    absolute = path if path.is_absolute() else Path.cwd() / path
    try:
        resolved = absolute.resolve(strict=True)
    except OSError:
        return False
    roots = {Path(root).resolve() for root in state["allowed_asset_roots"]}
    return absolute.is_file() and not absolute.is_symlink() and resolved.parent in roots


def _is_exact_file(raw_path: str, expected: Path) -> bool:
    path = Path(raw_path)
    try:
        return (
            raw_path == str(expected)
            and path.resolve(strict=True) == expected.resolve(strict=True)
            and path.is_file()
            and not path.is_symlink()
        )
    except OSError:
        return False


def _new_asset(state: dict[str, Any], local_path: Path, *, starter: bool) -> dict[str, Any]:
    contents = b"" if starter else local_path.read_bytes()
    asset = {
        "id": state["next_asset_id"],
        "name": local_path.name,
        "size": len(contents),
        "state": "starter" if starter else "uploaded",
        "uploader": {"login": f"{state['app_slug']}[bot]"},
        "label": None,
        "_bytes": base64.b64encode(contents).decode("ascii"),
    }
    state["next_asset_id"] += 1
    return asset


def _handle_create(path: Path, state: dict[str, Any], arguments: list[str]) -> int:
    repository = state["repository"]
    tag = state["release_tag"]
    expected_prefix = [
        "release",
        "create",
        tag,
        "--repo",
        repository,
        "--draft",
        "--verify-tag",
        "--target",
        state["release_sha"],
        "--title",
        tag,
        "--notes-file",
    ]
    if len(arguments) != 13 or arguments[:12] != expected_prefix or state["release"] is not None:
        return _reject(path, state, arguments)
    notes_path = Path(os.environ["RUNNER_TEMP"]) / "release-notes" / "vexcalibur-release-notes.md"
    if not _is_exact_file(arguments[12], notes_path):
        return _reject(path, state, arguments)
    state["release"] = {
        "id": state["release_id"],
        "tag_name": tag,
        "target_commitish": state["release_sha"],
        "name": tag,
        "body": notes_path.read_text(encoding="utf-8"),
        "draft": True,
        "prerelease": False,
        "immutable": False,
        "author": {"login": f"{state['app_slug']}[bot]"},
        "_assets": [],
    }
    exit_code = 1 if state["concurrent_create"] else 0
    _save_state(path, state)
    return exit_code


def _handle_upload(path: Path, state: dict[str, Any], arguments: list[str]) -> int:
    repository = state["repository"]
    release = state["release"]
    if (
        release is None
        or not _is_mutable_draft(release)
        or len(arguments) != 6
        or arguments[:3] != ["release", "upload", state["release_tag"]]
        or arguments[4:] != ["--repo", repository]
    ):
        return _reject(path, state, arguments)
    local_path = Path(arguments[3])
    if not _is_allowed_file(state, arguments[3]):
        return _reject(path, state, arguments)
    mode = state["upload_mode"]
    if mode == "complete":
        release["_assets"].append(_new_asset(state, local_path, starter=False))
    elif mode == "starter-once":
        starter = state["starter_uploads_remaining"] > 0
        state["starter_uploads_remaining"] -= int(starter)
        release["_assets"].append(_new_asset(state, local_path, starter=starter))
    elif mode != "missing":
        return _reject(path, state, arguments)
    exit_code = cast(int, state["upload_exit"])
    _save_state(path, state)
    return exit_code


def _handle_verify(path: Path, state: dict[str, Any], arguments: list[str]) -> int:
    repository = state["repository"]
    release = state["release"]
    if arguments == ["release", "verify", state["release_tag"], "--repo", repository]:
        if release is None or release["draft"] is not False or release["immutable"] is not True:
            return _reject(path, state, arguments)
        remaining = state["verify_release_failures"]
        state["verify_release_failures"] = max(0, remaining - 1)
        _save_state(path, state)
        return int(remaining > 0)
    if (
        release is not None
        and len(arguments) == 6
        and arguments[:3] == ["release", "verify-asset", state["release_tag"]]
        and arguments[4:] == ["--repo", repository]
        and release["draft"] is False
        and release["immutable"] is True
    ):
        local_path = Path(arguments[3])
        if not _is_allowed_file(state, arguments[3]):
            return _reject(path, state, arguments)
        matching = [asset for asset in release["_assets"] if asset["name"] == local_path.name]
        if len(matching) != 1:
            return _reject_verification(
                path,
                state,
                "release asset attestation target is missing or ambiguous",
            )
        if base64.b64decode(matching[0]["_bytes"]) != local_path.read_bytes():
            return _reject_verification(
                path,
                state,
                "release asset attestation bytes do not match",
            )
        remaining = state["verify_asset_failures"]
        state["verify_asset_failures"] = max(0, remaining - 1)
        _save_state(path, state)
        return int(remaining > 0)
    return _reject(path, state, arguments)


def _handle_release(path: Path, state: dict[str, Any], arguments: list[str]) -> int:
    if len(arguments) > 1 and arguments[1] == "create":
        return _handle_create(path, state, arguments)
    if len(arguments) > 1 and arguments[1] == "upload":
        return _handle_upload(path, state, arguments)
    if len(arguments) > 1 and arguments[1] in {"verify", "verify-asset"}:
        return _handle_verify(path, state, arguments)
    return _reject(path, state, arguments)


def _has_required_token(state: dict[str, Any], arguments: list[str]) -> bool:
    token = os.environ.get("GH_TOKEN")
    read_token = cast(str, state["read_token"])
    write_token = cast(str, state["write_token"])
    mutation = (arguments[:2] in (["release", "create"], ["release", "upload"])) or (
        len(arguments) > 2
        and arguments[:2] == ["api", "--method"]
        and arguments[2] in {"DELETE", "PATCH", "POST"}
    )
    if mutation:
        return token == write_token
    return token in {read_token, write_token}


def main() -> int:
    path, state = _load_state()
    arguments = sys.argv[1:]
    state["calls"].append(arguments)
    _save_state(path, state)
    if not arguments:
        return _reject(path, state, arguments)
    if not _has_required_token(state, arguments):
        return _reject_authentication(path, state)
    if arguments[0] == "api":
        return _handle_api(path, state, arguments)
    if arguments[0] == "release":
        return _handle_release(path, state, arguments)
    return _reject(path, state, arguments)


if __name__ == "__main__":
    raise SystemExit(main())
