#!/usr/bin/env python3
"""Read and validate the GitHub controls for the Vexcalibur repositories."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, cast

ORGANIZATION = "vexcalibur-dev"
BRANCH_RULESET_NAME = "protected main (PR + CI)"
TAG_CREATION_RULESET_NAME = "restricted release tag creation"
TAG_IMMUTABILITY_RULESET_NAME = "immutable release tags"
GITHUB_ACTIONS_INTEGRATION_ID = 15368
RELEASE_AUTOMATION_INTEGRATION_ID = 4250150

REQUIRED_CHECKS: dict[str, tuple[str, ...]] = {
    "vexcalibur": ("Analyze Python", "CI result", "dependency-review", "pre-commit"),
    "vexcalibur-action": ("Analyze (actions)", "Analyze (python)", "CI result"),
    "vexcalibur-orb": ("Analyze (actions)", "Analyze (python)", "Quality"),
    ".github": (
        "Analyze (actions)",
        "Smoke Python security commands",
        "Validate workflow templates",
    ),
}

TAG_CREATION_BYPASSES: dict[str, tuple[tuple[object, str, str], ...]] = {
    "vexcalibur": ((RELEASE_AUTOMATION_INTEGRATION_ID, "Integration", "always"),),
    "vexcalibur-action": ((RELEASE_AUTOMATION_INTEGRATION_ID, "Integration", "always"),),
    "vexcalibur-orb": ((None, "OrganizationAdmin", "always"),),
}

DEFAULT_CODEQL_REPOSITORIES = ("vexcalibur-action", "vexcalibur-orb", ".github")
CODEQL_LANGUAGES: dict[str, tuple[str, ...]] = {
    "vexcalibur-action": ("actions", "python"),
    "vexcalibur-orb": ("actions", "python"),
    ".github": ("actions",),
}

JsonObject = Mapping[str, object]


class GovernanceReadError(RuntimeError):
    """A required GitHub governance endpoint could not be read safely."""


class ApiClient(Protocol):
    """Minimal read-only client used by snapshot collection."""

    def get(self, endpoint: str) -> object:
        """Return the decoded response from one GitHub REST endpoint."""


class GhApiClient:
    """Read GitHub REST endpoints through the authenticated ``gh`` CLI."""

    def get(self, endpoint: str) -> object:
        """GET and decode an endpoint without exposing authentication material."""
        environment = dict(os.environ)
        environment.update({"GH_PAGER": "cat", "NO_COLOR": "1", "PAGER": "cat"})
        gh_path = shutil.which("gh")
        if gh_path is None:
            raise GovernanceReadError("the gh CLI is not installed or is not on PATH")
        try:
            result = subprocess.run(  # noqa: S603 - fixed executable and endpoint inventory
                [
                    gh_path,
                    "api",
                    "--hostname",
                    "github.com",
                    "--method",
                    "GET",
                    "-H",
                    "Accept: application/vnd.github+json",
                    "-H",
                    "X-GitHub-Api-Version: 2026-03-10",
                    endpoint,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
                env=environment,
            )
        except subprocess.TimeoutExpired as error:
            raise GovernanceReadError(f"GitHub endpoint timed out: {endpoint}") from error
        except OSError as error:
            raise GovernanceReadError("the gh CLI could not be executed") from error

        if result.returncode != 0:
            # Deliberately omit gh's output. Authentication errors can contain details
            # that do not belong in copied CI logs or issue reports.
            raise GovernanceReadError(
                f"GitHub endpoint was inaccessible: {endpoint} (gh exited {result.returncode})"
            )

        response = result.stdout.strip()
        if not response:
            return None
        try:
            return cast(object, json.loads(response))
        except json.JSONDecodeError as error:
            raise GovernanceReadError(
                f"GitHub endpoint returned non-JSON data: {endpoint}"
            ) from error


@dataclass(frozen=True)
class GovernanceSnapshot:
    """The security-relevant GitHub configuration read by the checker."""

    repository_rulesets: Mapping[str, Sequence[JsonObject]]
    repositories: Mapping[str, JsonObject]
    organization_installations: JsonObject
    organization_actions_permissions: JsonObject
    organization_immutable_releases: JsonObject
    orb_vulnerability_alerts_enabled: bool
    orb_automated_security_fixes: JsonObject
    orb_private_vulnerability_reporting: JsonObject
    codeql_default_setups: Mapping[str, JsonObject]
    pypi_environment: JsonObject
    pypi_deployment_branch_policies: JsonObject


def collect_snapshot(client: ApiClient) -> GovernanceSnapshot:
    """Collect every required setting using read-only REST requests."""
    repository_rulesets: dict[str, tuple[JsonObject, ...]] = {}
    for repository in REQUIRED_CHECKS:
        endpoint = f"repos/{ORGANIZATION}/{repository}/rulesets?per_page=100"
        summaries = _require_sequence(client.get(endpoint), endpoint)
        details: list[JsonObject] = []
        for summary_value in summaries:
            summary = _require_mapping(summary_value, endpoint)
            ruleset_id = summary.get("id")
            if not isinstance(ruleset_id, int) or isinstance(ruleset_id, bool):
                raise GovernanceReadError(
                    f"GitHub endpoint omitted a numeric ruleset id: {endpoint}"
                )
            detail_endpoint = f"repos/{ORGANIZATION}/{repository}/rulesets/{ruleset_id}"
            details.append(_require_mapping(client.get(detail_endpoint), detail_endpoint))
        repository_rulesets[repository] = tuple(details)

    vulnerability_alerts_endpoint = f"repos/{ORGANIZATION}/vexcalibur-orb/vulnerability-alerts"
    vulnerability_alerts_response = client.get(vulnerability_alerts_endpoint)
    if vulnerability_alerts_response is not None:
        raise GovernanceReadError(
            "GitHub returned an unexpected body while checking Orb vulnerability alerts"
        )

    return GovernanceSnapshot(
        repository_rulesets=repository_rulesets,
        repositories={
            repository: _get_mapping(client, f"repos/{ORGANIZATION}/{repository}")
            for repository in REQUIRED_CHECKS
        },
        organization_installations=_get_mapping(
            client, f"orgs/{ORGANIZATION}/installations?per_page=100"
        ),
        organization_actions_permissions=_get_mapping(
            client, f"orgs/{ORGANIZATION}/actions/permissions"
        ),
        organization_immutable_releases=_get_mapping(
            client, f"orgs/{ORGANIZATION}/settings/immutable-releases"
        ),
        orb_vulnerability_alerts_enabled=True,
        orb_automated_security_fixes=_get_mapping(
            client, f"repos/{ORGANIZATION}/vexcalibur-orb/automated-security-fixes"
        ),
        orb_private_vulnerability_reporting=_get_mapping(
            client, f"repos/{ORGANIZATION}/vexcalibur-orb/private-vulnerability-reporting"
        ),
        codeql_default_setups={
            repository: _get_mapping(
                client,
                f"repos/{ORGANIZATION}/{repository}/code-scanning/default-setup",
            )
            for repository in DEFAULT_CODEQL_REPOSITORIES
        },
        pypi_environment=_get_mapping(client, f"repos/{ORGANIZATION}/vexcalibur/environments/pypi"),
        pypi_deployment_branch_policies=_get_mapping(
            client,
            f"repos/{ORGANIZATION}/vexcalibur/environments/pypi/deployment-branch-policies",
        ),
    )


def load_snapshot(path: Path) -> GovernanceSnapshot:
    """Load an offline snapshot for deterministic testing and incident triage."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GovernanceReadError(f"could not load governance snapshot: {path}") from error
    root = _require_mapping(raw, str(path))
    raw_rulesets = _require_mapping(root.get("repository_rulesets"), str(path))
    raw_repositories = _require_mapping(root.get("repositories"), str(path))
    repository_rulesets: dict[str, tuple[JsonObject, ...]] = {}
    repositories: dict[str, JsonObject] = {}
    for repository in REQUIRED_CHECKS:
        values = _require_sequence(raw_rulesets.get(repository), str(path))
        repository_rulesets[repository] = tuple(
            _require_mapping(value, str(path)) for value in values
        )
        repositories[repository] = _require_mapping(
            raw_repositories.get(repository), f"{path}:repositories:{repository}"
        )

    return GovernanceSnapshot(
        repository_rulesets=repository_rulesets,
        repositories=repositories,
        organization_installations=_snapshot_mapping(root, "organization_installations", path),
        organization_actions_permissions=_snapshot_mapping(
            root, "organization_actions_permissions", path
        ),
        organization_immutable_releases=_snapshot_mapping(
            root, "organization_immutable_releases", path
        ),
        orb_vulnerability_alerts_enabled=_snapshot_bool(
            root, "orb_vulnerability_alerts_enabled", path
        ),
        orb_automated_security_fixes=_snapshot_mapping(root, "orb_automated_security_fixes", path),
        orb_private_vulnerability_reporting=_snapshot_mapping(
            root, "orb_private_vulnerability_reporting", path
        ),
        codeql_default_setups={
            repository: _require_mapping(
                _snapshot_mapping(root, "codeql_default_setups", path).get(repository),
                f"{path}:codeql_default_setups:{repository}",
            )
            for repository in DEFAULT_CODEQL_REPOSITORIES
        },
        pypi_environment=_snapshot_mapping(root, "pypi_environment", path),
        pypi_deployment_branch_policies=_snapshot_mapping(
            root, "pypi_deployment_branch_policies", path
        ),
    )


def validate_snapshot(snapshot: GovernanceSnapshot) -> tuple[str, ...]:
    """Return deterministic policy violations without changing GitHub state."""
    errors: list[str] = []
    for repository, required_checks in REQUIRED_CHECKS.items():
        _expect(
            errors,
            f"{repository} default branch",
            snapshot.repositories.get(repository, {}).get("default_branch"),
            "main",
        )
        rulesets = snapshot.repository_rulesets.get(repository, ())
        branch_ruleset = _named_ruleset(rulesets, BRANCH_RULESET_NAME, repository, errors)
        if branch_ruleset is not None:
            _validate_branch_ruleset(repository, branch_ruleset, required_checks, errors)

        if repository in TAG_CREATION_BYPASSES:
            creation_ruleset = _named_ruleset(
                rulesets, TAG_CREATION_RULESET_NAME, repository, errors
            )
            if creation_ruleset is not None:
                _validate_tag_creation_ruleset(repository, creation_ruleset, errors)
            immutable_ruleset = _named_ruleset(
                rulesets, TAG_IMMUTABILITY_RULESET_NAME, repository, errors
            )
            if immutable_ruleset is not None:
                _validate_tag_immutability_ruleset(repository, immutable_ruleset, errors)

    _expect(
        errors,
        "organization Actions applicability",
        snapshot.organization_actions_permissions.get("enabled_repositories"),
        "all",
    )
    _expect(
        errors,
        "organization Actions SHA pinning",
        snapshot.organization_actions_permissions.get("sha_pinning_required"),
        True,
    )
    _expect(
        errors,
        "organization immutable releases",
        snapshot.organization_immutable_releases.get("enforced_repositories"),
        "all",
    )
    _validate_release_automation_installation(snapshot, errors)
    _validate_orb_security(snapshot, errors)
    _validate_codeql_default_setups(snapshot, errors)
    _validate_pypi_environment(snapshot, errors)
    return tuple(sorted(errors))


def _validate_release_automation_installation(
    snapshot: GovernanceSnapshot, errors: list[str]
) -> None:
    installations = _mapping_sequence(snapshot.organization_installations.get("installations"))
    matches = tuple(
        installation
        for installation in installations
        if installation.get("app_id") == RELEASE_AUTOMATION_INTEGRATION_ID
    )
    if len(matches) != 1:
        errors.append(
            f"release automation App installation: expected exactly one, got {len(matches)}"
        )
        return

    installation = matches[0]
    _expect(
        errors,
        "release automation App slug",
        installation.get("app_slug"),
        "vexcalibur-dev-automation",
    )
    _expect(
        errors,
        "release automation App target",
        installation.get("target_type"),
        "Organization",
    )
    _expect(
        errors,
        "release automation App repository selection",
        installation.get("repository_selection"),
        "all",
    )
    _expect(
        errors,
        "release automation App suspension",
        installation.get("suspended_at"),
        None,
    )
    _expect(
        errors,
        "release automation App permissions",
        _mapping_value(installation, "permissions"),
        {"contents": "write", "metadata": "read"},
    )


def _validate_branch_ruleset(
    repository: str,
    ruleset: JsonObject,
    required_checks: tuple[str, ...],
    errors: list[str],
) -> None:
    label = f"{repository} default-branch ruleset"
    _expect(errors, f"{label} target", ruleset.get("target"), "branch")
    _expect(errors, f"{label} enforcement", ruleset.get("enforcement"), "active")
    _expect(errors, f"{label} bypass actors", _bypass_actors(ruleset), ())
    _expect(
        errors,
        f"{label} ref condition",
        _ref_condition(ruleset),
        (("~DEFAULT_BRANCH",), ()),
    )

    rules = _rules(ruleset)
    _expect(
        errors,
        f"{label} rule types",
        tuple(sorted(rule_type for rule_type, _ in rules)),
        ("deletion", "non_fast_forward", "pull_request", "required_status_checks"),
    )
    pull_request = _single_rule_parameters(rules, "pull_request")
    expected_pull_request = {
        "allowed_merge_methods": ("rebase", "squash"),
        "require_code_owner_review": False,
        "require_last_push_approval": False,
        "required_approving_review_count": 0,
        "required_review_thread_resolution": True,
    }
    for key, expected in expected_pull_request.items():
        actual = pull_request.get(key)
        if key == "allowed_merge_methods":
            actual = _string_tuple(actual)
        _expect(errors, f"{label} pull-request {key}", actual, expected)

    status_parameters = _single_rule_parameters(rules, "required_status_checks")
    _expect(
        errors,
        f"{label} strict required checks",
        status_parameters.get("strict_required_status_checks_policy"),
        True,
    )
    _expect(
        errors,
        f"{label} creation behavior",
        status_parameters.get("do_not_enforce_on_create"),
        True,
    )
    expected_status_checks = tuple(
        (context, GITHUB_ACTIONS_INTEGRATION_ID) for context in sorted(required_checks)
    )
    _expect(
        errors,
        f"{label} required checks",
        _status_checks(status_parameters),
        expected_status_checks,
    )


def _validate_tag_creation_ruleset(repository: str, ruleset: JsonObject, errors: list[str]) -> None:
    label = f"{repository} release-tag creation ruleset"
    _validate_tag_ruleset_base(label, ruleset, errors)
    _expect(errors, f"{label} rule types", _rule_types(ruleset), ("creation",))
    _expect(
        errors,
        f"{label} bypass actors",
        _bypass_actors(ruleset),
        TAG_CREATION_BYPASSES[repository],
    )


def _validate_tag_immutability_ruleset(
    repository: str, ruleset: JsonObject, errors: list[str]
) -> None:
    label = f"{repository} immutable release-tag ruleset"
    _validate_tag_ruleset_base(label, ruleset, errors)
    _expect(errors, f"{label} rule types", _rule_types(ruleset), ("deletion", "update"))
    _expect(errors, f"{label} bypass actors", _bypass_actors(ruleset), ())


def _validate_tag_ruleset_base(label: str, ruleset: JsonObject, errors: list[str]) -> None:
    _expect(errors, f"{label} target", ruleset.get("target"), "tag")
    _expect(errors, f"{label} enforcement", ruleset.get("enforcement"), "active")
    _expect(
        errors,
        f"{label} ref condition",
        _ref_condition(ruleset),
        (("refs/tags/v*",), ()),
    )


def _validate_orb_security(snapshot: GovernanceSnapshot, errors: list[str]) -> None:
    orb_repository = snapshot.repositories.get("vexcalibur-orb", {})
    _expect(
        errors,
        "vexcalibur-orb merge commits",
        orb_repository.get("allow_merge_commit"),
        False,
    )
    _expect(
        errors,
        "vexcalibur-orb automatic branch deletion",
        orb_repository.get("delete_branch_on_merge"),
        True,
    )
    security_and_analysis = _mapping_value(orb_repository, "security_and_analysis")
    required_features = (
        "dependabot_security_updates",
        "secret_scanning",
        "secret_scanning_push_protection",
    )
    for feature in required_features:
        settings = _mapping_value(security_and_analysis, feature)
        _expect(
            errors,
            f"vexcalibur-orb {feature}",
            settings.get("status"),
            "enabled",
        )
    _expect(
        errors,
        "vexcalibur-orb vulnerability alerts",
        snapshot.orb_vulnerability_alerts_enabled,
        True,
    )
    _expect(
        errors,
        "vexcalibur-orb automated security fixes",
        snapshot.orb_automated_security_fixes.get("enabled"),
        True,
    )
    _expect(
        errors,
        "vexcalibur-orb automated security fixes pause",
        snapshot.orb_automated_security_fixes.get("paused"),
        False,
    )
    _expect(
        errors,
        "vexcalibur-orb private vulnerability reporting",
        snapshot.orb_private_vulnerability_reporting.get("enabled"),
        True,
    )


def _validate_codeql_default_setups(snapshot: GovernanceSnapshot, errors: list[str]) -> None:
    for repository in DEFAULT_CODEQL_REPOSITORIES:
        setup = snapshot.codeql_default_setups.get(repository, {})
        label = f"{repository} CodeQL default setup"
        _expect(errors, f"{label} state", setup.get("state"), "configured")
        _expect(
            errors,
            f"{label} languages",
            _string_tuple(setup.get("languages")),
            CODEQL_LANGUAGES[repository],
        )
        _expect(errors, f"{label} query suite", setup.get("query_suite"), "extended")
        _expect(
            errors,
            f"{label} threat model",
            setup.get("threat_model"),
            "remote_and_local",
        )
        _expect(errors, f"{label} schedule", setup.get("schedule"), "weekly")


def _validate_pypi_environment(snapshot: GovernanceSnapshot, errors: list[str]) -> None:
    environment = snapshot.pypi_environment
    _expect(errors, "pypi environment name", environment.get("name"), "pypi")
    _expect(
        errors,
        "pypi environment administrator bypass",
        environment.get("can_admins_bypass"),
        True,
    )
    deployment_policy = _mapping_value(environment, "deployment_branch_policy")
    _expect(
        errors,
        "pypi environment protected-branch policy",
        deployment_policy.get("protected_branches"),
        False,
    )
    _expect(
        errors,
        "pypi environment custom deployment policies",
        deployment_policy.get("custom_branch_policies"),
        True,
    )
    protection_types = tuple(
        sorted(
            str(protection.get("type"))
            for protection in _mapping_sequence(environment.get("protection_rules"))
        )
    )
    _expect(errors, "pypi environment protection rules", protection_types, ("branch_policy",))

    branch_policies = snapshot.pypi_deployment_branch_policies
    normalized_policies = tuple(
        sorted(
            (
                (policy.get("name"), policy.get("type"))
                for policy in _mapping_sequence(branch_policies.get("branch_policies"))
            ),
            key=_stable,
        )
    )
    _expect(errors, "pypi deployment policies", normalized_policies, (("v*", "tag"),))
    _expect(errors, "pypi deployment policy count", branch_policies.get("total_count"), 1)


def _named_ruleset(
    rulesets: Sequence[JsonObject], name: str, repository: str, errors: list[str]
) -> JsonObject | None:
    matches = tuple(ruleset for ruleset in rulesets if ruleset.get("name") == name)
    if len(matches) != 1:
        errors.append(f"{repository} ruleset {name!r}: expected exactly one, got {len(matches)}")
        return None
    return matches[0]


def _rules(ruleset: JsonObject) -> tuple[tuple[str, JsonObject], ...]:
    normalized: list[tuple[str, JsonObject]] = []
    for rule in _mapping_sequence(ruleset.get("rules")):
        rule_type = rule.get("type")
        if not isinstance(rule_type, str):
            raise GovernanceReadError("ruleset rule omitted a string type")
        raw_parameters = rule.get("parameters")
        if raw_parameters is None:
            parameters: JsonObject = {}
        else:
            parameters = _require_mapping(raw_parameters, f"ruleset rule {rule_type!r} parameters")
        normalized.append((rule_type, parameters))
    return tuple(normalized)


def _single_rule_parameters(rules: Sequence[tuple[str, JsonObject]], rule_type: str) -> JsonObject:
    matches = tuple(parameters for actual_type, parameters in rules if actual_type == rule_type)
    return matches[0] if len(matches) == 1 else {}


def _rule_types(ruleset: JsonObject) -> tuple[str, ...]:
    return tuple(sorted(rule_type for rule_type, _ in _rules(ruleset)))


def _bypass_actors(ruleset: JsonObject) -> tuple[tuple[object, str, str], ...]:
    actors: list[tuple[object, str, str]] = []
    for actor in _mapping_sequence(ruleset.get("bypass_actors")):
        actor_type = actor.get("actor_type")
        bypass_mode = actor.get("bypass_mode")
        if not isinstance(actor_type, str) or not isinstance(bypass_mode, str):
            raise GovernanceReadError("ruleset bypass actor has a malformed type or mode")
        actor_id = actor.get("actor_id")
        if actor_id is not None and (not isinstance(actor_id, int) or isinstance(actor_id, bool)):
            raise GovernanceReadError("ruleset bypass actor has a malformed actor id")
        actors.append((actor_id, actor_type, bypass_mode))
    return tuple(sorted(actors, key=lambda item: (_stable(item[0]), item[1], item[2])))


def _ref_condition(ruleset: JsonObject) -> tuple[tuple[str, ...], tuple[str, ...]]:
    conditions = _mapping_value(ruleset, "conditions")
    ref_name = _mapping_value(conditions, "ref_name")
    return (_string_tuple(ref_name.get("include")), _string_tuple(ref_name.get("exclude")))


def _status_checks(parameters: JsonObject) -> tuple[tuple[str, object], ...]:
    checks: list[tuple[str, object]] = []
    for check in _mapping_sequence(parameters.get("required_status_checks")):
        context = check.get("context")
        integration_id = check.get("integration_id")
        if not isinstance(context, str):
            raise GovernanceReadError("required status check omitted a string context")
        if not isinstance(integration_id, int) or isinstance(integration_id, bool):
            raise GovernanceReadError("required status check omitted a numeric integration id")
        checks.append((context, integration_id))
    return tuple(sorted(checks, key=lambda item: (item[0], _stable(item[1]))))


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise GovernanceReadError("expected a JSON array of strings")
    if any(not isinstance(item, str) for item in value):
        raise GovernanceReadError("JSON string array contained a non-string item")
    return tuple(sorted(cast(str, item) for item in value))


def _mapping_sequence(value: object) -> tuple[JsonObject, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise GovernanceReadError("expected a JSON array of objects")
    if any(not isinstance(item, Mapping) for item in value):
        raise GovernanceReadError("JSON object array contained a non-object item")
    return tuple(cast(JsonObject, item) for item in value)


def _mapping_value(mapping: JsonObject, key: str) -> JsonObject:
    return _require_mapping(mapping.get(key), f"nested key {key!r}")


def _expect(errors: list[str], label: str, actual: object, expected: object) -> None:
    if _stable(actual) != _stable(expected):
        errors.append(f"{label}: expected {_stable(expected)}, got {_stable(actual)}")


def _stable(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _get_mapping(client: ApiClient, endpoint: str) -> JsonObject:
    return _require_mapping(client.get(endpoint), endpoint)


def _require_mapping(value: object, source: str) -> JsonObject:
    if not isinstance(value, Mapping):
        raise GovernanceReadError(f"expected a JSON object from {source}")
    return cast(JsonObject, value)


def _require_sequence(value: object, source: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise GovernanceReadError(f"expected a JSON array from {source}")
    return cast(Sequence[object], value)


def _snapshot_mapping(root: JsonObject, key: str, path: Path) -> JsonObject:
    return _require_mapping(root.get(key), f"{path}:{key}")


def _snapshot_bool(root: JsonObject, key: str, path: Path) -> bool:
    value = root.get(key)
    if not isinstance(value, bool):
        raise GovernanceReadError(f"expected a boolean at {path}:{key}")
    return value


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read and validate Vexcalibur's GitHub governance controls."
    )
    parser.add_argument(
        "--snapshot",
        type=Path,
        help="Validate a saved JSON snapshot instead of contacting GitHub.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the checker and return a process exit status."""
    args = _parse_args(argv)
    try:
        snapshot = (
            load_snapshot(args.snapshot) if args.snapshot else collect_snapshot(GhApiClient())
        )
        violations = validate_snapshot(snapshot)
    except GovernanceReadError as error:
        print(
            f"ERROR: governance check could not read every required setting: {error}",
            file=sys.stderr,
        )
        return 2

    if violations:
        print("GitHub governance drift detected:", file=sys.stderr)
        for violation in violations:
            print(f"- {violation}", file=sys.stderr)
        return 1

    print("GitHub governance matches the committed Vexcalibur policy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
