"""Shared helpers for GitHub release workflow contract tests."""

from __future__ import annotations

import re
import textwrap
from pathlib import Path

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
RELEASE_VALIDATION_WORKFLOW = ROOT / ".github" / "workflows" / "release-validation.yml"
PYPI_WORKFLOW = ROOT / ".github" / "workflows" / "pypi.yml"


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _job(text: str, name: str) -> str:
    pattern = rf"(?ms)^  {re.escape(name)}:\n.*?(?=^  [a-z0-9][a-z0-9-]*:\n|\Z)"
    matches = list(re.finditer(pattern, text))
    assert len(matches) == 1, f"release workflow must have exactly one {name!r} job"
    return matches[0].group(0)


def _step(job: str, name: str) -> str:
    pattern = rf"(?ms)^      - name: {re.escape(name)}\n.*?(?=^      - |\Z)"
    matches = list(re.finditer(pattern, job))
    assert len(matches) == 1, f"workflow job must have exactly one {name!r} step"
    return matches[0].group(0)


def _job_mapping(job: str) -> MappingNode:
    root = yaml.compose(textwrap.dedent(job), Loader=yaml.BaseLoader)
    assert isinstance(root, MappingNode) and len(root.value) == 1, (
        "workflow job scope must contain exactly one job"
    )
    job_node = root.value[0][1]
    assert isinstance(job_node, MappingNode), "workflow job must be a mapping"
    return job_node


def _job_condition(job: str) -> str:
    condition_nodes = [
        value
        for key, value in _job_mapping(job).value
        if isinstance(key, ScalarNode) and key.value == "if"
    ]
    assert len(condition_nodes) == 1 and isinstance(condition_nodes[0], ScalarNode), (
        "workflow job must contain exactly one scalar condition"
    )
    condition = condition_nodes[0].value
    assert isinstance(condition, str), "workflow job condition must be text"
    return condition


def _job_step_names(job: str) -> list[str]:
    step_nodes = [
        value
        for key, value in _job_mapping(job).value
        if isinstance(key, ScalarNode) and key.value == "steps"
    ]
    assert len(step_nodes) == 1 and isinstance(step_nodes[0], SequenceNode), (
        "workflow job must contain exactly one steps sequence"
    )

    names: list[str] = []
    for step_node in step_nodes[0].value:
        assert isinstance(step_node, MappingNode), "workflow step must be a mapping"
        name_nodes = [
            value
            for key, value in step_node.value
            if isinstance(key, ScalarNode) and key.value == "name"
        ]
        if not name_nodes:
            continue
        assert len(name_nodes) == 1 and isinstance(name_nodes[0], ScalarNode), (
            "workflow step must have one scalar name"
        )
        name = name_nodes[0].value
        assert name not in names, f"workflow job contains duplicate step name {name!r}"
        names.append(name)
    return names


def _step_script(step: str) -> str:
    marker = "        run: |\n"
    assert marker in step
    return textwrap.dedent(step.partition(marker)[2])


def _environment_entries(text: str, *, indentation: int) -> dict[str, str]:
    root = yaml.compose(text, Loader=yaml.BaseLoader)
    assert root is not None, "workflow scope is empty"
    scope = _scope_mapping(root, indentation=indentation)
    environment_nodes = [
        value for key, value in scope.value if isinstance(key, ScalarNode) and key.value == "env"
    ]
    if not environment_nodes:
        return {}
    assert len(environment_nodes) == 1, "workflow scope contains duplicate environment mappings"
    environment = environment_nodes[0]
    assert isinstance(environment, MappingNode), (
        "workflow environment must be a block or flow mapping"
    )

    entries: dict[str, str] = {}
    for key, value in environment.value:
        assert isinstance(key, ScalarNode) and re.fullmatch(r"[A-Z][A-Z0-9_]*", key.value), (
            "workflow environment key is unsupported"
        )
        assert key.value not in entries, "workflow environment contains a duplicate key"
        assert isinstance(value, ScalarNode), "nested workflow environment values are unsupported"
        assert value.style not in {"|", ">"}, "workflow environment block scalars are unsupported"
        assert value.value, "empty workflow environment values are unsupported"
        entries[key.value] = value.value
    return entries


def _scope_mapping(root: Node, *, indentation: int) -> MappingNode:
    if indentation == 0:
        assert isinstance(root, MappingNode), "workflow root must be a mapping"
        return root
    if indentation == 4:
        assert isinstance(root, MappingNode) and len(root.value) == 1, (
            "workflow job scope must contain exactly one job"
        )
        job = root.value[0][1]
        assert isinstance(job, MappingNode), "workflow job must be a mapping"
        return job
    assert indentation == 8, "unsupported workflow scope indentation"
    assert isinstance(root, SequenceNode) and len(root.value) == 1, (
        "workflow step scope must contain exactly one step"
    )
    step = root.value[0]
    assert isinstance(step, MappingNode), "workflow step must be a mapping"
    return step


def _step_environment(step: str) -> dict[str, str]:
    return _environment_entries(step, indentation=8)


def _job_environment(job: str) -> dict[str, str]:
    return _environment_entries(job, indentation=4)


def _workflow_environment(workflow: str) -> dict[str, str]:
    return _environment_entries(workflow, indentation=0)


def _workflow_job_dependencies(text: str) -> dict[str, set[str]]:
    jobs_text = text.partition("\njobs:\n")[2]
    job_names = re.findall(r"(?m)^  ([a-z][a-z0-9-]*):\n", jobs_text)
    dependencies: dict[str, set[str]] = {}
    for job_name in job_names:
        job = _job(jobs_text, job_name)
        inline = re.search(r"(?m)^    needs: \[([^\]]+)\]$", job)
        scalar = re.search(r"(?m)^    needs: ([a-z][a-z0-9-]*)$", job)
        block = re.search(
            r"(?ms)^    needs:\n((?:      - [a-z][a-z0-9-]*\n)+)",
            job,
        )
        if inline is not None:
            dependencies[job_name] = {value.strip() for value in inline.group(1).split(",")}
        elif scalar is not None:
            dependencies[job_name] = {scalar.group(1)}
        elif block is not None:
            dependencies[job_name] = set(
                re.findall(r"(?m)^      - ([a-z][a-z0-9-]*)$", block.group(1))
            )
        else:
            dependencies[job_name] = set()
    return dependencies


def _has_job_ancestor(
    dependencies: dict[str, set[str]],
    *,
    job_name: str,
    ancestor: str,
) -> bool:
    pending = list(dependencies[job_name])
    visited: set[str] = set()
    while pending:
        dependency = pending.pop()
        if dependency == ancestor:
            return True
        if dependency in visited:
            continue
        visited.add(dependency)
        pending.extend(dependencies.get(dependency, ()))
    return False


def _validation_text() -> str:
    return RELEASE_VALIDATION_WORKFLOW.read_text(encoding="utf-8")


def _pypi_text() -> str:
    return PYPI_WORKFLOW.read_text(encoding="utf-8")


def _workflow_call_outputs(text: str) -> set[str]:
    start = text.index("    outputs:\n")
    end = text.index("\npermissions:\n", start)
    return set(re.findall(r"(?m)^      ([a-z][a-z0-9-]*):\n", text[start:end]))
