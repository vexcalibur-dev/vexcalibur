from __future__ import annotations

import ast
import json
import shutil
import subprocess
from pathlib import Path, PurePosixPath

import pytest
import scripts.check_coverage_policy as coverage_policy

ROOT = Path(__file__).parents[1]
EXPECTED_CRITICAL_FLOORS = {
    PurePosixPath("src/vexcalibur/generation_result.py"): 88.0,
    PurePosixPath("src/vexcalibur/execution_report_validation.py"): 75.0,
    PurePosixPath("src/vexcalibur/generation_output.py"): 90.0,
    PurePosixPath("src/vexcalibur/execution_report_destination.py"): 88.0,
    PurePosixPath("src/vexcalibur/execution_report_filesystem.py"): 80.0,
    PurePosixPath("src/vexcalibur/execution_report_lifecycle.py"): 95.0,
    PurePosixPath("src/vexcalibur/execution_report_locks.py"): 85.0,
    PurePosixPath("src/vexcalibur/execution_report_staging.py"): 82.0,
    PurePosixPath("src/vexcalibur/github_sbom.py"): 75.0,
    PurePosixPath("scripts/archive_limits.py"): 85.0,
    PurePosixPath("scripts/check_coverage_policy.py"): 90.0,
    PurePosixPath("scripts/execution_report_oracle.py"): 74.0,
    PurePosixPath("scripts/release_evidence.py"): 65.0,
}


@pytest.fixture(autouse=True)
def _clear_coverage_policy_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("COVERAGE_COMPARE_REF", raising=False)
    monkeypatch.delenv("COVERAGE_TARGET_REF", raising=False)


def _git(repository: Path, *arguments: str) -> str:
    git = shutil.which("git")
    assert git is not None
    completed = subprocess.run(  # noqa: S603 - fixed executable and test-owned arguments.
        [git, *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def test_critical_coverage_contract_is_explicit() -> None:
    assert coverage_policy.CRITICAL_FLOORS == EXPECTED_CRITICAL_FLOORS


def test_critical_scripts_cannot_hide_code_in_unmonitored_helpers() -> None:
    critical_modules = {
        f"scripts.{path.stem}"
        for path in EXPECTED_CRITICAL_FLOORS
        if PurePosixPath("scripts") in path.parents
    }
    script_modules = {
        f"scripts.{path.stem}" for path in (ROOT / "scripts").glob("*.py") if "-" not in path.stem
    }
    for module in critical_modules:
        source = ROOT / f"{module.replace('.', '/')}.py"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    candidate = f"scripts.{alias.name}"
                    imported.add(candidate if candidate in script_modules else alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module == "scripts":
                imported.update(f"scripts.{alias.name}" for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported.add(node.module)
        assert imported & script_modules <= critical_modules


def _file_coverage(
    *,
    executed: list[int] | None = None,
    missing: list[int] | None = None,
    missing_branches: list[list[int]] | None = None,
    excluded: list[int] | None = None,
    percentage: float = 100.0,
) -> dict[str, object]:
    return {
        "executed_lines": [1] if executed is None else executed,
        "missing_lines": [] if missing is None else missing,
        "excluded_lines": [] if excluded is None else excluded,
        "missing_branches": [] if missing_branches is None else missing_branches,
        "summary": {"percent_covered": percentage},
    }


def _coverage_document(
    *,
    aggregate: float = 100.0,
    extra_files: dict[str, dict[str, object]] | None = None,
) -> dict[str, object]:
    files = {str(path): _file_coverage() for path in coverage_policy.CRITICAL_FLOORS}
    files.update(extra_files or {})
    return {
        "meta": {"branch_coverage": True},
        "files": files,
        "totals": {"percent_covered": aggregate},
    }


def _write_coverage_report(
    path: Path,
    *,
    aggregate: float = 100.0,
    extra_files: dict[str, dict[str, object]] | None = None,
) -> None:
    path.write_text(
        json.dumps(_coverage_document(aggregate=aggregate, extra_files=extra_files)),
        encoding="utf-8",
    )


def test_load_coverage_report_preserves_line_and_branch_state(tmp_path: Path) -> None:
    report_path = tmp_path / "coverage.json"
    example = "src/vexcalibur/example.py"
    _write_coverage_report(
        report_path,
        aggregate=87.5,
        extra_files={
            example: _file_coverage(
                executed=[5, 7, 8],
                missing=[6],
                missing_branches=[[7, 9]],
                excluded=[9],
                percentage=72.5,
            )
        },
    )

    report = coverage_policy.load_coverage_report(report_path)
    file_coverage = report.files[PurePosixPath(example)]

    assert report.aggregate_percentage == 87.5
    assert file_coverage.covers(4) is None
    assert file_coverage.covers(5) is True
    assert file_coverage.covers(6) is False
    assert file_coverage.covers(7) is False
    assert file_coverage.covers(8) is True
    assert file_coverage.covers(9) is None
    assert file_coverage.percentage == 72.5


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        (lambda document: document["meta"].update(branch_coverage=False), "branch coverage"),
        (lambda document: document.update(totals={"percent_covered": float("nan")}), "between"),
        (lambda document: document.update(files=[]), "files must be an object"),
    ],
)
def test_load_coverage_report_rejects_malformed_evidence(
    tmp_path: Path,
    mutation: object,
    error: str,
) -> None:
    report_path = tmp_path / "coverage.json"
    document = _coverage_document()
    assert callable(mutation)
    mutation(document)
    report_path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(coverage_policy.CoveragePolicyError, match=error):
        coverage_policy.load_coverage_report(report_path)


def test_coverage_evidence_validators_fail_closed() -> None:
    with pytest.raises(coverage_policy.CoveragePolicyError, match="must be a percentage"):
        coverage_policy._require_percentage(True, field="percentage")
    with pytest.raises(coverage_policy.CoveragePolicyError, match="positive line numbers"):
        coverage_policy._require_lines([0], field="lines")
    with pytest.raises(coverage_policy.CoveragePolicyError, match="must not repeat"):
        coverage_policy._require_lines([1, 1], field="lines")
    with pytest.raises(coverage_policy.CoveragePolicyError, match="must be a list"):
        coverage_policy._require_branch_origins({}, field="branches")
    with pytest.raises(coverage_policy.CoveragePolicyError, match="branch line pairs"):
        coverage_policy._require_branch_origins([[0, 1]], field="branches")
    with pytest.raises(coverage_policy.CoveragePolicyError, match="unsafe path"):
        coverage_policy._normalized_path("../outside.py")

    assert coverage_policy._normalized_path(
        r"src\vexcalibur\module.py", windows_separators=True
    ) == PurePosixPath("src/vexcalibur/module.py")


def test_load_coverage_report_rejects_duplicate_and_contradictory_files(tmp_path: Path) -> None:
    report_path = tmp_path / "coverage.json"
    document = _coverage_document(
        extra_files={
            "module.py": _file_coverage(),
            "./module.py": _file_coverage(),
        }
    )
    report_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(coverage_policy.CoveragePolicyError, match=r"repeats module\.py"):
        coverage_policy.load_coverage_report(report_path)

    document = _coverage_document(
        extra_files={"module.py": _file_coverage(executed=[1], missing=[1])}
    )
    report_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(coverage_policy.CoveragePolicyError, match="contradicts itself"):
        coverage_policy.load_coverage_report(report_path)


def test_parse_changed_lines_supports_single_zero_and_multiple_line_hunks() -> None:
    patch = """@@ -4 +5 @@ context
@@ -9,2 +10,0 @@ deleted
@@ -20 +21,3 @@ added
"""

    assert coverage_policy.parse_changed_lines(patch) == frozenset({5, 21, 22, 23})


def test_evaluate_changed_coverage_ignores_non_executable_lines() -> None:
    path = PurePosixPath("src/vexcalibur/example.py")
    report = coverage_policy.CoverageReport(
        files={
            path: coverage_policy.FileCoverage(
                executed_lines=frozenset({5, 7}),
                missing_lines=frozenset({6}),
                excluded_lines=frozenset({9}),
                missing_branch_origins=frozenset({7}),
                percentage=50.0,
            )
        },
        aggregate_percentage=50.0,
    )

    result = coverage_policy.evaluate_changed_coverage(
        report, ((path, frozenset({4, 5, 6, 7, 9})),)
    )

    assert result.covered == 1
    assert result.measured == 3
    assert result.percentage == pytest.approx(100 / 3)
    assert result.uncovered == ((path, 6), (path, 7))
    assert result.missing_files == ()


def test_evaluate_changed_coverage_fails_closed_for_unmeasured_source_file() -> None:
    path = PurePosixPath("src/vexcalibur/new_module.py")
    report = coverage_policy.CoverageReport(files={}, aggregate_percentage=100.0)

    result = coverage_policy.evaluate_changed_coverage(report, ((path, frozenset({1, 2})),))

    assert result.percentage == 100.0
    assert result.missing_files == (path,)


def test_git_comparison_includes_tracked_and_untracked_monitored_lines(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    source = repository / "src" / "vexcalibur"
    source.mkdir(parents=True)
    tracked = source / "example.py"
    tracked.write_text("value = 1\nresult = value + 1\n")
    _git(repository, "init", "--initial-branch=main")
    _git(repository, "config", "user.name", "Coverage Test")
    _git(repository, "config", "user.email", "coverage@example.test")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "test: establish baseline")
    base = _git(repository, "rev-parse", "HEAD")

    tracked.write_text("value = 2\nresult = value + 1\nresult += 1\n")
    untracked = source / "new_module.py"
    untracked.write_text("first = 1\nsecond = 2\n")
    monkeypatch.chdir(repository)
    git = shutil.which("git")
    assert git is not None

    assert coverage_policy.changed_files(git, repository, base) == (
        coverage_policy.ChangedPath(PurePosixPath("src/vexcalibur/example.py")),
        coverage_policy.ChangedPath(PurePosixPath("src/vexcalibur/new_module.py")),
    )
    assert coverage_policy.changed_lines_for_file(
        git,
        repository,
        base,
        coverage_policy.ChangedPath(PurePosixPath("src/vexcalibur/example.py")),
    ) == frozenset({1, 3})
    assert coverage_policy.changed_lines_for_file(
        git,
        repository,
        base,
        coverage_policy.ChangedPath(PurePosixPath("src/vexcalibur/new_module.py")),
    ) == frozenset({1, 2})


def test_git_comparison_uses_exact_target_and_ignores_diff_attributes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    source = repository / "src" / "vexcalibur"
    source.mkdir(parents=True)
    module = source / "example.py"
    module.write_text("value = 1\nresult = value + 1\n")
    _git(repository, "init", "--initial-branch=main")
    _git(repository, "config", "user.name", "Coverage Test")
    _git(repository, "config", "user.email", "coverage@example.test")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "test: establish baseline")
    base = _git(repository, "rev-parse", "HEAD")

    (repository / ".gitattributes").write_text("*.py -diff\n")
    module.write_text("value = 2\nresult = value + 1\n")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "test: modify attributed source")
    target = _git(repository, "rev-parse", "HEAD")
    monkeypatch.chdir(source)
    git = shutil.which("git")
    assert git is not None
    root = coverage_policy.repository_root(git)

    assert root == repository.resolve()
    assert coverage_policy.changed_files(git, root, base, target) == (
        coverage_policy.ChangedPath(PurePosixPath("src/vexcalibur/example.py")),
    )
    assert coverage_policy.changed_lines_for_file(
        git,
        root,
        base,
        coverage_policy.ChangedPath(PurePosixPath("src/vexcalibur/example.py")),
        target,
    ) == frozenset({1})


def test_git_comparison_does_not_score_an_unchanged_rename(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    source = repository / "src" / "vexcalibur"
    source.mkdir(parents=True)
    original = source / "old.py"
    original.write_text("value = 1\n")
    _git(repository, "init", "--initial-branch=main")
    _git(repository, "config", "user.name", "Coverage Test")
    _git(repository, "config", "user.email", "coverage@example.test")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "test: establish baseline")
    base = _git(repository, "rev-parse", "HEAD")
    _git(repository, "mv", "src/vexcalibur/old.py", "src/vexcalibur/new.py")
    _git(repository, "commit", "-m", "test: rename source")
    target = _git(repository, "rev-parse", "HEAD")
    git = shutil.which("git")
    assert git is not None
    change = coverage_policy.ChangedPath(
        path=PurePosixPath("src/vexcalibur/new.py"),
        source_path=PurePosixPath("src/vexcalibur/old.py"),
    )

    assert coverage_policy.changed_files(git, repository, base, target) == (change,)
    assert (
        coverage_policy.changed_lines_for_file(git, repository, base, change, target) == frozenset()
    )


def test_git_paths_do_not_treat_backslash_as_a_separator() -> None:
    assert coverage_policy._decode_git_path(b"src/vexcalibur/back\\slash.py") == (
        PurePosixPath("src/vexcalibur/back\\slash.py")
    )


def test_repository_root_preserves_legal_trailing_space(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repository "
    monkeypatch.setattr(
        coverage_policy,
        "_run_git",
        lambda *_args, **_kwargs: f"{root}\n".encode(),
    )

    assert coverage_policy.repository_root("git") == root


@pytest.mark.parametrize(
    "payload",
    [b"\0", b"R100\0src/vexcalibur/old.py\0", b"M\0"],
)
def test_changed_files_rejects_malformed_git_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> None:
    monkeypatch.setattr(coverage_policy, "_run_git", lambda *_args, **_kwargs: payload)

    with pytest.raises(coverage_policy.CoveragePolicyError, match="Git reported"):
        coverage_policy.changed_files("git", tmp_path, "base", "target")


def test_git_failures_and_non_utf8_paths_are_reported(tmp_path: Path) -> None:
    git = shutil.which("git")
    assert git is not None
    with pytest.raises(coverage_policy.CoveragePolicyError, match="Git comparison failed"):
        coverage_policy._run_git(git, ("rev-parse", "--verify", "missing"), repository=tmp_path)
    with pytest.raises(coverage_policy.CoveragePolicyError, match="non-UTF-8 source path"):
        coverage_policy._decode_git_path(b"\xff")


def test_main_enforces_aggregate_and_critical_floors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report_path = tmp_path / "coverage.json"
    _write_coverage_report(report_path, aggregate=74.9)

    assert coverage_policy.main((str(report_path),)) == 1
    assert "Aggregate branch coverage: 74.90% (required 75.00%)" in capsys.readouterr().out

    document = _coverage_document()
    critical = next(iter(coverage_policy.CRITICAL_FLOORS))
    document["files"][str(critical)] = _file_coverage(percentage=0.0)
    report_path.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setitem(coverage_policy.CRITICAL_FLOORS, critical, 1.0)
    assert coverage_policy.main((str(report_path),)) == 1
    assert f"{critical}: 0.00% (required 1.00%)" in capsys.readouterr().out

    document["files"].pop(str(critical))
    report_path.write_text(json.dumps(document), encoding="utf-8")
    assert coverage_policy.main((str(report_path),)) == 1
    assert f"{critical}: missing coverage entry" in capsys.readouterr().out


def test_main_reports_invalid_evidence_and_compare_ref(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report_path = tmp_path / "coverage.json"
    report_path.write_text("not JSON", encoding="utf-8")

    assert coverage_policy.main((str(report_path),)) == 2
    assert "Coverage policy failed: could not read" in capsys.readouterr().err
    assert coverage_policy.main((str(report_path), "--compare-ref=-invalid")) == 2
    assert "--compare-ref must be" in capsys.readouterr().err
    assert coverage_policy.main((str(report_path), "--target-ref=HEAD")) == 2
    assert "--target-ref requires" in capsys.readouterr().err


def test_parser_reads_git_revisions_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COVERAGE_COMPARE_REF", "base")
    monkeypatch.setenv("COVERAGE_TARGET_REF", "target")

    args = coverage_policy._parser().parse_args(("coverage.json",))

    assert args.compare_ref == "base"
    assert args.target_ref == "target"


def test_main_reports_uncovered_changed_lines_and_exit_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository = tmp_path / "repository"
    source = repository / "src" / "vexcalibur"
    source.mkdir(parents=True)
    module = source / "example.py"
    module.write_text("value = 1\n")
    _git(repository, "init", "--initial-branch=main")
    _git(repository, "config", "user.name", "Coverage Test")
    _git(repository, "config", "user.email", "coverage@example.test")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "test: establish baseline")
    base = _git(repository, "rev-parse", "HEAD")
    module.write_text("value = 2\n")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "test: change source")
    target = _git(repository, "rev-parse", "HEAD")
    report_path = repository / "coverage.json"
    _write_coverage_report(
        report_path,
        extra_files={"src/vexcalibur/example.py": _file_coverage(executed=[], missing=[1])},
    )
    monkeypatch.chdir(repository)

    assert (
        coverage_policy.main((str(report_path), f"--compare-ref={base}", f"--target-ref={target}"))
        == 1
    )
    output = capsys.readouterr().out
    assert "Uncovered changed lines: src/vexcalibur/example.py:1" in output
    assert "Changed-line branch coverage: 0.00% (0/1); required 90.00%" in output


def test_main_reports_missing_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report_path = tmp_path / "coverage.json"
    _write_coverage_report(report_path)
    monkeypatch.setattr(coverage_policy.shutil, "which", lambda _name: None)

    assert coverage_policy.main((str(report_path), "--compare-ref=HEAD")) == 2
    assert "git is required" in capsys.readouterr().err


def test_line_ranges_compacts_adjacent_lines() -> None:
    assert coverage_policy._line_ranges([5, 2, 3, 5, 8]) == "2-3, 5, 8"


def test_pull_request_ci_runs_complete_policy_against_exact_base() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "github.event.pull_request.base.sha" in workflow
    assert "COVERAGE_TARGET_REF:" in workflow
    assert "github.sha" in workflow
    assert "run: make coverage-policy" in workflow
    assert 'pytest -m "not live and not fuzz" --cov-fail-under=75' in workflow

    release_workflow = (ROOT / ".github" / "workflows" / "release-validation.yml").read_text(
        encoding="utf-8"
    )
    assert "run: make coverage-policy" in release_workflow
    assert 'COVERAGE_COMPARE_REF: ""' in release_workflow


def test_contributor_docs_give_reproducible_coverage_command() -> None:
    documentation = (ROOT / "docs" / "contributing" / "ci.md").read_text(encoding="utf-8")

    assert "make coverage COVERAGE_COMPARE_REF=origin/main" in documentation
    assert "The changed-line floor is 90%." in documentation
    assert "it doesn't upload coverage" in documentation
    assert "or call an external service" in documentation


def test_production_coverage_cannot_be_suppressed_with_pragma() -> None:
    configuration = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert '"pragma: no cover"' not in configuration
    assert '"# coverage: platform-only"' in configuration
