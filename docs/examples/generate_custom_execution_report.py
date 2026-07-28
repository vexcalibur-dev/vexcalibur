#!/usr/bin/env python3
"""Generate an execution report for custom Python source and renderer types."""

from datetime import datetime
from typing import Literal

from packageurl import PackageURL

from vexcalibur.domain import ComponentIdentity, VulnerabilityFinding
from vexcalibur.generate import generate_vex_from_components_result
from vexcalibur.generation_result import (
    ExecutionReportFindingSourceDeclaration,
    ExecutionReportOutputFormat,
    ExecutionReportOutputFormatDeclaration,
    FindingSourceCategory,
    GenerationExecutionContext,
    InventorySourceCategory,
)


class CustomSource(ExecutionReportFindingSourceDeclaration):
    def execution_report_finding_source(
        self,
    ) -> Literal[FindingSourceCategory.CUSTOM]:
        return FindingSourceCategory.CUSTOM

    def findings_for_components(
        self,
        components: tuple[ComponentIdentity, ...],
    ) -> tuple[VulnerabilityFinding, ...]:
        return ()


class CustomRenderer(ExecutionReportOutputFormatDeclaration):
    def execution_report_output_format(
        self,
    ) -> Literal[ExecutionReportOutputFormat.CUSTOM]:
        return ExecutionReportOutputFormat.CUSTOM

    def render(
        self,
        *,
        components: tuple[ComponentIdentity, ...],
        findings: tuple[VulnerabilityFinding, ...],
        timestamp: datetime | None = None,
    ) -> str:
        return '{"format":"example","findings":[]}\n'


def main() -> None:
    component = ComponentIdentity(
        ref="component:demo",
        name="demo",
        version="1.0.0",
        purl=PackageURL.from_string("pkg:pypi/demo@1.0.0"),
    )
    context = GenerationExecutionContext(
        inventory_source=InventorySourceCategory.CUSTOM,
        finding_source=FindingSourceCategory.CUSTOM,
        output_format=ExecutionReportOutputFormat.CUSTOM,
    )
    result = generate_vex_from_components_result(
        components=(component,),
        source=CustomSource(),
        timestamp=None,
        renderer=CustomRenderer(),
        execution_context=context,
    )
    print(result.execution_report().to_json(), end="")


if __name__ == "__main__":
    main()
