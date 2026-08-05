#!/usr/bin/env python3
"""Generate an execution report for custom Python source and renderer types."""

from datetime import datetime

from packageurl import PackageURL

from vexcalibur.api import (
    ComponentIdentity,
    ExecutionReportOutputFormat,
    FindingSourceCategory,
    GenerationExecutionContext,
    InventorySourceCategory,
    VulnerabilityFinding,
    generate_vex_from_components_result,
)


class CustomSource:
    def findings_for_components(
        self,
        components: tuple[ComponentIdentity, ...],
    ) -> tuple[VulnerabilityFinding, ...]:
        return ()


class CustomRenderer:
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
