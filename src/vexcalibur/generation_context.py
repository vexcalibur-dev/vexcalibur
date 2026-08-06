"""Execution-report provenance retained during VEX generation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class InventorySourceCategory(str, Enum):
    """Identifier-free categories for the component inventory source."""

    SBOM_FILE = "sbom_file"
    GITHUB_DEPENDENCY_GRAPH = "github_dependency_graph"
    CUSTOM = "custom"


class FindingSourceCategory(str, Enum):
    """Identifier-free categories for the vulnerability finding source."""

    LOCAL_FILE = "local_file"
    PUBLIC_OSV = "public_osv"
    CUSTOM_OSV = "custom_osv"
    CUSTOM = "custom"


class ExecutionReportOutputFormat(str, Enum):
    """Identifier-free categories for the generated document format."""

    CYCLONEDX = "cyclonedx"
    OPENVEX = "openvex"
    CSAF = "csaf"
    CUSTOM = "custom"


@dataclass(frozen=True)
class GenerationExecutionContext:
    """Source and renderer facts retained by one generation operation.

    Args:
        inventory_source: Category for the component inventory.
        finding_source: Category for vulnerability findings.
        output_format: Category for the rendered VEX document.

    Raises:
        TypeError: Any category is not a member of its declared enum.
    """

    inventory_source: InventorySourceCategory
    finding_source: FindingSourceCategory
    output_format: ExecutionReportOutputFormat

    def __post_init__(self) -> None:
        if not isinstance(self.inventory_source, InventorySourceCategory):
            raise TypeError("inventory_source must be an InventorySourceCategory")
        if not isinstance(self.finding_source, FindingSourceCategory):
            raise TypeError("finding_source must be a FindingSourceCategory")
        if not isinstance(self.output_format, ExecutionReportOutputFormat):
            raise TypeError("output_format must be an ExecutionReportOutputFormat")
