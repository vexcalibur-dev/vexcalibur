"""Assert the CSAF contract against output from an installed wheel."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from importlib.metadata import version as distribution_version
from pathlib import Path
from typing import Any

EXPECTED_STATE_AND_STATUS = {
    "CVE-2026-0001": ("resolved", "fixed"),
    "CVE-2026-0002": ("exploitable", "known_affected"),
    "CVE-2026-0003": ("in_triage", "under_investigation"),
    "CVE-2026-0004": ("false_positive", "known_not_affected"),
    "CVE-2026-0005": ("not_affected", "known_not_affected"),
}


def main() -> None:
    """Check metadata, state mappings, and required evidence."""
    if len(sys.argv) != 3:
        print("usage: check_installed_csaf.py DOCUMENT REPORT", file=sys.stderr)
        raise SystemExit(2)

    document_path = Path(sys.argv[1])
    report_path = Path(sys.argv[2])
    _assert_expected_python()
    _require(document_path.name == "acme-vex-2026-001.json", "CSAF filename is incorrect")
    document_bytes = document_path.read_bytes()
    document = json.loads(document_bytes)
    _assert_execution_report(report_path=report_path, document_bytes=document_bytes)

    _require("$schema" not in document, "CSAF output must not contain root $schema")
    _require(document["document"]["category"] == "csaf_vex", "CSAF category is incorrect")
    _require(document["document"]["csaf_version"] == "2.0", "CSAF version is incorrect")

    engine = document["document"]["tracking"]["generator"]["engine"]
    _require(engine["name"] == "Vexcalibur", "CSAF generator engine name is incorrect")
    _require(
        engine["version"] == distribution_version("vexcalibur"),
        "CSAF generator engine version does not match the installed distribution",
    )

    products = {
        product["product_id"]: product for product in document["product_tree"]["full_product_names"]
    }
    vulnerabilities = {item["cve"]: item for item in document["vulnerabilities"]}
    _require(
        set(vulnerabilities) == set(EXPECTED_STATE_AND_STATUS),
        "CSAF output does not contain exactly the five fixture vulnerabilities",
    )

    for cve, (state, status) in EXPECTED_STATE_AND_STATUS.items():
        vulnerability = vulnerabilities[cve]
        product_status = vulnerability["product_status"]
        _require(
            set(product_status) == {status},
            f"{cve} did not map exclusively to CSAF status {status}",
        )
        product_ids = set(product_status[status])
        _require(product_ids, f"{cve} CSAF status has no products")
        _require(product_ids <= products.keys(), f"{cve} references an unknown product")

        notes = "\n".join(note["text"] for note in vulnerability["notes"])
        _require(
            f"Original Vexcalibur analysis state: {state}" in notes,
            f"{cve} notes do not preserve original state {state}",
        )

        if status == "known_affected":
            _assert_affected_evidence(vulnerability, product_ids=product_ids, cve=cve)
        elif status == "known_not_affected":
            _assert_not_affected_evidence(vulnerability, product_ids=product_ids, cve=cve)
        elif status == "fixed":
            _assert_fixed_evidence(products, product_ids=product_ids, notes=notes, cve=cve)


def _assert_expected_python() -> None:
    expected = os.environ.get("VEXCALIBUR_EXPECTED_PYTHON")
    if expected is None:
        return
    try:
        expected_info = tuple(int(value) for value in expected.split("."))
    except ValueError:
        _require(False, f"Expected Python version is invalid: {expected!r}")
        return
    _require(len(expected_info) == 2, f"Expected Python version is invalid: {expected!r}")
    actual_info = sys.version_info[:2]
    _require(
        actual_info == expected_info,
        f"Installed checks used Python {actual_info[0]}.{actual_info[1]} instead of {expected}",
    )


def _assert_execution_report(*, report_path: Path, document_bytes: bytes) -> None:
    report_bytes = report_path.read_bytes()
    report = json.loads(report_bytes)
    expected = {
        "schema_version": 1,
        "command": "generate",
        "vexcalibur_version": distribution_version("vexcalibur"),
        "inventory_source": "sbom_file",
        "finding_source": "local_file",
        "output_format": "csaf",
        "component_count": 2,
        "finding_count": 5,
        "analysis_state_counts": {
            "resolved": 1,
            "exploitable": 1,
            "in_triage": 1,
            "false_positive": 1,
            "not_affected": 1,
        },
        "document": {
            "sha256": hashlib.sha256(document_bytes).hexdigest(),
            "bytes": len(document_bytes),
        },
    }
    _require(report == expected, "CSAF execution report does not match the generated document")
    canonical = (
        json.dumps(expected, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("ascii")
    _require(report_bytes == canonical, "CSAF execution report is not canonical JSON")


def _assert_affected_evidence(
    vulnerability: dict[str, Any], *, product_ids: set[str], cve: str
) -> None:
    remediations = vulnerability.get("remediations", [])
    matching = [
        remediation
        for remediation in remediations
        if remediation.get("category") == "vendor_fix"
        and remediation.get("details") == "Upgrade minimist to version 1.2.8 or later."
        and set(remediation.get("product_ids", [])) == product_ids
    ]
    _require(len(matching) == 1, f"{cve} lacks product-scoped vendor_fix evidence")


def _assert_not_affected_evidence(
    vulnerability: dict[str, Any], *, product_ids: set[str], cve: str
) -> None:
    matching = [
        threat
        for threat in vulnerability.get("threats", [])
        if threat.get("category") == "impact"
        and isinstance(threat.get("details"), str)
        and threat["details"].strip()
        and set(threat.get("product_ids", [])) == product_ids
    ]
    _require(len(matching) == 1, f"{cve} lacks product-scoped impact evidence")


def _assert_fixed_evidence(
    products: dict[str, dict[str, Any]], *, product_ids: set[str], notes: str, cve: str
) -> None:
    _require(len(product_ids) == 1, f"{cve} fixed status does not identify one product")
    product = products[next(iter(product_ids))]
    purl = product["product_identification_helper"]["purl"]
    _require(purl.endswith("@1.2"), f"{cve} fixed product does not use version 1.2")
    _require(
        "Confirmed fixed product version: 1.2" in notes,
        f"{cve} notes do not preserve fixed-version evidence",
    )


def _require(condition: bool, message: str) -> None:
    if condition:
        return
    print(message, file=sys.stderr)
    raise SystemExit(1)


if __name__ == "__main__":
    main()
