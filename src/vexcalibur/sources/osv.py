"""OSV API client."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import quote

import httpx
from packageurl import PackageURL

DEFAULT_OSV_API_URL = "https://api.osv.dev"


@dataclass(frozen=True)
class OsvVulnerabilitySummary:
    """Minimal OSV vulnerability data returned by query endpoints."""

    id: str
    modified: str | None = None


@dataclass(frozen=True)
class OsvVulnerability:
    """Full OSV vulnerability payload.

    The OSV schema evolves over time. Keep the raw payload available so callers
    can consume fields before Vexcalibur promotes them into typed attributes.
    """

    id: str
    raw: dict[str, Any]


@dataclass(frozen=True)
class OsvQueryResult:
    """OSV query result associated with the submitted package URL."""

    purl: str
    vulnerabilities: tuple[OsvVulnerabilitySummary, ...]


class OsvClient:
    """Small client for OSV's public API."""

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_OSV_API_URL,
        timeout: float = 30.0,
        client: httpx.Client | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._client = client

    def query(self, purl: PackageURL) -> OsvQueryResult:
        """Query OSV for one package URL."""
        response = self._post(
            "/v1/query",
            {
                "package": {
                    "purl": purl.to_string(),
                }
            },
        )
        return OsvQueryResult(
            purl=purl.to_string(),
            vulnerabilities=_parse_vulnerability_summaries(response.get("vulns", [])),
        )

    def query_batch(self, purls: list[PackageURL]) -> list[OsvQueryResult]:
        """Query OSV for package URLs using the batch endpoint."""
        payload = {
            "queries": [
                {
                    "package": {
                        "purl": purl.to_string(),
                    }
                }
                for purl in purls
            ]
        }
        response = self._post("/v1/querybatch", payload)
        raw_results = response.get("results", [])
        if not isinstance(raw_results, list):
            msg = "OSV response field 'results' must be a list"
            raise TypeError(msg)

        return [
            OsvQueryResult(
                purl=purl.to_string(),
                vulnerabilities=_parse_vulnerability_summaries(
                    _get_optional_list_field(raw_result, "vulns")
                ),
            )
            for purl, raw_result in zip(purls, raw_results, strict=True)
        ]

    def get_vulnerability(self, vulnerability_id: str) -> OsvVulnerability:
        """Fetch a full OSV vulnerability by ID."""
        response = self._get(f"/v1/vulns/{quote(vulnerability_id, safe='')}")
        return OsvVulnerability(id=str(response["id"]), raw=response)

    def _get(self, path: str) -> dict[str, Any]:
        client = self._client
        if client is not None:
            response = client.get(f"{self._base_url}{path}", timeout=self._timeout)
            response.raise_for_status()
            return cast(dict[str, Any], response.json())

        with httpx.Client() as owned_client:
            response = owned_client.get(
                f"{self._base_url}{path}",
                timeout=self._timeout,
            )
            response.raise_for_status()
            return cast(dict[str, Any], response.json())

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        client = self._client
        if client is not None:
            response = client.post(f"{self._base_url}{path}", json=payload, timeout=self._timeout)
            response.raise_for_status()
            return cast(dict[str, Any], response.json())

        with httpx.Client() as owned_client:
            response = owned_client.post(
                f"{self._base_url}{path}",
                json=payload,
                timeout=self._timeout,
            )
            response.raise_for_status()
            return cast(dict[str, Any], response.json())


def _parse_vulnerability_summaries(raw_vulnerabilities: Any) -> tuple[OsvVulnerabilitySummary, ...]:
    if not isinstance(raw_vulnerabilities, list):
        msg = "OSV response field 'vulns' must be a list"
        raise TypeError(msg)

    parsed: list[OsvVulnerabilitySummary] = []
    for vuln in raw_vulnerabilities:
        if not isinstance(vuln, dict):
            msg = "OSV vulnerability entries must be objects"
            raise TypeError(msg)
        parsed.append(
            OsvVulnerabilitySummary(
                id=str(vuln["id"]),
                modified=cast(str | None, vuln.get("modified")),
            )
        )
    return tuple(parsed)


def _get_optional_list_field(raw_value: Any, field_name: str) -> list[Any]:
    if not isinstance(raw_value, dict):
        msg = "OSV query batch result entries must be objects"
        raise TypeError(msg)

    field_value = raw_value.get(field_name, [])
    if not isinstance(field_value, list):
        msg = f"OSV response field '{field_name}' must be a list"
        raise TypeError(msg)
    return field_value
