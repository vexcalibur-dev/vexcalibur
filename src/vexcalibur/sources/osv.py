"""OSV API client."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlparse

import httpx
from packageurl import PackageURL

from vexcalibur.domain import ComponentIdentity, VulnerabilityFinding

DEFAULT_OSV_API_URL = "https://api.osv.dev"
DEFAULT_MAX_OSV_PAGES = 100
PUBLIC_OSV_API_HOST = "api.osv.dev"
OSV_SOURCE_NAME = "OSV"
OSV_SOURCE_URL = "https://osv.dev/"


@dataclass(frozen=True)
class OsvVulnerabilitySummary:
    """Minimal OSV vulnerability data returned by query endpoints."""

    id: str
    modified: datetime | None = None


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
    version: str | None = None


@dataclass(frozen=True)
class OsvPackageQuery:
    """OSV package query with optional top-level version fallback."""

    purl: PackageURL
    version: str | None = None


class OsvClientError(RuntimeError):
    """Base error raised for OSV client failures."""


class OsvResponseError(OsvClientError):
    """Raised when OSV returns a response that does not match the expected API shape."""


class OsvConfigurationError(OsvClientError, ValueError):
    """Raised when OSV source configuration is unsafe or invalid."""


@dataclass(frozen=True)
class _BatchPageResult:
    vulnerabilities: tuple[OsvVulnerabilitySummary, ...]
    next_page_token: str | None


class OsvClient:
    """Small client for OSV's public API."""

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_OSV_API_URL,
        timeout: float = 30.0,
        max_pages: int = DEFAULT_MAX_OSV_PAGES,
        client: httpx.Client | None = None,
    ) -> None:
        if max_pages < 1:
            msg = "max_pages must be at least 1"
            raise ValueError(msg)
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._max_pages = max_pages
        self._client = client

    @property
    def base_url(self) -> str:
        """Base URL used for OSV API requests."""
        return self._base_url

    def query(self, purl: PackageURL, *, version: str | None = None) -> OsvQueryResult:
        """Query OSV for one package URL."""
        query = OsvPackageQuery(purl=purl, version=version)
        raw_vulnerabilities: list[Any] = []
        page_token: str | None = None
        seen_page_tokens: set[str] = set()

        for _ in range(self._max_pages):
            response = self._post("/v1/query", _query_payload(query, page_token=page_token))
            raw_vulnerabilities.extend(_get_optional_list_field(response, "vulns"))

            page_token = _get_optional_string_field(response, "next_page_token")
            if page_token is None:
                break
            if page_token in seen_page_tokens:
                msg = "OSV query response repeated next_page_token"
                raise OsvResponseError(msg)
            seen_page_tokens.add(page_token)
        else:
            msg = f"OSV query exceeded pagination limit of {self._max_pages} pages"
            raise OsvResponseError(msg)

        return OsvQueryResult(
            purl=purl.to_string(),
            vulnerabilities=_parse_vulnerability_summaries(raw_vulnerabilities),
            version=version,
        )

    def query_batch(self, purls: list[PackageURL]) -> list[OsvQueryResult]:
        """Query OSV for package URLs using the batch endpoint."""
        return self.query_batch_packages([OsvPackageQuery(purl=purl) for purl in purls])

    def query_batch_packages(self, queries: list[OsvPackageQuery]) -> list[OsvQueryResult]:
        """Query OSV for packages using the batch endpoint."""
        if not queries:
            return []

        vulnerabilities_by_index: list[list[OsvVulnerabilitySummary]] = [[] for _ in queries]
        active_queries: list[tuple[int, OsvPackageQuery, str | None]] = [
            (index, query, None) for index, query in enumerate(queries)
        ]
        seen_page_tokens_by_index: list[set[str]] = [set() for _ in queries]

        for _ in range(self._max_pages):
            response = self._post(
                "/v1/querybatch",
                {
                    "queries": [
                        _query_payload(query, page_token=page_token)
                        for _, query, page_token in active_queries
                    ]
                },
            )
            page_results = _parse_batch_page_results(response, expected_count=len(active_queries))

            next_queries: list[tuple[int, OsvPackageQuery, str | None]] = []
            for query, page_result in zip(active_queries, page_results, strict=True):
                original_index, package_query, _ = query
                vulnerabilities_by_index[original_index].extend(page_result.vulnerabilities)
                if page_result.next_page_token is not None:
                    if page_result.next_page_token in seen_page_tokens_by_index[original_index]:
                        msg = "OSV query batch response repeated next_page_token"
                        raise OsvResponseError(msg)
                    seen_page_tokens_by_index[original_index].add(page_result.next_page_token)
                    next_queries.append(
                        (original_index, package_query, page_result.next_page_token)
                    )

            active_queries = next_queries
            if not active_queries:
                break
        else:
            msg = f"OSV query batch exceeded pagination limit of {self._max_pages} pages"
            raise OsvResponseError(msg)

        return [
            OsvQueryResult(
                purl=query.purl.to_string(),
                vulnerabilities=tuple(vulnerabilities),
                version=query.version,
            )
            for query, vulnerabilities in zip(queries, vulnerabilities_by_index, strict=True)
        ]

    def get_vulnerability(self, vulnerability_id: str) -> OsvVulnerability:
        """Fetch a full OSV vulnerability by ID."""
        response = self._get(f"/v1/vulns/{quote(vulnerability_id, safe='')}")
        vulnerability_id = _get_required_string_field(response, "id")
        return OsvVulnerability(id=vulnerability_id, raw=response)

    def _get(self, path: str) -> dict[str, Any]:
        return self._request_json("GET", path)

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request_json("POST", path, payload=payload)

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        client = self._client
        if client is not None:
            return self._send_json_request(client, method, path, payload=payload)

        with httpx.Client() as owned_client:
            return self._send_json_request(owned_client, method, path, payload=payload)

    def _send_json_request(
        self,
        client: httpx.Client,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None,
    ) -> dict[str, Any]:
        try:
            url = f"{self._base_url}{path}"
            if payload is None:
                response = client.request(method, url, timeout=self._timeout)
            else:
                response = client.request(method, url, json=payload, timeout=self._timeout)
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code
            msg = f"OSV API {method} {path} failed with HTTP {status_code}"
            raise OsvClientError(msg) from exc
        except httpx.HTTPError as exc:
            msg = f"OSV API {method} {path} request failed"
            raise OsvClientError(msg) from exc

        try:
            response_body = response.json()
        except ValueError as exc:
            msg = "OSV response body must be JSON"
            raise OsvResponseError(msg) from exc

        if not isinstance(response_body, dict):
            msg = "OSV response body must be an object"
            raise OsvResponseError(msg)

        return response_body


def osv_client_for_url(*, osv_base_url: str, allow_public_osv: bool) -> OsvClient:
    """Build an OSV client, requiring explicit opt-in for public OSV."""
    ensure_osv_url_allowed(
        osv_base_url=osv_base_url,
        allow_public_osv=allow_public_osv,
    )
    return OsvClient(base_url=osv_base_url)


def ensure_osv_url_allowed(*, osv_base_url: str, allow_public_osv: bool) -> None:
    """Reject public OSV URLs unless the caller explicitly opted in."""
    if is_public_osv_url(osv_base_url) and not allow_public_osv:
        msg = (
            "public OSV queries require explicit opt-in; pass --allow-public-osv "
            "or configure a private OSV mirror with --osv-url"
        )
        raise OsvConfigurationError(msg)


def ensure_osv_client_allowed(
    *,
    osv_client: object,
    osv_base_url: str,
    allow_public_osv: bool,
) -> None:
    """Reject injected public OSV clients unless the caller explicitly opted in."""
    client_base_url = _client_base_url(osv_client) or osv_base_url
    ensure_osv_url_allowed(
        osv_base_url=client_base_url,
        allow_public_osv=allow_public_osv,
    )


def is_public_osv_url(osv_base_url: str) -> bool:
    parsed = urlparse(osv_base_url)
    hostname = parsed.hostname
    if hostname is None:
        return False
    return _normalized_hostname(hostname) == PUBLIC_OSV_API_HOST


def _client_base_url(osv_client: object) -> str | None:
    base_url = getattr(osv_client, "base_url", None)
    if isinstance(base_url, str):
        return base_url
    return None


def _normalized_hostname(hostname: str) -> str:
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        ascii_hostname = hostname
    return ascii_hostname.rstrip(".").lower()


def findings_from_osv_results(
    *,
    components: tuple[ComponentIdentity, ...],
    results: list[OsvQueryResult],
) -> tuple[VulnerabilityFinding, ...]:
    """Map OSV query results onto affected SBOM component references."""
    components_by_query: dict[tuple[str, str | None], list[ComponentIdentity]] = {}
    for component in components:
        key = (component.purl.to_string(), _osv_query_version(component))
        components_by_query.setdefault(key, []).append(component)

    findings: list[VulnerabilityFinding] = []
    for result in results:
        for vulnerability in result.vulnerabilities:
            for component in components_by_query.get((result.purl, result.version), []):
                findings.append(
                    VulnerabilityFinding(
                        id=vulnerability.id,
                        source_name=OSV_SOURCE_NAME,
                        source_url=OSV_SOURCE_URL,
                        component_ref=component.ref,
                        purl=result.purl,
                        modified=vulnerability.modified,
                    )
                )

    return tuple(
        sorted(
            findings,
            key=lambda finding: (
                finding.id,
                finding.source_name,
                finding.component_ref,
                finding.purl,
            ),
        )
    )


def osv_queries_for_components(
    components: tuple[ComponentIdentity, ...],
) -> list[OsvPackageQuery]:
    """Build precise OSV package queries for SBOM components."""
    queries_by_key: dict[tuple[str, str | None], OsvPackageQuery] = {}
    for component in components:
        if component.purl.version is None and component.version is None:
            continue
        query = OsvPackageQuery(purl=component.purl, version=_osv_query_version(component))
        queries_by_key[(query.purl.to_string(), query.version)] = query
    return [queries_by_key[key] for key in sorted(queries_by_key)]


def _osv_query_version(component: ComponentIdentity) -> str | None:
    if component.purl.version is not None:
        return None
    return component.version


def _query_payload(query: OsvPackageQuery, *, page_token: str | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "package": {
            "purl": query.purl.to_string(),
        }
    }
    if query.version is not None:
        payload["version"] = query.version
    if page_token is not None:
        payload["page_token"] = page_token
    return payload


def _parse_batch_page_results(
    response: dict[str, Any],
    *,
    expected_count: int,
) -> list[_BatchPageResult]:
    raw_results = response.get("results", [])
    if not isinstance(raw_results, list):
        msg = "OSV response field 'results' must be a list"
        raise OsvResponseError(msg)
    if len(raw_results) != expected_count:
        msg = (
            "OSV query batch response count must match request count "
            f"({len(raw_results)} != {expected_count})"
        )
        raise OsvResponseError(msg)

    return [
        _BatchPageResult(
            vulnerabilities=_parse_vulnerability_summaries(
                _get_optional_list_field(raw_result, "vulns")
            ),
            next_page_token=_get_optional_string_field(raw_result, "next_page_token"),
        )
        for raw_result in raw_results
    ]


def _parse_vulnerability_summaries(raw_vulnerabilities: Any) -> tuple[OsvVulnerabilitySummary, ...]:
    if not isinstance(raw_vulnerabilities, list):
        msg = "OSV response field 'vulns' must be a list"
        raise OsvResponseError(msg)

    parsed: list[OsvVulnerabilitySummary] = []
    for vuln in raw_vulnerabilities:
        if not isinstance(vuln, dict):
            msg = "OSV vulnerability entries must be objects"
            raise OsvResponseError(msg)
        parsed.append(
            OsvVulnerabilitySummary(
                id=_get_required_string_field(vuln, "id"),
                modified=_get_optional_timestamp_field(vuln, "modified"),
            )
        )
    return tuple(parsed)


def _get_optional_list_field(raw_value: Any, field_name: str) -> list[Any]:
    if not isinstance(raw_value, dict):
        msg = "OSV query batch result entries must be objects"
        raise OsvResponseError(msg)

    field_value = raw_value.get(field_name, [])
    if not isinstance(field_value, list):
        msg = f"OSV response field '{field_name}' must be a list"
        raise OsvResponseError(msg)
    return field_value


def _get_required_string_field(raw_value: dict[str, Any], field_name: str) -> str:
    field_value = raw_value.get(field_name)
    if not isinstance(field_value, str) or not field_value:
        msg = f"OSV response field '{field_name}' must be a non-empty string"
        raise OsvResponseError(msg)
    return field_value


def _get_optional_string_field(raw_value: Any, field_name: str) -> str | None:
    if not isinstance(raw_value, dict):
        msg = "OSV response objects must be objects"
        raise OsvResponseError(msg)

    field_value = raw_value.get(field_name)
    if field_value is None:
        return None
    if not isinstance(field_value, str) or not field_value:
        msg = f"OSV response field '{field_name}' must be a non-empty string when present"
        raise OsvResponseError(msg)
    return field_value


def _get_optional_timestamp_field(raw_value: Any, field_name: str) -> datetime | None:
    field_value = _get_optional_string_field(raw_value, field_name)
    if field_value is None:
        return None
    try:
        parsed = datetime.fromisoformat(field_value.replace("Z", "+00:00"))
    except ValueError as exc:
        msg = f"OSV response field '{field_name}' must be an ISO-8601 timestamp"
        raise OsvResponseError(msg) from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
