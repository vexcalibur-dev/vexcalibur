"""OSV API client."""

from __future__ import annotations

import posixpath
import time
import unicodedata
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address
from math import isfinite
from typing import Any, TypeVar
from urllib.parse import quote, unquote, urlparse

import httpx
from packageurl import PackageURL

from vexcalibur.domain import (
    ComponentIdentity,
    ComponentVersionError,
    VulnerabilityFinding,
    VulnerabilitySourceError,
    VulnerabilitySourceInputError,
    canonical_component_version,
)
from vexcalibur.json_boundary import JsonFailureKind, StrictJsonError, strict_json_loads
from vexcalibur.url_policy import BaseUrlValidationError, validate_base_url

DEFAULT_OSV_API_URL = "https://api.osv.dev"
DEFAULT_MAX_OSV_PAGES = 100
DEFAULT_MAX_OSV_RESPONSE_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_OSV_TOTAL_RESPONSE_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_OSV_ENCODED_RESPONSE_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_OSV_TOTAL_ENCODED_RESPONSE_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_OSV_QUERIES = 10_000
DEFAULT_MAX_OSV_VULNERABILITIES_PER_QUERY = 10_000
DEFAULT_MAX_OSV_TOTAL_VULNERABILITIES = 100_000
DEFAULT_MAX_OSV_FINDINGS = 100_000
DEFAULT_OSV_OPERATION_TIMEOUT = 120.0
MAX_OSV_BATCH_QUERIES = 1_000
MAX_OSV_PAGE_TOKEN_LENGTH = 4_096
MAX_OSV_VULNERABILITY_ID_LENGTH = 512
MAX_OSV_TIMESTAMP_LENGTH = 128
OSV_RESPONSE_CHUNK_SIZE = 64 * 1024
PUBLIC_OSV_API_HOST = "api.osv.dev"
PUBLIC_OSV_PROVENANCE_HOST = "osv.dev"
OSV_SOURCE_NAME = "OSV"
OSV_SOURCE_URL = "https://osv.dev/"
OSV_MIRROR_SOURCE_NAME = "OSV-compatible mirror"
OSV_ANALYSIS_DETAIL = "Detected by OSV; manual exploitability analysis required."
OSV_MIRROR_ANALYSIS_DETAIL = (
    "Detected by an OSV-compatible source; manual exploitability analysis required."
)

_T = TypeVar("_T")


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


class OsvClientError(VulnerabilitySourceError):
    """Base error raised for OSV client failures."""


class OsvResponseError(OsvClientError):
    """Raised when OSV returns a response that does not match the expected API shape."""


class OsvConfigurationError(OsvClientError, ValueError):
    """Raised when OSV source configuration is unsafe or invalid."""


@dataclass(frozen=True)
class _BatchPageResult:
    new_vulnerability_count: int
    next_page_token: str | None


@dataclass
class _VulnerabilityAccumulator:
    """First-seen ID order with the newest available modification time."""

    summaries: list[OsvVulnerabilitySummary] = field(default_factory=list)
    indexes: dict[str, int] = field(default_factory=dict)


@dataclass
class _OsvOperationBudget:
    """Mutable byte and wall-clock budgets shared by one client operation."""

    deadline: float
    max_total_decoded_response_bytes: int
    max_total_encoded_response_bytes: int
    decoded_response_bytes: int = 0
    encoded_response_bytes: int = 0

    def remaining_seconds(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            msg = "OSV operation exceeded its overall deadline"
            raise OsvClientError(msg)
        return remaining

    def consume_decoded_response_bytes(self, count: int) -> None:
        self.remaining_seconds()
        if self.decoded_response_bytes + count > self.max_total_decoded_response_bytes:
            msg = (
                "OSV operation decoded response bodies exceed the cumulative "
                f"{self.max_total_decoded_response_bytes} byte limit"
            )
            raise OsvResponseError(msg)
        self.decoded_response_bytes += count

    def consume_encoded_response_bytes(self, count: int) -> None:
        self.remaining_seconds()
        if self.encoded_response_bytes + count > self.max_total_encoded_response_bytes:
            msg = (
                "OSV operation encoded response bodies exceed the cumulative "
                f"{self.max_total_encoded_response_bytes} byte limit"
            )
            raise OsvResponseError(msg)
        self.encoded_response_bytes += count


class OsvClient:
    """Bounded client for the public OSV API and compatible endpoints."""

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_OSV_API_URL,
        timeout: float = 30.0,
        max_pages: int = DEFAULT_MAX_OSV_PAGES,
        operation_timeout: float = DEFAULT_OSV_OPERATION_TIMEOUT,
        max_response_bytes: int = DEFAULT_MAX_OSV_RESPONSE_BYTES,
        max_total_response_bytes: int = DEFAULT_MAX_OSV_TOTAL_RESPONSE_BYTES,
        max_encoded_response_bytes: int = DEFAULT_MAX_OSV_ENCODED_RESPONSE_BYTES,
        max_total_encoded_response_bytes: int = DEFAULT_MAX_OSV_TOTAL_ENCODED_RESPONSE_BYTES,
        max_queries: int = DEFAULT_MAX_OSV_QUERIES,
        max_vulnerabilities_per_query: int = DEFAULT_MAX_OSV_VULNERABILITIES_PER_QUERY,
        max_total_vulnerabilities: int = DEFAULT_MAX_OSV_TOTAL_VULNERABILITIES,
        max_page_token_length: int = MAX_OSV_PAGE_TOKEN_LENGTH,
        max_vulnerability_id_length: int = MAX_OSV_VULNERABILITY_ID_LENGTH,
        client: httpx.Client | None = None,
    ) -> None:
        if max_pages < 1:
            msg = "max_pages must be at least 1"
            raise ValueError(msg)
        if timeout <= 0 or not isfinite(timeout):
            msg = "timeout must be greater than 0"
            raise ValueError(msg)
        if operation_timeout <= 0 or not isfinite(operation_timeout):
            msg = "operation_timeout must be greater than 0"
            raise ValueError(msg)
        _require_positive_limit("max_response_bytes", max_response_bytes)
        _require_positive_limit("max_total_response_bytes", max_total_response_bytes)
        if max_total_response_bytes < max_response_bytes:
            msg = "max_total_response_bytes must be at least max_response_bytes"
            raise ValueError(msg)
        _require_positive_limit("max_encoded_response_bytes", max_encoded_response_bytes)
        _require_positive_limit(
            "max_total_encoded_response_bytes",
            max_total_encoded_response_bytes,
        )
        if max_total_encoded_response_bytes < max_encoded_response_bytes:
            msg = "max_total_encoded_response_bytes must be at least max_encoded_response_bytes"
            raise ValueError(msg)
        _require_positive_limit("max_queries", max_queries)
        _require_positive_limit("max_vulnerabilities_per_query", max_vulnerabilities_per_query)
        _require_positive_limit("max_total_vulnerabilities", max_total_vulnerabilities)
        _require_positive_limit("max_page_token_length", max_page_token_length)
        _require_positive_limit("max_vulnerability_id_length", max_vulnerability_id_length)
        self._base_url = normalize_osv_base_url(base_url)
        validate_osv_base_url(self._base_url)
        self._timeout = timeout
        self._max_pages = max_pages
        self._operation_timeout = operation_timeout
        self._max_response_bytes = max_response_bytes
        self._max_total_response_bytes = max_total_response_bytes
        self._max_encoded_response_bytes = max_encoded_response_bytes
        self._max_total_encoded_response_bytes = max_total_encoded_response_bytes
        self._max_queries = max_queries
        self._max_vulnerabilities_per_query = max_vulnerabilities_per_query
        self._max_total_vulnerabilities = max_total_vulnerabilities
        self._max_page_token_length = max_page_token_length
        self._max_vulnerability_id_length = max_vulnerability_id_length
        self._client = client

    @property
    def base_url(self) -> str:
        """Base URL used for OSV API requests."""
        return self._base_url

    @property
    def max_vulnerability_id_length(self) -> int:
        """Maximum normalized vulnerability-ID length accepted by this client."""
        return self._max_vulnerability_id_length

    def query(self, purl: PackageURL, *, version: str | None = None) -> OsvQueryResult:
        """Query OSV for one package URL."""
        query = OsvPackageQuery(purl=purl, version=version)
        accumulator = _VulnerabilityAccumulator()
        total_vulnerabilities = 0
        page_token: str | None = None
        seen_page_tokens: set[str] = set()
        budget = self._operation_budget()

        for _ in range(self._max_pages):
            response = self._post(
                "/v1/query",
                _query_payload(query, page_token=page_token),
                budget=budget,
            )
            new_vulnerability_count = _parse_vulnerability_summaries(
                _get_optional_list_field(response, "vulns"),
                accumulator=accumulator,
                max_unique=self._max_vulnerabilities_per_query,
                max_id_length=self._max_vulnerability_id_length,
            )
            budget.remaining_seconds()
            if total_vulnerabilities + new_vulnerability_count > self._max_total_vulnerabilities:
                msg = (
                    "OSV operation contains more than "
                    f"{self._max_total_vulnerabilities} query-vulnerability results"
                )
                raise OsvResponseError(msg)
            total_vulnerabilities += new_vulnerability_count

            page_token = _get_optional_string_field(
                response,
                "next_page_token",
                max_length=self._max_page_token_length,
            )
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
            vulnerabilities=tuple(accumulator.summaries),
            version=version,
        )

    def query_batch(self, purls: list[PackageURL]) -> list[OsvQueryResult]:
        """Query OSV for package URLs using the batch endpoint."""
        return self.query_batch_packages([OsvPackageQuery(purl=purl) for purl in purls])

    def query_batch_packages(self, queries: list[OsvPackageQuery]) -> list[OsvQueryResult]:
        """Query OSV for packages using the batch endpoint."""
        if not queries:
            return []
        if len(queries) > self._max_queries:
            msg = f"OSV batch contains more than {self._max_queries} queries"
            raise OsvResponseError(msg)

        accumulators_by_index = [_VulnerabilityAccumulator() for _ in queries]
        active_queries: list[tuple[int, OsvPackageQuery, str | None]] = [
            (index, query, None) for index, query in enumerate(queries)
        ]
        seen_page_tokens_by_index: list[set[str]] = [set() for _ in queries]
        total_vulnerabilities = 0
        budget = self._operation_budget()

        for _ in range(self._max_pages):
            next_queries: list[tuple[int, OsvPackageQuery, str | None]] = []
            for query_chunk in _chunks(active_queries, MAX_OSV_BATCH_QUERIES):
                response = self._post(
                    "/v1/querybatch",
                    {
                        "queries": [
                            _query_payload(query, page_token=page_token)
                            for _, query, page_token in query_chunk
                        ]
                    },
                    budget=budget,
                )
                page_results = _parse_batch_page_results(
                    response,
                    expected_count=len(query_chunk),
                    accumulators=[
                        accumulators_by_index[original_index]
                        for original_index, _, _ in query_chunk
                    ],
                    max_vulnerabilities_per_query=self._max_vulnerabilities_per_query,
                    max_page_token_length=self._max_page_token_length,
                    max_vulnerability_id_length=self._max_vulnerability_id_length,
                )
                budget.remaining_seconds()

                for query_item, page_result in zip(query_chunk, page_results, strict=True):
                    original_index, package_query, _ = query_item
                    if (
                        total_vulnerabilities + page_result.new_vulnerability_count
                        > self._max_total_vulnerabilities
                    ):
                        msg = (
                            "OSV operation contains more than "
                            f"{self._max_total_vulnerabilities} query-vulnerability results"
                        )
                        raise OsvResponseError(msg)
                    total_vulnerabilities += page_result.new_vulnerability_count
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
                vulnerabilities=tuple(accumulator.summaries),
                version=query.version,
            )
            for query, accumulator in zip(queries, accumulators_by_index, strict=True)
        ]

    def get_vulnerability(self, vulnerability_id: str) -> OsvVulnerability:
        """Fetch a full OSV vulnerability by ID."""
        canonical_id = _validate_vulnerability_id(
            vulnerability_id,
            max_length=self._max_vulnerability_id_length,
            field_name="vulnerability_id",
        )
        response = self._get(
            f"/v1/vulns/{quote(canonical_id, safe='')}",
            budget=self._operation_budget(),
        )
        vulnerability_id = _validate_vulnerability_id(
            _get_required_string_field(response, "id"),
            max_length=self._max_vulnerability_id_length,
            field_name="id",
        )
        return OsvVulnerability(id=vulnerability_id, raw=response)

    def _operation_budget(self) -> _OsvOperationBudget:
        return _OsvOperationBudget(
            deadline=time.monotonic() + self._operation_timeout,
            max_total_decoded_response_bytes=self._max_total_response_bytes,
            max_total_encoded_response_bytes=self._max_total_encoded_response_bytes,
        )

    def _get(self, path: str, *, budget: _OsvOperationBudget) -> dict[str, Any]:
        return self._request_json("GET", path, budget=budget)

    def _post(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        budget: _OsvOperationBudget,
    ) -> dict[str, Any]:
        return self._request_json("POST", path, payload=payload, budget=budget)

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        budget: _OsvOperationBudget,
    ) -> dict[str, Any]:
        client = self._client
        if client is not None:
            return self._send_json_request(
                client,
                method,
                path,
                payload=payload,
                budget=budget,
            )

        with httpx.Client() as owned_client:
            return self._send_json_request(
                owned_client,
                method,
                path,
                payload=payload,
                budget=budget,
            )

    def _send_json_request(
        self,
        client: httpx.Client,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None,
        budget: _OsvOperationBudget,
    ) -> dict[str, Any]:
        try:
            url = f"{self._base_url}{path}"
            request_timeout = min(self._timeout, budget.remaining_seconds())
            with client.stream(
                method,
                url,
                json=payload,
                headers={"Accept-Encoding": "gzip"},
                follow_redirects=False,
                timeout=request_timeout,
            ) as response:
                response_body_bytes = self._read_response_body(
                    response,
                    method=method,
                    path=path,
                    budget=budget,
                )
                status_code = response.status_code
        except httpx.HTTPError as exc:
            msg = f"OSV API {method} {path} request failed"
            raise OsvClientError(msg) from exc

        if status_code < 200 or status_code >= 300:
            msg = f"OSV API {method} {path} failed with HTTP {status_code}"
            raise OsvClientError(msg)

        try:
            response_body = strict_json_loads(response_body_bytes)
        except StrictJsonError as exc:
            msg = _osv_json_error_message(exc)
            raise OsvResponseError(msg) from exc

        if not isinstance(response_body, dict):
            msg = "OSV response body must be an object"
            raise OsvResponseError(msg)

        budget.remaining_seconds()
        return response_body

    def _read_response_body(
        self,
        response: httpx.Response,
        *,
        method: str,
        path: str,
        budget: _OsvOperationBudget,
    ) -> bytes:
        content_encoding = _content_encoding(response)
        declared_length = _content_length(response)
        if declared_length is not None:
            if declared_length > self._max_encoded_response_bytes:
                msg = (
                    f"OSV API {method} {path} encoded response exceeds the "
                    f"{self._max_encoded_response_bytes} byte limit"
                )
                raise OsvResponseError(msg)
            if (
                budget.encoded_response_bytes + declared_length
                > budget.max_total_encoded_response_bytes
            ):
                msg = (
                    "OSV operation encoded response bodies exceed the cumulative "
                    f"{budget.max_total_encoded_response_bytes} byte limit"
                )
                raise OsvResponseError(msg)
            if content_encoding == "identity":
                if declared_length > self._max_response_bytes:
                    msg = (
                        f"OSV API {method} {path} decoded response exceeds the "
                        f"{self._max_response_bytes} byte limit"
                    )
                    raise OsvResponseError(msg)
                if (
                    budget.decoded_response_bytes + declared_length
                    > budget.max_total_decoded_response_bytes
                ):
                    msg = (
                        "OSV operation decoded response bodies exceed the cumulative "
                        f"{budget.max_total_decoded_response_bytes} byte limit"
                    )
                    raise OsvResponseError(msg)

        content = bytearray()
        encoded_response_bytes = 0
        decoder = (
            zlib.decompressobj(wbits=16 + zlib.MAX_WBITS) if content_encoding == "gzip" else None
        )

        def append_decoded_chunk(chunk: bytes) -> None:
            if len(content) + len(chunk) > self._max_response_bytes:
                msg = (
                    f"OSV API {method} {path} decoded response exceeds the "
                    f"{self._max_response_bytes} byte limit"
                )
                raise OsvResponseError(msg)
            budget.consume_decoded_response_bytes(len(chunk))
            content.extend(chunk)

        # Mock transports and other injected clients may return an already-read
        # response even when ``stream=True``. HTTPX stores that cache decoded, so
        # enforce the decoded limit directly and use Content-Length only for the
        # encoded accounting that can still be observed.
        if response.is_stream_consumed:
            cached_content = response.content
            observable_encoded_bytes = (
                len(cached_content) if content_encoding == "identity" else declared_length or 0
            )
            if observable_encoded_bytes:
                budget.consume_encoded_response_bytes(observable_encoded_bytes)
            append_decoded_chunk(cached_content)
            budget.remaining_seconds()
            return bytes(content)

        for raw_chunk in response.iter_raw():
            budget.remaining_seconds()
            if not raw_chunk:
                continue
            if encoded_response_bytes + len(raw_chunk) > self._max_encoded_response_bytes:
                msg = (
                    f"OSV API {method} {path} encoded response exceeds the "
                    f"{self._max_encoded_response_bytes} byte limit"
                )
                raise OsvResponseError(msg)
            budget.consume_encoded_response_bytes(len(raw_chunk))
            encoded_response_bytes += len(raw_chunk)

            if decoder is None:
                append_decoded_chunk(raw_chunk)
                continue

            pending = raw_chunk
            while pending:
                budget.remaining_seconds()
                per_response_remaining = self._max_response_bytes - len(content)
                cumulative_remaining = (
                    budget.max_total_decoded_response_bytes - budget.decoded_response_bytes
                )
                max_output = max(
                    1,
                    min(
                        OSV_RESPONSE_CHUNK_SIZE,
                        per_response_remaining + 1,
                        cumulative_remaining + 1,
                    ),
                )
                try:
                    decoded_chunk = decoder.decompress(pending, max_output)
                except zlib.error as exc:
                    msg = f"OSV API {method} {path} response has invalid gzip encoding"
                    raise OsvResponseError(msg) from exc
                unconsumed = decoder.unconsumed_tail
                if len(unconsumed) == len(pending) and not decoded_chunk:
                    msg = f"OSV API {method} {path} gzip decoder made no progress"
                    raise OsvResponseError(msg)
                pending = unconsumed
                if decoded_chunk:
                    append_decoded_chunk(decoded_chunk)
                if decoder.unused_data:
                    msg = f"OSV API {method} {path} gzip response has trailing data"
                    raise OsvResponseError(msg)
                budget.remaining_seconds()

        if decoder is not None and not decoder.eof:
            msg = f"OSV API {method} {path} response has truncated gzip encoding"
            raise OsvResponseError(msg)
        budget.remaining_seconds()
        return bytes(content)


def _osv_json_error_message(error: StrictJsonError) -> str:
    if error.kind is JsonFailureKind.ENCODING:
        return "OSV response body must be UTF-8 JSON"
    if error.kind is JsonFailureKind.DUPLICATE_KEY:
        return "OSV response body must not contain duplicate JSON object keys"
    if error.kind is JsonFailureKind.NESTING:
        return "OSV response body is too deeply nested"
    if error.kind is JsonFailureKind.INTEGER:
        return "OSV response body contains an oversized JSON integer"
    return "OSV response body must be JSON"


@dataclass(frozen=True)
class OsvSource:
    """Vulnerability source backed by an OSV-compatible API client."""

    client: OsvClient | None = None
    osv_base_url: str = DEFAULT_OSV_API_URL
    allow_public_osv: bool = False
    source_name: str | None = None
    source_url: str | None = None

    def __post_init__(self) -> None:
        source_name, source_url = _normalize_provenance_alias(
            source_name=self.source_name,
            source_url=self.source_url,
        )
        object.__setattr__(self, "source_name", source_name)
        object.__setattr__(self, "source_url", source_url)

    def findings_for_components(
        self,
        components: tuple[ComponentIdentity, ...],
    ) -> tuple[VulnerabilityFinding, ...]:
        """Return VEX-ready findings discovered from OSV query results."""
        queries = osv_queries_for_components(components)
        if not queries:
            msg = "no components with versioned package URLs were found"
            raise VulnerabilitySourceInputError(msg)
        client = self._client()
        source_name, source_url, analysis_detail = self._provenance(client)
        return findings_from_osv_results(
            components=components,
            results=client.query_batch_packages(queries),
            source_name=source_name,
            source_url=source_url,
            analysis_detail=analysis_detail,
            max_vulnerability_id_length=getattr(
                client,
                "max_vulnerability_id_length",
                MAX_OSV_VULNERABILITY_ID_LENGTH,
            ),
        )

    def _client(self) -> OsvClient:
        if self.client is None:
            return osv_client_for_url(
                osv_base_url=self.osv_base_url,
                allow_public_osv=self.allow_public_osv,
            )
        ensure_osv_client_allowed(
            osv_client=self.client,
            osv_base_url=self.osv_base_url,
            allow_public_osv=self.allow_public_osv,
        )
        return self.client

    def _provenance(self, client: OsvClient) -> tuple[str, str, str]:
        effective_base_url = normalize_osv_base_url(_client_base_url(client) or self.osv_base_url)
        validate_osv_base_url(effective_base_url)
        is_official = _is_canonical_public_osv_endpoint(effective_base_url)
        analysis_detail = OSV_ANALYSIS_DETAIL if is_official else OSV_MIRROR_ANALYSIS_DETAIL
        if is_official and self.source_name is not None:
            msg = "the canonical public OSV endpoint cannot use a provenance alias"
            raise OsvConfigurationError(msg)
        if self.source_name is not None and self.source_url is not None:
            return self.source_name, self.source_url, analysis_detail
        if is_official:
            return OSV_SOURCE_NAME, OSV_SOURCE_URL, analysis_detail
        return (
            OSV_MIRROR_SOURCE_NAME,
            _canonical_httpx_url(effective_base_url),
            analysis_detail,
        )


def osv_client_for_url(*, osv_base_url: str, allow_public_osv: bool) -> OsvClient:
    """Build an OSV client, requiring explicit opt-in for public OSV."""
    normalized_base_url = normalize_osv_base_url(osv_base_url)
    ensure_osv_url_allowed(
        osv_base_url=normalized_base_url,
        allow_public_osv=allow_public_osv,
    )
    return OsvClient(base_url=normalized_base_url)


def ensure_osv_url_allowed(*, osv_base_url: str, allow_public_osv: bool) -> None:
    """Reject public OSV URLs unless the caller explicitly opted in."""
    validate_osv_base_url(osv_base_url)
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
    try:
        parsed = urlparse(normalize_osv_base_url(osv_base_url))
        hostname = parsed.hostname
    except ValueError:
        return False
    if hostname is None:
        return False
    return _normalized_hostname(hostname) == PUBLIC_OSV_API_HOST


def normalize_osv_base_url(osv_base_url: str) -> str:
    """Normalize OSV base URL whitespace and trailing slashes."""
    return osv_base_url.strip().rstrip("/")


def validate_osv_base_url(osv_base_url: str) -> None:
    """Require OSV URLs to be HTTPS, except HTTP loopback for local test services."""
    try:
        parsed = validate_base_url(
            osv_base_url,
            option_name="--osv-url",
            allowed_schemes={"https", "http"},
            scheme_message="--osv-url must be an absolute https URL with a hostname",
        ).parsed
    except BaseUrlValidationError as exc:
        raise OsvConfigurationError(str(exc)) from exc

    hostname = parsed.hostname
    if hostname is None:
        raise AssertionError("validated OSV base URL must include a hostname")
    if parsed.scheme == "http" and not _is_loopback_hostname(hostname):
        msg = "--osv-url must use https unless it points to a loopback host"
        raise OsvConfigurationError(msg)


def _client_base_url(osv_client: object) -> str | None:
    base_url = getattr(osv_client, "base_url", None)
    if isinstance(base_url, str):
        return base_url
    if isinstance(base_url, httpx.URL):
        return str(base_url)
    return None


def _normalized_hostname(hostname: str) -> str:
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        ascii_hostname = hostname
    return ascii_hostname.rstrip(".").lower()


def _is_loopback_hostname(hostname: str) -> bool:
    normalized = _normalized_hostname(hostname)
    if normalized == "localhost":
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def _is_canonical_public_osv_endpoint(osv_base_url: str) -> bool:
    try:
        parsed = urlparse(normalize_osv_base_url(osv_base_url))
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and hostname is not None
        and _normalized_hostname(hostname) == PUBLIC_OSV_API_HOST
        and port in {None, 443}
        and _is_root_equivalent_url_path(parsed.path)
        and not parsed.params
        and not parsed.query
        and not parsed.fragment
    )


def _normalize_provenance_alias(
    *,
    source_name: str | None,
    source_url: str | None,
) -> tuple[str | None, str | None]:
    if (source_name is None) != (source_url is None):
        msg = "OSV source_name and source_url must be provided together"
        raise OsvConfigurationError(msg)
    if source_name is None or source_url is None:
        return None, None

    normalized_name = source_name.strip()
    if not normalized_name:
        msg = "--osv-source-name must not be empty"
        raise OsvConfigurationError(msg)
    if _contains_unsafe_identifier_character(normalized_name):
        msg = "--osv-source-name must not contain unsafe separator or control characters"
        raise OsvConfigurationError(msg)
    if unicodedata.normalize("NFKC", normalized_name).casefold() == OSV_SOURCE_NAME.casefold():
        msg = "official OSV provenance is reserved for the canonical public service"
        raise OsvConfigurationError(msg)

    try:
        validated_url = validate_base_url(
            source_url,
            option_name="--osv-source-url",
            allowed_schemes={"https"},
            scheme_message="--osv-source-url must be an absolute https URL with a hostname",
        ).value
    except BaseUrlValidationError as exc:
        raise OsvConfigurationError(str(exc)) from exc
    canonical_url = _canonical_httpx_url(validated_url)
    if _is_official_provenance_url(canonical_url):
        msg = "official OSV provenance is reserved for the canonical public service"
        raise OsvConfigurationError(msg)
    return normalized_name, canonical_url


def _is_official_provenance_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and hostname is not None
        and _normalized_hostname(hostname) == PUBLIC_OSV_PROVENANCE_HOST
        and port in {None, 443}
        and not parsed.params
        and not parsed.query
        and not parsed.fragment
    )


def _is_root_equivalent_url_path(path: str) -> bool:
    decoded_path = unquote(path)
    return posixpath.normpath(f"/{decoded_path.lstrip('/')}") == "/"


def _canonical_httpx_url(value: str) -> str:
    try:
        return str(httpx.URL(value))
    except httpx.InvalidURL as exc:
        msg = "OSV URL must be a valid absolute URL"
        raise OsvConfigurationError(msg) from exc


def findings_from_osv_results(
    *,
    components: tuple[ComponentIdentity, ...],
    results: list[OsvQueryResult],
    source_name: str,
    source_url: str,
    analysis_detail: str,
    max_findings: int = DEFAULT_MAX_OSV_FINDINGS,
    max_vulnerability_id_length: int = MAX_OSV_VULNERABILITY_ID_LENGTH,
) -> tuple[VulnerabilityFinding, ...]:
    """Map OSV results using caller-supplied, explicit source provenance."""
    _require_positive_limit("max_findings", max_findings)
    _require_positive_limit("max_vulnerability_id_length", max_vulnerability_id_length)
    components_by_query: dict[tuple[str, str | None], list[ComponentIdentity]] = {}
    try:
        for component in components:
            key = (component.purl.to_string(), _osv_query_version(component))
            components_by_query.setdefault(key, []).append(component)
    except ComponentVersionError as exc:
        msg = f"component has conflicting version identity: {exc}"
        raise VulnerabilitySourceInputError(msg) from exc

    vulnerabilities_by_query: dict[tuple[str, str | None], dict[str, OsvVulnerabilitySummary]] = {}
    for result in results:
        for vulnerability in result.vulnerabilities:
            canonical_id = _validate_vulnerability_id(
                vulnerability.id,
                max_length=max_vulnerability_id_length,
                field_name="id",
            )
            vulnerabilities = vulnerabilities_by_query.setdefault((result.purl, result.version), {})
            candidate = OsvVulnerabilitySummary(
                id=canonical_id,
                modified=vulnerability.modified,
            )
            existing = vulnerabilities.get(canonical_id)
            vulnerabilities[canonical_id] = (
                candidate
                if existing is None
                else _summary_with_newest_modified(existing, candidate)
            )

    relation_count = 0
    for query_key, vulnerabilities in vulnerabilities_by_query.items():
        relation_count += len(components_by_query.get(query_key, [])) * len(vulnerabilities)
        if relation_count > max_findings:
            msg = (
                "OSV component-vulnerability relation count exceeds the "
                f"{max_findings} finding limit"
            )
            raise OsvResponseError(msg)

    findings: list[VulnerabilityFinding] = []
    for query_key, vulnerabilities in vulnerabilities_by_query.items():
        result_purl, _ = query_key
        for vulnerability in vulnerabilities.values():
            for component in components_by_query.get(query_key, []):
                findings.append(
                    VulnerabilityFinding(
                        id=vulnerability.id,
                        source_name=source_name,
                        source_url=source_url,
                        component_ref=component.ref,
                        purl=result_purl,
                        modified=vulnerability.modified,
                        analysis_detail=analysis_detail,
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
    try:
        for component in components:
            if canonical_component_version(version=component.version, purl=component.purl) is None:
                continue
            query = OsvPackageQuery(purl=component.purl, version=_osv_query_version(component))
            queries_by_key[(query.purl.to_string(), query.version)] = query
    except ComponentVersionError as exc:
        msg = f"component has conflicting version identity: {exc}"
        raise VulnerabilitySourceInputError(msg) from exc
    return [queries_by_key[key] for key in sorted(queries_by_key)]


def _osv_query_version(component: ComponentIdentity) -> str | None:
    version = canonical_component_version(version=component.version, purl=component.purl)
    if component.purl.version is not None:
        return None
    return version


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
    accumulators: list[_VulnerabilityAccumulator],
    max_vulnerabilities_per_query: int,
    max_page_token_length: int,
    max_vulnerability_id_length: int,
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
    if len(accumulators) != expected_count:
        raise AssertionError("OSV batch parser state must match request count")

    return [
        _BatchPageResult(
            new_vulnerability_count=_parse_vulnerability_summaries(
                _get_optional_list_field(raw_result, "vulns"),
                accumulator=accumulator,
                max_unique=max_vulnerabilities_per_query,
                max_id_length=max_vulnerability_id_length,
            ),
            next_page_token=_get_optional_string_field(
                raw_result,
                "next_page_token",
                max_length=max_page_token_length,
            ),
        )
        for raw_result, accumulator in zip(raw_results, accumulators, strict=True)
    ]


def _parse_vulnerability_summaries(
    raw_vulnerabilities: Any,
    *,
    accumulator: _VulnerabilityAccumulator,
    max_unique: int,
    max_id_length: int,
) -> int:
    if not isinstance(raw_vulnerabilities, list):
        msg = "OSV response field 'vulns' must be a list"
        raise OsvResponseError(msg)

    new_vulnerability_count = 0
    for vuln in raw_vulnerabilities:
        if not isinstance(vuln, dict):
            msg = "OSV vulnerability entries must be objects"
            raise OsvResponseError(msg)
        vulnerability_id = _validate_vulnerability_id(
            _get_required_string_field(vuln, "id"),
            max_length=max_id_length,
            field_name="id",
        )
        modified = _get_optional_timestamp_field(vuln, "modified")
        summary = OsvVulnerabilitySummary(id=vulnerability_id, modified=modified)
        existing_index = accumulator.indexes.get(vulnerability_id)
        if existing_index is not None:
            accumulator.summaries[existing_index] = _summary_with_newest_modified(
                accumulator.summaries[existing_index],
                summary,
            )
            continue
        if len(accumulator.indexes) >= max_unique:
            msg = f"OSV query contains more than {max_unique} unique vulnerabilities"
            raise OsvResponseError(msg)
        accumulator.indexes[vulnerability_id] = len(accumulator.summaries)
        accumulator.summaries.append(summary)
        new_vulnerability_count += 1
    return new_vulnerability_count


def _summary_with_newest_modified(
    existing: OsvVulnerabilitySummary,
    candidate: OsvVulnerabilitySummary,
) -> OsvVulnerabilitySummary:
    if candidate.modified is None:
        return existing
    candidate_modified = _comparable_timestamp(candidate.modified)
    if existing.modified is None or candidate_modified > _comparable_timestamp(existing.modified):
        return OsvVulnerabilitySummary(id=existing.id, modified=candidate.modified)
    return existing


def _comparable_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


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


def _get_optional_string_field(
    raw_value: Any,
    field_name: str,
    *,
    max_length: int | None = None,
) -> str | None:
    if not isinstance(raw_value, dict):
        msg = "OSV response objects must be objects"
        raise OsvResponseError(msg)

    field_value = raw_value.get(field_name)
    if field_value is None:
        return None
    if not isinstance(field_value, str) or not field_value:
        msg = f"OSV response field '{field_name}' must be a non-empty string when present"
        raise OsvResponseError(msg)
    if max_length is not None and len(field_value) > max_length:
        msg = f"OSV response field '{field_name}' exceeds the {max_length} character limit"
        raise OsvResponseError(msg)
    return field_value


def _get_optional_timestamp_field(raw_value: Any, field_name: str) -> datetime | None:
    field_value = _get_optional_string_field(
        raw_value,
        field_name,
        max_length=MAX_OSV_TIMESTAMP_LENGTH,
    )
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


def _validate_vulnerability_id(
    value: str,
    *,
    max_length: int,
    field_name: str,
) -> str:
    canonical = unicodedata.normalize("NFC", value)
    if len(canonical) > max_length:
        msg = f"OSV response field '{field_name}' exceeds the {max_length} character limit"
        raise OsvResponseError(msg)
    if _contains_unsafe_identifier_character(canonical):
        msg = (
            f"OSV response field '{field_name}' must not contain control, "
            "bidi-control, or line-separator characters"
        )
        raise OsvResponseError(msg)
    return canonical


def _contains_unsafe_identifier_character(value: str) -> bool:
    return any(
        unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"} for character in value
    )


def _content_length(response: httpx.Response) -> int | None:
    raw_length = response.headers.get("Content-Length")
    if raw_length is None:
        return None
    try:
        parsed = int(raw_length, 10)
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def _content_encoding(response: httpx.Response) -> str:
    raw_encoding = response.headers.get("Content-Encoding")
    if raw_encoding is None:
        return "identity"
    encoding = raw_encoding.strip().casefold()
    if encoding in {"", "identity"}:
        return "identity"
    if encoding == "gzip":
        return "gzip"
    msg = f"OSV response uses unsupported Content-Encoding {raw_encoding!r}"
    raise OsvResponseError(msg)


def _chunks(values: list[_T], size: int) -> list[list[_T]]:
    return [values[index : index + size] for index in range(0, len(values), size)]


def _require_positive_limit(name: str, value: int) -> None:
    if value < 1:
        msg = f"{name} must be at least 1"
        raise ValueError(msg)
