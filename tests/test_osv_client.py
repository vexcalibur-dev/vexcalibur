import gzip
import json
import time
import unicodedata
from collections.abc import Iterator

import httpx
import pytest
from packageurl import PackageURL

from vexcalibur.domain import ComponentIdentity, VulnerabilitySourceInputError
from vexcalibur.sources.osv import (
    OsvClient,
    OsvClientError,
    OsvConfigurationError,
    OsvPackageQuery,
    OsvQueryResult,
    OsvResponseError,
    OsvVulnerabilitySummary,
    findings_from_osv_results,
    osv_client_for_url,
    osv_queries_for_components,
)
from vexcalibur.vex import parse_timestamp


class _ChunkedStream(httpx.SyncByteStream):
    def __init__(self, *chunks: bytes) -> None:
        self._chunks = chunks

    def __iter__(self) -> Iterator[bytes]:
        yield from self._chunks


class _SlowDripStream(httpx.SyncByteStream):
    def __init__(self, content: bytes, *, delay: float) -> None:
        self._content = content
        self._delay = delay
        self.yielded_chunks = 0

    def __iter__(self) -> Iterator[bytes]:
        for byte in self._content:
            time.sleep(self._delay)
            self.yielded_chunks += 1
            yield bytes((byte,))


def test_osv_client_normalizes_base_url_whitespace_and_trailing_slash() -> None:
    client = OsvClient(base_url=" https://osv.example.test/ ")

    assert client.base_url == "https://osv.example.test"


@pytest.mark.parametrize(
    ("base_url", "message"),
    (
        ("api.osv.dev", "absolute https URL"),
        ("//api.osv.dev", "absolute https URL"),
        ("ftp://api.osv.dev", "absolute https URL"),
        ("https://[::1", "absolute https URL"),
        ("https://osv.internal.example:bad", "port"),
        ("https://user@osv.internal.example", "userinfo"),
        ("https://osv.internal.example?debug=true", "params, query, or fragment"),
        ("https://osv.internal.example#fragment", "params, query, or fragment"),
        ("https://osv.internal.example/path;param", "params, query, or fragment"),
        ("http://osv.internal.example", "must use https"),
    ),
)
def test_osv_client_rejects_unsafe_base_urls(base_url: str, message: str) -> None:
    with pytest.raises(OsvConfigurationError, match=message):
        OsvClient(base_url=base_url)


@pytest.mark.parametrize(
    "base_url",
    (
        "http://127.0.0.1:8080/",
        "http://[::1]:8080/",
        "http://localhost:8080/",
    ),
)
def test_osv_client_allows_http_loopback_base_urls(base_url: str) -> None:
    client = OsvClient(base_url=base_url)

    assert client.base_url == base_url.rstrip("/")


def test_osv_client_for_url_rejects_scheme_less_public_osv_url() -> None:
    with pytest.raises(OsvConfigurationError, match="absolute https URL"):
        osv_client_for_url(osv_base_url="api.osv.dev", allow_public_osv=True)


def test_query_sends_purl_to_osv_query_endpoint() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={"vulns": [{"id": "GHSA-test-0002"}]},
        )

    transport = httpx.MockTransport(handler)
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    result = client.query(PackageURL.from_string("pkg:maven/org.example/demo@1.0.0"))

    assert result.purl == "pkg:maven/org.example/demo@1.0.0"
    assert [vuln.id for vuln in result.vulnerabilities] == ["GHSA-test-0002"]
    assert requests[0].url == "https://osv.example.test/v1/query"
    assert requests[0].headers["Accept-Encoding"] == "gzip"
    assert json.loads(requests[0].content) == {
        "package": {
            "purl": "pkg:maven/org.example/demo@1.0.0",
        }
    }


def test_query_sends_top_level_version_when_supplied() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"vulns": []})

    transport = httpx.MockTransport(handler)
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    result = client.query(PackageURL.from_string("pkg:pypi/django"), version="1.2")

    assert result.version == "1.2"
    assert json.loads(requests[0].content) == {
        "package": {
            "purl": "pkg:pypi/django",
        },
        "version": "1.2",
    }


def test_query_follows_next_page_token() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(
                200,
                json={
                    "vulns": [{"id": "GHSA-test-0001"}],
                    "next_page_token": "page-2",
                },
            )
        return httpx.Response(200, json={"vulns": [{"id": "GHSA-test-0002"}]})

    transport = httpx.MockTransport(handler)
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    result = client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))

    assert [vuln.id for vuln in result.vulnerabilities] == [
        "GHSA-test-0001",
        "GHSA-test-0002",
    ]
    assert [request.url for request in requests] == [
        "https://osv.example.test/v1/query",
        "https://osv.example.test/v1/query",
    ]
    assert json.loads(requests[1].content) == {
        "package": {
            "purl": "pkg:pypi/example@1.0.0",
        },
        "page_token": "page-2",
    }


def test_query_rejects_repeated_next_page_token() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={
                "vulns": [],
                "next_page_token": "same-token",
            },
        )
    )
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(OsvResponseError, match="repeated next_page_token"):
        client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))


def test_query_rejects_excessive_pages() -> None:
    token_number = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal token_number
        token_number += 1
        return httpx.Response(
            200,
            json={
                "vulns": [],
                "next_page_token": f"page-{token_number}",
            },
        )

    transport = httpx.MockTransport(handler)
    client = OsvClient(
        base_url="https://osv.example.test",
        max_pages=2,
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(OsvResponseError, match="exceeded pagination limit"):
        client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))


def test_query_batch_maps_results_to_input_purls() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "results": [
                    {"vulns": [{"id": "GHSA-test-0001", "modified": "2026-01-01T00:00:00Z"}]},
                    {},
                ]
            },
        )

    transport = httpx.MockTransport(handler)
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    results = client.query_batch(
        [
            PackageURL.from_string("pkg:pypi/example@1.0.0"),
            PackageURL.from_string("pkg:npm/example@2.0.0"),
        ]
    )

    assert [result.purl for result in results] == [
        "pkg:pypi/example@1.0.0",
        "pkg:npm/example@2.0.0",
    ]
    assert [vuln.id for vuln in results[0].vulnerabilities] == ["GHSA-test-0001"]
    assert results[0].vulnerabilities[0].modified == parse_timestamp("2026-01-01T00:00:00Z")
    assert results[1].vulnerabilities == ()
    assert requests[0].url == "https://osv.example.test/v1/querybatch"
    assert json.loads(requests[0].content) == {
        "queries": [
            {
                "package": {
                    "purl": "pkg:pypi/example@1.0.0",
                }
            },
            {
                "package": {
                    "purl": "pkg:npm/example@2.0.0",
                }
            },
        ]
    }


def test_query_batch_packages_sends_top_level_version_when_supplied() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"results": [{}]})

    transport = httpx.MockTransport(handler)
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    results = client.query_batch_packages(
        [OsvPackageQuery(purl=PackageURL.from_string("pkg:pypi/django"), version="1.2")]
    )

    assert [(result.purl, result.version) for result in results] == [("pkg:pypi/django", "1.2")]
    assert json.loads(requests[0].content) == {
        "queries": [
            {
                "package": {
                    "purl": "pkg:pypi/django",
                },
                "version": "1.2",
            }
        ]
    }


def test_query_batch_follows_next_page_token_for_paginated_results_only() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "vulns": [{"id": "GHSA-test-0001"}],
                            "next_page_token": "first-purl-page-2",
                        },
                        {"vulns": [{"id": "GHSA-test-0003"}]},
                    ]
                },
            )
        return httpx.Response(
            200,
            json={"results": [{"vulns": [{"id": "GHSA-test-0002"}]}]},
        )

    transport = httpx.MockTransport(handler)
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    results = client.query_batch(
        [
            PackageURL.from_string("pkg:pypi/example@1.0.0"),
            PackageURL.from_string("pkg:npm/example@2.0.0"),
        ]
    )

    assert [vuln.id for vuln in results[0].vulnerabilities] == [
        "GHSA-test-0001",
        "GHSA-test-0002",
    ]
    assert [vuln.id for vuln in results[1].vulnerabilities] == ["GHSA-test-0003"]
    assert json.loads(requests[1].content) == {
        "queries": [
            {
                "package": {
                    "purl": "pkg:pypi/example@1.0.0",
                },
                "page_token": "first-purl-page-2",
            }
        ]
    }


def test_query_batch_keeps_first_id_order_and_newest_modified_across_pages() -> None:
    request_number = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_number
        request_number += 1
        if request_number == 1:
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "vulns": [
                                {"id": "CVE-2", "modified": "2026-01-01T00:00:00Z"},
                                {"id": "CVE-1", "modified": "2026-03-01T00:00:00Z"},
                            ],
                            "next_page_token": "page-2",
                        }
                    ]
                },
            )
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "vulns": [
                            {"id": "CVE-2", "modified": "2026-07-01T00:00:00Z"},
                            {"id": "CVE-1", "modified": "2026-02-01T00:00:00Z"},
                        ]
                    }
                ]
            },
        )

    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    result = client.query_batch([PackageURL.from_string("pkg:pypi/example@1.0.0")])[0]

    assert result.vulnerabilities == (
        OsvVulnerabilitySummary(
            id="CVE-2",
            modified=parse_timestamp("2026-07-01T00:00:00Z"),
        ),
        OsvVulnerabilitySummary(
            id="CVE-1",
            modified=parse_timestamp("2026-03-01T00:00:00Z"),
        ),
    )


def test_query_batch_keeps_paginating_each_active_query_until_complete() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "vulns": [{"id": "GHSA-test-0001"}],
                            "next_page_token": "first-page-2",
                        },
                        {
                            "vulns": [{"id": "GHSA-test-0003"}],
                            "next_page_token": "second-page-2",
                        },
                    ]
                },
            )
        if len(requests) == 2:
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"vulns": [{"id": "GHSA-test-0002"}]},
                        {
                            "vulns": [{"id": "GHSA-test-0004"}],
                            "next_page_token": "second-page-3",
                        },
                    ]
                },
            )
        return httpx.Response(
            200,
            json={
                "results": [
                    {"vulns": [{"id": "GHSA-test-0005"}]},
                ]
            },
        )

    transport = httpx.MockTransport(handler)
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    results = client.query_batch(
        [
            PackageURL.from_string("pkg:pypi/example@1.0.0"),
            PackageURL.from_string("pkg:npm/example@2.0.0"),
        ]
    )

    assert [vuln.id for vuln in results[0].vulnerabilities] == [
        "GHSA-test-0001",
        "GHSA-test-0002",
    ]
    assert [vuln.id for vuln in results[1].vulnerabilities] == [
        "GHSA-test-0003",
        "GHSA-test-0004",
        "GHSA-test-0005",
    ]
    assert json.loads(requests[1].content) == {
        "queries": [
            {
                "package": {
                    "purl": "pkg:pypi/example@1.0.0",
                },
                "page_token": "first-page-2",
            },
            {
                "package": {
                    "purl": "pkg:npm/example@2.0.0",
                },
                "page_token": "second-page-2",
            },
        ]
    }
    assert json.loads(requests[2].content) == {
        "queries": [
            {
                "package": {
                    "purl": "pkg:npm/example@2.0.0",
                },
                "page_token": "second-page-3",
            },
        ]
    }


def test_query_batch_rejects_repeated_next_page_token() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={"results": [{"vulns": [], "next_page_token": "same-token"}]},
        )
    )
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(OsvResponseError, match="repeated next_page_token"):
        client.query_batch([PackageURL.from_string("pkg:pypi/example@1.0.0")])


def test_query_batch_rejects_excessive_pages() -> None:
    token_number = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal token_number
        token_number += 1
        return httpx.Response(
            200,
            json={"results": [{"vulns": [], "next_page_token": f"page-{token_number}"}]},
        )

    transport = httpx.MockTransport(handler)
    client = OsvClient(
        base_url="https://osv.example.test",
        max_pages=2,
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(OsvResponseError, match="exceeded pagination limit"):
        client.query_batch([PackageURL.from_string("pkg:pypi/example@1.0.0")])


def test_client_rejects_invalid_max_pages() -> None:
    with pytest.raises(ValueError, match="max_pages"):
        OsvClient(max_pages=0)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    (
        ({"timeout": float("nan")}, "timeout"),
        ({"operation_timeout": float("inf")}, "operation_timeout"),
        ({"max_response_bytes": 0}, "max_response_bytes"),
        (
            {"max_response_bytes": 2, "max_total_response_bytes": 1},
            "max_total_response_bytes",
        ),
        ({"max_encoded_response_bytes": 0}, "max_encoded_response_bytes"),
        (
            {
                "max_encoded_response_bytes": 2,
                "max_total_encoded_response_bytes": 1,
            },
            "max_total_encoded_response_bytes",
        ),
        ({"max_queries": 0}, "max_queries"),
        ({"max_vulnerabilities_per_query": 0}, "max_vulnerabilities_per_query"),
        ({"max_total_vulnerabilities": 0}, "max_total_vulnerabilities"),
        ({"max_page_token_length": 0}, "max_page_token_length"),
        ({"max_vulnerability_id_length": 0}, "max_vulnerability_id_length"),
    ),
)
def test_client_rejects_invalid_resource_limits(
    kwargs: dict[str, float | int],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        OsvClient(**kwargs)


def test_query_batch_with_no_purls_does_not_call_osv() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        pytest.fail(f"unexpected OSV request: {request.url}")

    transport = httpx.MockTransport(handler)
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    assert client.query_batch([]) == []


def test_get_vulnerability_fetches_full_payload() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "id": "GHSA-test-0003",
                "summary": "Example vulnerability",
                "affected": [],
            },
        )

    transport = httpx.MockTransport(handler)
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    vulnerability = client.get_vulnerability("GHSA-test-0003")

    assert vulnerability.id == "GHSA-test-0003"
    assert vulnerability.raw["summary"] == "Example vulnerability"
    assert requests[0].url == "https://osv.example.test/v1/vulns/GHSA-test-0003"
    assert requests[0].content == b""


def test_get_vulnerability_encodes_id_as_path_segment() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"id": "GHSA-test/slash"})

    transport = httpx.MockTransport(handler)
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    vulnerability = client.get_vulnerability("GHSA-test/slash")

    assert vulnerability.id == "GHSA-test/slash"
    assert requests[0].url == "https://osv.example.test/v1/vulns/GHSA-test%2Fslash"


def test_query_rejects_non_list_vulns_field() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"vulns": {}}))
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(OsvResponseError, match="must be a list"):
        client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))


def test_query_batch_rejects_non_list_results_field() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"results": {}}))
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(OsvResponseError, match=r"results.*must be a list"):
        client.query_batch([PackageURL.from_string("pkg:pypi/example@1.0.0")])


def test_query_batch_rejects_non_object_result_entries() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"results": ["bad"]}))
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(OsvResponseError, match="result entries must be objects"):
        client.query_batch([PackageURL.from_string("pkg:pypi/example@1.0.0")])


def test_query_rejects_non_object_vulnerability_entries() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"vulns": ["bad"]}))
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(OsvResponseError, match="vulnerability entries must be objects"):
        client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))


def test_query_batch_rejects_result_count_mismatch() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"results": [{}]}))
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(OsvResponseError, match="response count must match request count"):
        client.query_batch(
            [
                PackageURL.from_string("pkg:pypi/example@1.0.0"),
                PackageURL.from_string("pkg:npm/example@2.0.0"),
            ]
        )


def test_query_rejects_missing_vulnerability_id() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"vulns": [{}]}))
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(OsvResponseError, match=r"id.*non-empty string"):
        client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))


def test_query_rejects_non_string_modified_timestamp() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={"vulns": [{"id": "GHSA-test-0001", "modified": 123}]},
        )
    )
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(OsvResponseError, match=r"modified.*non-empty string"):
        client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))


def test_query_rejects_invalid_modified_timestamp() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={"vulns": [{"id": "GHSA-test-0001", "modified": "not-a-timestamp"}]},
        )
    )
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(OsvResponseError, match=r"modified.*ISO-8601 timestamp"):
        client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))


def test_get_vulnerability_rejects_non_string_id() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"id": 123}))
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(OsvResponseError, match=r"id.*non-empty string"):
        client.get_vulnerability("GHSA-test-0001")


def test_query_rejects_invalid_json_response() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=b"not json"))
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(OsvResponseError, match="must be JSON"):
        client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))


@pytest.mark.parametrize(
    ("document", "message"),
    (
        (b'{"vulns":[],"vulns":[]}', "duplicate JSON object keys"),
        (
            b'{"vulns":[{"id":"GHSA-test-0001","id":"GHSA-test-0002"}]}',
            "duplicate JSON object keys",
        ),
        (b'{"extra":' + b"[" * 2_000 + b"]" * 2_000 + b"}", "too deeply nested"),
        (b'{"extra":' + b"1" * 1_001 + b"}", "oversized JSON integer"),
        (b"\xff", "UTF-8 JSON"),
    ),
)
def test_query_normalizes_strict_json_failures(document: bytes, message: str) -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=document))
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(OsvResponseError, match=message):
        client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))


def test_osv_queries_defensively_reject_conflicting_component_versions() -> None:
    component = ComponentIdentity(
        ref="component:demo",
        name="demo",
        version="1.0",
        purl=PackageURL.from_string("pkg:pypi/demo@1.0"),
    )
    object.__setattr__(component, "version", "2.0")

    with pytest.raises(VulnerabilitySourceInputError, match="conflicting version identity"):
        osv_queries_for_components((component,))


def test_query_wraps_http_errors() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, request=request)

    transport = httpx.MockTransport(handler)
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(OsvClientError, match="HTTP 503"):
        client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))


def test_query_never_follows_redirects_from_injected_client() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.host != "osv.example.test":
            raise AssertionError("private OSV query body was forwarded across a redirect")
        return httpx.Response(
            307,
            headers={"Location": "https://collector.example.test/capture"},
            content=b"redirecting",
        )

    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(
            transport=httpx.MockTransport(handler),
            follow_redirects=True,
        ),
    )

    with pytest.raises(OsvClientError, match="HTTP 307"):
        client.query(PackageURL.from_string("pkg:pypi/private-package@1.0.0"))

    assert len(requests) == 1
    assert b"private-package" in requests[0].content


def test_query_applies_response_budget_to_redirect_body() -> None:
    stream = _ChunkedStream(b"x" * 17)
    client = OsvClient(
        base_url="https://osv.example.test",
        max_response_bytes=16,
        max_total_response_bytes=16,
        max_encoded_response_bytes=16,
        max_total_encoded_response_bytes=16,
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    307,
                    headers={"Location": "https://collector.example.test/capture"},
                    stream=stream,
                )
            ),
            follow_redirects=True,
        ),
    )

    with pytest.raises(OsvResponseError, match=r"encoded response exceeds.*byte limit"):
        client.query(PackageURL.from_string("pkg:pypi/private-package@1.0.0"))


def test_query_accepts_response_at_exact_decoded_byte_limit() -> None:
    body = b'{"vulns":[]}'
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=body))
    client = OsvClient(
        base_url="https://osv.example.test",
        max_response_bytes=len(body),
        max_total_response_bytes=len(body),
        client=httpx.Client(transport=transport),
    )

    result = client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))

    assert result.vulnerabilities == ()


def test_query_rejects_response_at_decoded_byte_limit_plus_one() -> None:
    body = b'{"vulns":[]}'
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=body))
    client = OsvClient(
        base_url="https://osv.example.test",
        max_response_bytes=len(body) - 1,
        max_total_response_bytes=len(body) - 1,
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(OsvResponseError, match=r"response exceeds.*byte limit"):
        client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))


def test_query_rejects_oversized_declared_content_length_before_streaming() -> None:
    class UnreadableStream(httpx.SyncByteStream):
        def __iter__(self) -> Iterator[bytes]:
            raise AssertionError("oversized declared response should not be read")

    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            headers={"Content-Length": "101"},
            stream=UnreadableStream(),
        )
    )
    client = OsvClient(
        base_url="https://osv.example.test",
        max_response_bytes=100,
        max_total_response_bytes=100,
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(OsvResponseError, match=r"response exceeds.*100 byte limit"):
        client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))


@pytest.mark.parametrize("subtract_byte", (0, 1))
def test_query_counts_actual_decoded_bytes_for_compressed_response(subtract_byte: int) -> None:
    body = b'{"vulns":[],"padding":"' + (b"x" * 1_000) + b'"}'
    compressed = gzip.compress(body)
    assert len(compressed) < len(body)
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            headers={
                "Content-Encoding": "gzip",
                "Content-Length": str(len(compressed)),
            },
            stream=_ChunkedStream(compressed),
        )
    )
    client = OsvClient(
        base_url="https://osv.example.test",
        max_response_bytes=len(body) - subtract_byte,
        max_total_response_bytes=len(body) - subtract_byte,
        client=httpx.Client(transport=transport),
    )

    if subtract_byte:
        with pytest.raises(OsvResponseError, match=r"response exceeds.*byte limit"):
            client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))
    else:
        assert client.query(PackageURL.from_string("pkg:pypi/example@1.0.0")).vulnerabilities == ()


def test_query_treats_compressed_content_length_as_encoded_bytes() -> None:
    body = b'{"vulns":[]}'
    compressed = gzip.compress(body)
    assert len(compressed) > len(body)
    client = OsvClient(
        base_url="https://osv.example.test",
        max_response_bytes=len(body),
        max_total_response_bytes=len(body),
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200,
                    headers={
                        "Content-Encoding": "gzip",
                        "Content-Length": str(len(compressed)),
                    },
                    stream=_ChunkedStream(compressed),
                )
            )
        ),
    )

    assert client.query(PackageURL.from_string("pkg:pypi/example@1.0.0")).vulnerabilities == ()


def test_query_bounds_encoded_response_independently_of_decoded_response() -> None:
    body = b'{"vulns":[]}'
    compressed = gzip.compress(body)
    client = OsvClient(
        base_url="https://osv.example.test",
        max_response_bytes=len(body),
        max_total_response_bytes=len(body),
        max_encoded_response_bytes=len(compressed) - 1,
        max_total_encoded_response_bytes=len(compressed) - 1,
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200,
                    headers={"Content-Encoding": "gzip"},
                    stream=_ChunkedStream(compressed[:5], compressed[5:]),
                )
            )
        ),
    )

    with pytest.raises(OsvResponseError, match=r"encoded response exceeds.*byte limit"):
        client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))


def test_query_stops_gzip_expansion_at_decoded_byte_limit() -> None:
    body = b'{"vulns":[],"padding":"' + (b"x" * (2 * 1024 * 1024)) + b'"}'
    compressed = gzip.compress(body)
    assert len(compressed) < 4_096
    client = OsvClient(
        base_url="https://osv.example.test",
        max_response_bytes=1_024,
        max_total_response_bytes=1_024,
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200,
                    headers={"Content-Encoding": "gzip"},
                    stream=_ChunkedStream(compressed),
                )
            )
        ),
    )

    with pytest.raises(OsvResponseError, match=r"decoded response exceeds.*byte limit"):
        client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))


@pytest.mark.parametrize("content_encoding", ("identity", "gzip"))
def test_query_deadline_cannot_be_bypassed_by_slow_drip_stream(
    content_encoding: str,
) -> None:
    body = (
        b'{"vulns":[],"padding":"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"}'
    )
    encoded = gzip.compress(body) if content_encoding == "gzip" else body
    stream = _SlowDripStream(encoded, delay=0.01)
    headers = {"Content-Encoding": "gzip"} if content_encoding == "gzip" else {}
    client = OsvClient(
        base_url="https://osv.example.test",
        timeout=1.0,
        operation_timeout=0.025,
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, headers=headers, stream=stream)
            )
        ),
    )

    with pytest.raises(OsvClientError, match="overall deadline"):
        client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))

    assert stream.yielded_chunks < len(encoded)


@pytest.mark.parametrize(
    ("headers", "body", "message"),
    (
        ({"Content-Encoding": "br"}, b"not-brotli", "unsupported Content-Encoding"),
        (
            {"Content-Encoding": "gzip"},
            gzip.compress(b'{"vulns":[]}')[:-2],
            "truncated gzip",
        ),
    ),
)
def test_query_rejects_unsupported_or_truncated_content_encoding(
    headers: dict[str, str],
    body: bytes,
    message: str,
) -> None:
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200,
                    headers=headers,
                    stream=_ChunkedStream(body),
                )
            )
        ),
    )

    with pytest.raises(OsvResponseError, match=message):
        client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))


@pytest.mark.parametrize("extra_byte", (0, 1))
def test_query_counts_chunked_response_bytes(extra_byte: int) -> None:
    body = b'{"vulns":[]}'
    stream = _ChunkedStream(body[:5], body[5:])
    transport = httpx.MockTransport(lambda request: httpx.Response(200, stream=stream))
    limit = len(body) - extra_byte
    client = OsvClient(
        base_url="https://osv.example.test",
        max_response_bytes=limit,
        max_total_response_bytes=limit,
        client=httpx.Client(transport=transport),
    )

    if extra_byte:
        with pytest.raises(OsvResponseError, match=r"response exceeds.*byte limit"):
            client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))
    else:
        assert client.query(PackageURL.from_string("pkg:pypi/example@1.0.0")).vulnerabilities == ()


def test_query_streams_error_body_under_the_same_byte_limit() -> None:
    body = b"service unavailable"

    def response_client(max_response_bytes: int) -> OsvClient:
        transport = httpx.MockTransport(lambda request: httpx.Response(503, content=body))
        return OsvClient(
            base_url="https://osv.example.test",
            max_response_bytes=max_response_bytes,
            max_total_response_bytes=max_response_bytes,
            client=httpx.Client(transport=transport),
        )

    with pytest.raises(OsvClientError, match="HTTP 503"):
        response_client(len(body)).query(PackageURL.from_string("pkg:pypi/example@1.0.0"))
    with pytest.raises(OsvResponseError, match=r"response exceeds.*byte limit"):
        response_client(len(body) - 1).query(PackageURL.from_string("pkg:pypi/example@1.0.0"))


@pytest.mark.parametrize("subtract_byte", (0, 1))
def test_query_applies_cumulative_response_byte_budget(subtract_byte: int) -> None:
    bodies = [
        b'{"vulns":[],"next_page_token":"page-2"}',
        b'{"vulns":[]}',
    ]
    response_number = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal response_number
        body = bodies[response_number]
        response_number += 1
        return httpx.Response(200, content=body)

    total_limit = sum(map(len, bodies)) - subtract_byte
    client = OsvClient(
        base_url="https://osv.example.test",
        max_response_bytes=max(map(len, bodies)),
        max_total_response_bytes=total_limit,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    if subtract_byte:
        with pytest.raises(OsvResponseError, match=r"cumulative.*byte limit"):
            client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))
    else:
        assert client.query(PackageURL.from_string("pkg:pypi/example@1.0.0")).vulnerabilities == ()


@pytest.mark.parametrize("subtract_byte", (0, 1))
def test_query_applies_cumulative_encoded_response_budget(subtract_byte: int) -> None:
    decoded_bodies = [
        b'{"vulns":[],"next_page_token":"page-2"}',
        b'{"vulns":[]}',
    ]
    encoded_bodies = [gzip.compress(body) for body in decoded_bodies]
    response_number = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal response_number
        body = encoded_bodies[response_number]
        response_number += 1
        return httpx.Response(
            200,
            headers={"Content-Encoding": "gzip"},
            stream=_ChunkedStream(body),
        )

    total_encoded_limit = sum(map(len, encoded_bodies)) - subtract_byte
    client = OsvClient(
        base_url="https://osv.example.test",
        max_response_bytes=max(map(len, decoded_bodies)),
        max_total_response_bytes=sum(map(len, decoded_bodies)),
        max_encoded_response_bytes=max(map(len, encoded_bodies)),
        max_total_encoded_response_bytes=total_encoded_limit,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    if subtract_byte:
        with pytest.raises(OsvResponseError, match=r"encoded.*cumulative.*byte limit"):
            client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))
    else:
        assert client.query(PackageURL.from_string("pkg:pypi/example@1.0.0")).vulnerabilities == ()


def test_query_applies_overall_operation_deadline(monkeypatch) -> None:
    now = 0.0

    def monotonic() -> float:
        return now

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal now
        now = 2.0
        return httpx.Response(200, content=b'{"vulns":[]}')

    monkeypatch.setattr("vexcalibur.sources.osv.time.monotonic", monotonic)
    client = OsvClient(
        base_url="https://osv.example.test",
        operation_timeout=1.0,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    with pytest.raises(OsvClientError, match="overall deadline"):
        client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))


def test_query_batch_chunks_official_maximum_and_preserves_indices() -> None:
    request_sizes: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        query_count = len(json.loads(request.content)["queries"])
        request_sizes.append(query_count)
        return httpx.Response(200, json={"results": [{} for _ in range(query_count)]})

    purls = [PackageURL.from_string(f"pkg:pypi/example-{index}@1.0") for index in range(1_001)]
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    results = client.query_batch(purls)

    assert request_sizes == [1_000, 1]
    assert [result.purl for result in results] == [purl.to_string() for purl in purls]


@pytest.mark.parametrize("query_count", (2, 3))
def test_query_batch_bounds_total_queries(query_count: int) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        queries = json.loads(request.content)["queries"]
        return httpx.Response(200, json={"results": [{} for _ in queries]})

    purls = [
        PackageURL.from_string(f"pkg:pypi/example-{index}@1.0") for index in range(query_count)
    ]
    client = OsvClient(
        base_url="https://osv.example.test",
        max_queries=2,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    if query_count == 3:
        with pytest.raises(OsvResponseError, match="more than 2 queries"):
            client.query_batch(purls)
    else:
        assert len(client.query_batch(purls)) == 2


@pytest.mark.parametrize("token_length", (5, 6))
def test_query_bounds_page_token_length(token_length: int) -> None:
    request_number = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_number
        request_number += 1
        if request_number == 1:
            return httpx.Response(
                200,
                json={"vulns": [], "next_page_token": "x" * token_length},
            )
        return httpx.Response(200, json={"vulns": []})

    client = OsvClient(
        base_url="https://osv.example.test",
        max_page_token_length=5,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    if token_length == 6:
        with pytest.raises(OsvResponseError, match=r"next_page_token.*5 character limit"):
            client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))
    else:
        assert client.query(PackageURL.from_string("pkg:pypi/example@1.0.0")).vulnerabilities == ()


def test_query_deduplicates_canonical_ids_and_keeps_newest_modified() -> None:
    request_number = 0
    decomposed_id = "GHSA-cafe\u0301"
    canonical_id = unicodedata.normalize("NFC", decomposed_id)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_number
        request_number += 1
        if request_number == 1:
            return httpx.Response(
                200,
                json={
                    "vulns": [
                        {"id": decomposed_id, "modified": "2026-01-01T00:00:00Z"},
                        {"id": decomposed_id},
                    ],
                    "next_page_token": "page-2",
                },
            )
        return httpx.Response(
            200,
            json={
                "vulns": [
                    {"id": canonical_id, "modified": "2026-01-02T00:00:00Z"},
                    {"id": "[bold]漏洞[/bold]"},
                ]
            },
        )

    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    result = client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))

    assert result.vulnerabilities == (
        OsvVulnerabilitySummary(
            id=canonical_id,
            modified=parse_timestamp("2026-01-02T00:00:00Z"),
        ),
        OsvVulnerabilitySummary(id="[bold]漏洞[/bold]"),
    )


@pytest.mark.parametrize("unsafe_id", ("CVE-1\nspoof", "CVE-1\u2028spoof", "CVE-1\u202espoof"))
def test_query_rejects_output_unsafe_vulnerability_ids(unsafe_id: str) -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"vulns": [{"id": unsafe_id}]})
    )
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(OsvResponseError, match=r"control.*line-separator"):
        client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))


@pytest.mark.parametrize("id_length", (5, 6))
def test_query_bounds_vulnerability_id_length(id_length: int) -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"vulns": [{"id": "x" * id_length}]})
    )
    client = OsvClient(
        base_url="https://osv.example.test",
        max_vulnerability_id_length=5,
        client=httpx.Client(transport=transport),
    )

    if id_length == 6:
        with pytest.raises(OsvResponseError, match=r"id.*5 character limit"):
            client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))
    else:
        assert [
            vulnerability.id
            for vulnerability in client.query(
                PackageURL.from_string("pkg:pypi/example@1.0.0")
            ).vulnerabilities
        ] == ["xxxxx"]


def test_query_normalizes_vulnerability_id_before_length_check() -> None:
    decomposed_id = "xxxxe\u0301"
    canonical_id = unicodedata.normalize("NFC", decomposed_id)
    assert len(decomposed_id) == 6
    assert len(canonical_id) == 5
    client = OsvClient(
        base_url="https://osv.example.test",
        max_vulnerability_id_length=5,
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"vulns": [{"id": decomposed_id}]})
            )
        ),
    )

    result = client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))

    assert [vulnerability.id for vulnerability in result.vulnerabilities] == [canonical_id]


@pytest.mark.parametrize("vulnerability_count", (2, 3))
def test_query_bounds_unique_vulnerabilities_per_query(vulnerability_count: int) -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={"vulns": [{"id": f"CVE-{index}"} for index in range(vulnerability_count)]},
        )
    )
    client = OsvClient(
        base_url="https://osv.example.test",
        max_vulnerabilities_per_query=2,
        max_total_vulnerabilities=2,
        client=httpx.Client(transport=transport),
    )

    if vulnerability_count == 3:
        with pytest.raises(OsvResponseError, match="more than 2 unique vulnerabilities"):
            client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))
    else:
        assert (
            len(client.query(PackageURL.from_string("pkg:pypi/example@1.0.0")).vulnerabilities) == 2
        )


@pytest.mark.parametrize("max_total", (2, 1))
def test_query_batch_bounds_total_query_vulnerability_results(max_total: int) -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            json={
                "results": [
                    {"vulns": [{"id": "CVE-1"}]},
                    {"vulns": [{"id": "CVE-2"}]},
                ]
            },
        )
    )
    client = OsvClient(
        base_url="https://osv.example.test",
        max_total_vulnerabilities=max_total,
        client=httpx.Client(transport=transport),
    )
    purls = [
        PackageURL.from_string("pkg:pypi/first@1.0"),
        PackageURL.from_string("pkg:pypi/second@1.0"),
    ]

    if max_total == 1:
        with pytest.raises(OsvResponseError, match="more than 1 query-vulnerability"):
            client.query_batch(purls)
    else:
        assert sum(len(result.vulnerabilities) for result in client.query_batch(purls)) == 2


def test_findings_deduplicate_before_relation_limit_and_materialization() -> None:
    purl = PackageURL.from_string("pkg:pypi/example@1.0")
    components = (
        ComponentIdentity(ref="component:first", name="example", version="1.0", purl=purl),
        ComponentIdentity(ref="component:second", name="example", version="1.0", purl=purl),
    )
    results = [
        OsvQueryResult(
            purl=purl.to_string(),
            vulnerabilities=(
                OsvVulnerabilitySummary(id="CVE-1"),
                OsvVulnerabilitySummary(id="CVE-1"),
                OsvVulnerabilitySummary(id="CVE-2"),
            ),
        )
    ]

    findings = findings_from_osv_results(
        components=components,
        results=results,
        source_name="Unit Test Feed",
        source_url="https://security.example.test/feed",
        analysis_detail="Detected by the unit-test feed.",
        max_findings=4,
    )

    assert [(finding.id, finding.component_ref) for finding in findings] == [
        ("CVE-1", "component:first"),
        ("CVE-1", "component:second"),
        ("CVE-2", "component:first"),
        ("CVE-2", "component:second"),
    ]
    with pytest.raises(OsvResponseError, match=r"relation count.*3 finding limit"):
        findings_from_osv_results(
            components=components,
            results=results,
            source_name="Unit Test Feed",
            source_url="https://security.example.test/feed",
            analysis_detail="Detected by the unit-test feed.",
            max_findings=3,
        )


def test_findings_deduplicate_results_with_newest_modified_timestamp() -> None:
    purl = PackageURL.from_string("pkg:pypi/example@1.0")
    component = ComponentIdentity(
        ref="component:example",
        name="example",
        version="1.0",
        purl=purl,
    )
    results = [
        OsvQueryResult(
            purl=purl.to_string(),
            vulnerabilities=(
                OsvVulnerabilitySummary(
                    id="CVE-1",
                    modified=parse_timestamp("2026-01-01T00:00:00Z"),
                ),
            ),
        ),
        OsvQueryResult(
            purl=purl.to_string(),
            vulnerabilities=(
                OsvVulnerabilitySummary(
                    id="CVE-1",
                    modified=parse_timestamp("2026-07-01T00:00:00Z"),
                ),
            ),
        ),
    ]

    findings = findings_from_osv_results(
        components=(component,),
        results=results,
        source_name="Unit Test Feed",
        source_url="https://security.example.test/feed",
        analysis_detail="Detected by the unit-test feed.",
    )

    assert len(findings) == 1
    assert findings[0].modified == parse_timestamp("2026-07-01T00:00:00Z")


@pytest.mark.live
def test_live_osv_query_batch_shape() -> None:
    results = OsvClient().query_batch([PackageURL.from_string("pkg:pypi/django@1.2")])

    assert len(results) == 1
    assert results[0].purl == "pkg:pypi/django@1.2"
    assert isinstance(results[0].vulnerabilities, tuple)
