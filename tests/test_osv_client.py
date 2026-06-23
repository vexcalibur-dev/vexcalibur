import json

import httpx
import pytest
from packageurl import PackageURL

from vexcalibur.sources.osv import OsvClient, OsvClientError, OsvResponseError


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
    assert json.loads(requests[0].content) == {
        "package": {
            "purl": "pkg:maven/org.example/demo@1.0.0",
        }
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


def test_query_batch_keeps_paginating_each_active_query_until_complete() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        match len(requests):
            case 1:
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
            case 2:
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
            case _:
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


@pytest.mark.live
def test_live_osv_query_batch_shape() -> None:
    results = OsvClient().query_batch([PackageURL.from_string("pkg:pypi/django@1.2")])

    assert len(results) == 1
    assert results[0].purl == "pkg:pypi/django@1.2"
    assert isinstance(results[0].vulnerabilities, tuple)
