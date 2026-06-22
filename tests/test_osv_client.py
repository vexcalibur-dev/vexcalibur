import json

import httpx
import pytest
from packageurl import PackageURL

from vexcalibur.sources.osv import OsvClient


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

    with pytest.raises(TypeError, match="must be a list"):
        client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))


def test_query_batch_rejects_non_list_results_field() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"results": {}}))
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(TypeError, match=r"results.*must be a list"):
        client.query_batch([PackageURL.from_string("pkg:pypi/example@1.0.0")])


def test_query_batch_rejects_non_object_result_entries() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"results": ["bad"]}))
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(TypeError, match="result entries must be objects"):
        client.query_batch([PackageURL.from_string("pkg:pypi/example@1.0.0")])


def test_query_rejects_non_object_vulnerability_entries() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"vulns": ["bad"]}))
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )

    with pytest.raises(TypeError, match="vulnerability entries must be objects"):
        client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))


@pytest.mark.live
def test_live_osv_query_batch_shape() -> None:
    results = OsvClient().query_batch([PackageURL.from_string("pkg:pypi/django@1.2")])

    assert len(results) == 1
    assert results[0].purl == "pkg:pypi/django@1.2"
    assert isinstance(results[0].vulnerabilities, tuple)
