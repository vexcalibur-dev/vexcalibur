import httpx
import pytest
from packageurl import PackageURL

from vexcalibur.sources.osv import OsvClient, OsvResponseError


def _query_vulnerability_id(vulnerability_id: str) -> str:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"vulns": [{"id": vulnerability_id}]})
    )
    client = OsvClient(
        base_url="https://osv.example.test",
        client=httpx.Client(transport=transport),
    )
    result = client.query(PackageURL.from_string("pkg:pypi/example@1.0.0"))
    return result.vulnerabilities[0].id


@pytest.mark.parametrize(
    "unsafe_id",
    (
        "CVE-2026-0001\rspoofed",
        "CVE-2026-0001\x1b[31m",
        "CVE-2026-0001\x85spoofed",
        "CVE-2026-0001\u2029spoofed",
        "CVE-2026-0001\n::error::forged workflow annotation",
    ),
    ids=("carriage-return", "escape", "c1-control", "paragraph-separator", "workflow-command"),
)
def test_issue_63_rejects_terminal_and_workflow_control_sequences(unsafe_id: str) -> None:
    with pytest.raises(OsvResponseError, match=r"control.*line-separator"):
        _query_vulnerability_id(unsafe_id)


def test_issue_63_allows_ordinary_rich_markup_text() -> None:
    vulnerability_id = "[link=https://security.example.test]GHSA-test-0001[/link]"

    assert _query_vulnerability_id(vulnerability_id) == vulnerability_id
