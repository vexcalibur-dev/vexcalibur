import subprocess

import httpx
import pytest

import vexcalibur.github_sbom as github_sbom_module
from vexcalibur.github_sbom import (
    GITHUB_API_VERSION,
    GithubSbomClient,
    GithubSbomClientError,
    GithubSbomConfigurationError,
    component_identities_from_github_spdx_sbom,
    normalize_github_api_url,
    parse_github_repository,
    resolve_github_token,
)
from vexcalibur.sbom import MAX_SBOM_BYTES


def test_parse_github_repository_accepts_owner_repo() -> None:
    repository = parse_github_repository(" vexcalibur-dev/vexcalibur.git ")

    assert repository.owner == "vexcalibur-dev"
    assert repository.repo == "vexcalibur"
    assert repository.full_name == "vexcalibur-dev/vexcalibur"


@pytest.mark.parametrize("value", ("", "owner", "/repo", "owner/", "owner/repo/extra", "../repo"))
def test_parse_github_repository_rejects_invalid_values(value: str) -> None:
    with pytest.raises(GithubSbomConfigurationError, match="--github-repo"):
        parse_github_repository(value)


def test_normalize_github_api_url_rejects_cleartext_urls() -> None:
    with pytest.raises(GithubSbomConfigurationError, match="HTTPS"):
        normalize_github_api_url("http://github.example/api/v3")


def test_normalize_github_api_url_rejects_userinfo() -> None:
    with pytest.raises(GithubSbomConfigurationError, match="userinfo"):
        normalize_github_api_url("https://api.github.com@collector.example/api/v3")


def test_resolve_github_token_prefers_explicit_env() -> None:
    token = resolve_github_token(
        token_env="VEXCALIBUR_GITHUB_TOKEN",  # noqa: S106
        allow_gh_cli=False,
        environ={"VEXCALIBUR_GITHUB_TOKEN": " token-value "},
    )

    assert token == "token-value"  # noqa: S105


def test_resolve_github_token_rejects_missing_explicit_env() -> None:
    with pytest.raises(GithubSbomConfigurationError, match="VEXCALIBUR_GITHUB_TOKEN"):
        resolve_github_token(
            token_env="VEXCALIBUR_GITHUB_TOKEN",  # noqa: S106
            allow_gh_cli=False,
            environ={},
        )


def test_resolve_github_token_uses_standard_env() -> None:
    assert (
        resolve_github_token(
            allow_gh_cli=False,
            environ={"GH_TOKEN": "gh-token", "GITHUB_TOKEN": "github-token"},
        )
        == "gh-token"
    )


def test_resolve_github_token_uses_enterprise_env_for_enterprise_api() -> None:
    assert (
        resolve_github_token(
            api_url="https://github.example.test/api/v3",
            allow_gh_cli=False,
            environ={"GH_ENTERPRISE_TOKEN": "enterprise-token", "GH_TOKEN": "gh-token"},
        )
        == "enterprise-token"
    )


def test_resolve_github_token_does_not_send_generic_token_to_enterprise_api() -> None:
    assert (
        resolve_github_token(
            api_url="https://github.example.test/api/v3",
            allow_gh_cli=False,
            environ={"GH_TOKEN": "gh-token", "GITHUB_TOKEN": "github-token"},
        )
        is None
    )


def test_resolve_github_token_uses_hostname_without_port_for_default_github() -> None:
    assert (
        resolve_github_token(
            api_url="https://api.github.com:443",
            allow_gh_cli=False,
            environ={"GH_TOKEN": "gh-token"},
        )
        == "gh-token"
    )


def test_resolve_github_token_falls_back_to_gh_auth_token(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_args: list[list[str]] = []

    def fake_run(args: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
        captured_args.append(args)
        return subprocess.CompletedProcess(args=args, returncode=0, stdout=" gh-token\n")

    monkeypatch.setattr(github_sbom_module.subprocess, "run", fake_run)

    token = resolve_github_token(allow_gh_cli=True, environ={})

    assert token == "gh-token"  # noqa: S105
    assert captured_args == [["gh", "auth", "token", "--hostname", "github.com"]]


def test_resolve_github_token_returns_none_without_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(args: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=args, returncode=1, stdout="")

    monkeypatch.setattr(github_sbom_module.subprocess, "run", fake_run)

    assert resolve_github_token(allow_gh_cli=True, environ={}) is None


def test_component_identities_from_github_spdx_sbom_extracts_package_purls() -> None:
    components = component_identities_from_github_spdx_sbom(
        {
            "sbom": {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {
                        "SPDXID": "SPDXRef-pypi-django-1.2",
                        "name": "django",
                        "versionInfo": "1.2",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:pypi/django@1.2",
                            }
                        ],
                    },
                    {
                        "SPDXID": "SPDXRef-npm-minimist-0.0.8",
                        "name": "minimist",
                        "versionInfo": "0.0.8",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:npm/minimist@0.0.8",
                            }
                        ],
                    },
                    {
                        "SPDXID": "SPDXRef-Repository",
                        "name": "vexcalibur-dev/vexcalibur",
                        "versionInfo": "main",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:github/vexcalibur-dev/vexcalibur@main",
                            }
                        ],
                    },
                ],
            }
        },
        source="vexcalibur-dev/vexcalibur",
    )

    assert [
        (component.ref, component.name, component.version, component.purl.to_string())
        for component in components
    ] == [
        (
            "SPDXRef-npm-minimist-0.0.8",
            "minimist",
            "0.0.8",
            "pkg:npm/minimist@0.0.8",
        ),
        ("SPDXRef-pypi-django-1.2", "django", "1.2", "pkg:pypi/django@1.2"),
    ]


def test_component_identities_from_github_spdx_sbom_skips_described_repository_package() -> None:
    components = component_identities_from_github_spdx_sbom(
        {
            "sbom": {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {
                        "SPDXID": "SPDXRef-github-vexcalibur-dev-vexcalibur-main",
                        "name": "vexcalibur-dev/vexcalibur",
                        "versionInfo": "main",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:github/vexcalibur-dev/vexcalibur@main",
                            }
                        ],
                    },
                    {
                        "SPDXID": "SPDXRef-pypi-django-1.2",
                        "name": "django",
                        "versionInfo": "1.2",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:pypi/django@1.2",
                            }
                        ],
                    },
                ],
                "relationships": [
                    {
                        "spdxElementId": "SPDXRef-DOCUMENT",
                        "relationshipType": "DESCRIBES",
                        "relatedSpdxElement": "SPDXRef-github-vexcalibur-dev-vexcalibur-main",
                    }
                ],
            }
        },
        source="vexcalibur-dev/vexcalibur",
    )

    assert [(component.ref, component.purl.to_string()) for component in components] == [
        ("SPDXRef-pypi-django-1.2", "pkg:pypi/django@1.2")
    ]


def test_component_identities_from_github_spdx_sbom_uses_version_info_fallback() -> None:
    components = component_identities_from_github_spdx_sbom(
        {
            "sbom": {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {
                        "SPDXID": "SPDXRef-pypi-django",
                        "name": "django",
                        "versionInfo": "1.2",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:pypi/django",
                            }
                        ],
                    }
                ],
            }
        },
        source="vexcalibur-dev/vexcalibur",
    )

    assert [(component.purl.to_string(), component.version) for component in components] == [
        ("pkg:pypi/django", "1.2")
    ]


def test_component_identities_from_github_spdx_sbom_ignores_packages_without_purls() -> None:
    components = component_identities_from_github_spdx_sbom(
        {
            "sbom": {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {
                        "SPDXID": "SPDXRef-no-purl",
                        "name": "no-purl",
                        "externalRefs": [],
                    }
                ],
            }
        },
        source="vexcalibur-dev/vexcalibur",
    )

    assert components == ()


def test_component_identities_from_github_spdx_sbom_rejects_duplicate_refs() -> None:
    raw_response = {
        "sbom": {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "SPDXID": "SPDXRef-duplicate",
                    "name": "django",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/django@1.2",
                        }
                    ],
                },
                {
                    "SPDXID": "SPDXRef-duplicate",
                    "name": "flask",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/flask@2.0.0",
                        }
                    ],
                },
            ],
        }
    }

    with pytest.raises(GithubSbomClientError, match="duplicate component bom-ref"):
        component_identities_from_github_spdx_sbom(raw_response, source="owner/repo")


def test_component_identities_from_github_spdx_sbom_rejects_malformed_shape() -> None:
    with pytest.raises(GithubSbomClientError, match="field 'sbom'"):
        component_identities_from_github_spdx_sbom({}, source="owner/repo")


def test_component_identities_from_github_spdx_sbom_rejects_unsupported_spdx_version() -> None:
    with pytest.raises(GithubSbomClientError, match="unsupported spdxVersion"):
        component_identities_from_github_spdx_sbom(
            {"sbom": {"spdxVersion": "SPDX-1.2", "packages": []}},
            source="owner/repo",
        )


def test_component_identities_from_github_spdx_sbom_rejects_invalid_purl() -> None:
    raw_response = {
        "sbom": {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "SPDXID": "SPDXRef-invalid",
                    "name": "invalid",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "not a purl",
                        }
                    ],
                }
            ],
        }
    }

    with pytest.raises(GithubSbomClientError, match="package purl is invalid"):
        component_identities_from_github_spdx_sbom(raw_response, source="owner/repo")


def test_github_sbom_client_fetches_components_with_auth_header() -> None:
    captured_request: httpx.Request | None = None

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal captured_request
        captured_request = request
        return httpx.Response(
            200,
            json={
                "sbom": {
                    "spdxVersion": "SPDX-2.3",
                    "packages": [
                        {
                            "SPDXID": "SPDXRef-pypi-django-1.2",
                            "name": "django",
                            "versionInfo": "1.2",
                            "externalRefs": [
                                {
                                    "referenceCategory": "PACKAGE-MANAGER",
                                    "referenceType": "purl",
                                    "referenceLocator": "pkg:pypi/django@1.2",
                                }
                            ],
                        }
                    ],
                }
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        client = GithubSbomClient(
            token="secret-token",  # noqa: S106
            client=http_client,
        )
        components = client.component_identities("vexcalibur-dev/vexcalibur")

    assert [(component.ref, component.purl.to_string()) for component in components] == [
        ("SPDXRef-pypi-django-1.2", "pkg:pypi/django@1.2")
    ]
    assert captured_request is not None
    assert (
        str(captured_request.url)
        == "https://api.github.com/repos/vexcalibur-dev/vexcalibur/dependency-graph/sbom"
    )
    assert captured_request.headers["authorization"] == "Bearer secret-token"
    assert captured_request.headers["x-github-api-version"] == GITHUB_API_VERSION


def test_github_sbom_client_allows_anonymous_public_requests() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert "authorization" not in request.headers
        return httpx.Response(
            200,
            json={"sbom": {"spdxVersion": "SPDX-2.3", "packages": []}},
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        components = GithubSbomClient(client=http_client).component_identities(
            "vexcalibur-dev/vexcalibur"
        )

    assert components == ()


def test_github_sbom_client_reports_http_status_without_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "Not Found"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        client = GithubSbomClient(token="secret-token", client=http_client)  # noqa: S106

        with pytest.raises(GithubSbomClientError, match="HTTP 404") as exc_info:
            client.component_identities("vexcalibur-dev/private")

    assert "secret-token" not in str(exc_info.value)


def test_github_sbom_client_rejects_oversized_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"{" + (b" " * MAX_SBOM_BYTES) + b"}")

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        client = GithubSbomClient(client=http_client)

        with pytest.raises(GithubSbomClientError, match="byte limit"):
            client.component_identities("vexcalibur-dev/vexcalibur")


@pytest.mark.live
def test_live_github_sbom_shape_for_public_repo() -> None:
    components = GithubSbomClient().component_identities("vexcalibur-dev/vexcalibur")

    assert components
    assert all(component.ref for component in components)
    assert all(component.purl.to_string().startswith("pkg:") for component in components)
    assert all(
        component.purl.to_string() != "pkg:github/vexcalibur-dev/vexcalibur@main"
        for component in components
    )
