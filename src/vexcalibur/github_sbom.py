"""GitHub Dependency Graph SBOM client."""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlparse

import httpx
from packageurl import PackageURL

from vexcalibur.domain import ComponentIdentity
from vexcalibur.sbom import MAX_COMPONENTS, MAX_SBOM_BYTES, SbomError

DEFAULT_GITHUB_API_URL = "https://api.github.com"
GITHUB_API_VERSION = "2026-03-10"
DEFAULT_GITHUB_TIMEOUT = 30.0
GITHUB_RESPONSE_CHUNK_SIZE = 64 * 1024
SUPPORTED_GITHUB_SPDX_VERSION = "SPDX-2.3"


class GithubSbomError(SbomError):
    """Base error raised for GitHub SBOM input failures."""


class GithubSbomConfigurationError(GithubSbomError):
    """Raised when GitHub SBOM input configuration is invalid."""


class GithubSbomClientError(GithubSbomError):
    """Raised when GitHub's SBOM API cannot return usable data."""


@dataclass(frozen=True)
class GithubRepository:
    """Parsed GitHub repository owner and name."""

    owner: str
    repo: str

    @property
    def full_name(self) -> str:
        """Return the `OWNER/REPO` repository name."""
        return f"{self.owner}/{self.repo}"


class GithubSbomClient:
    """Client for GitHub's Dependency Graph SBOM export endpoint."""

    def __init__(
        self,
        *,
        api_url: str = DEFAULT_GITHUB_API_URL,
        token: str | None = None,
        timeout: float = DEFAULT_GITHUB_TIMEOUT,
        client: httpx.Client | None = None,
    ) -> None:
        self._api_url = normalize_github_api_url(api_url)
        self._token = token
        self._timeout = timeout
        self._client = client

    @property
    def api_url(self) -> str:
        """GitHub API base URL used by this client."""
        return self._api_url

    def component_identities(self, repository: str) -> tuple[ComponentIdentity, ...]:
        """Fetch and parse repository Dependency Graph SBOM components."""
        parsed_repository = parse_github_repository(repository)
        response_body = self._get_json(_repository_sbom_path(parsed_repository))
        return component_identities_from_github_spdx_sbom(
            response_body,
            source=parsed_repository.full_name,
        )

    def _get_json(self, path: str) -> dict[str, Any]:
        client = self._client
        if client is not None:
            return self._send_json_request(client, path)

        with httpx.Client() as owned_client:
            return self._send_json_request(owned_client, path)

    def _send_json_request(self, client: httpx.Client, path: str) -> dict[str, Any]:
        url = f"{self._api_url}{path}"
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        try:
            with client.stream("GET", url, headers=headers, timeout=self._timeout) as response:
                response.raise_for_status()
                raw_content = _read_limited_response_content(response)
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code
            msg = f"GitHub SBOM API GET {path} failed with HTTP {status_code}"
            raise GithubSbomClientError(msg) from exc
        except httpx.HTTPError as exc:
            msg = f"GitHub SBOM API GET {path} request failed"
            raise GithubSbomClientError(msg) from exc

        try:
            response_body = json.loads(raw_content.decode("utf-8"))
        except UnicodeDecodeError as exc:
            msg = "GitHub SBOM response body must be UTF-8 JSON"
            raise GithubSbomClientError(msg) from exc
        except json.JSONDecodeError as exc:
            msg = "GitHub SBOM response body must be JSON"
            raise GithubSbomClientError(msg) from exc

        if not isinstance(response_body, dict):
            msg = "GitHub SBOM response body must be a JSON object"
            raise GithubSbomClientError(msg)
        return response_body


def component_identities_from_github_spdx_sbom(
    raw_response: Any,
    *,
    source: str,
) -> tuple[ComponentIdentity, ...]:
    """Extract component identities from GitHub Dependency Graph SPDX JSON."""
    raw_sbom = _github_spdx_sbom_document(raw_response, source=source)
    packages = raw_sbom.get("packages")
    if not isinstance(packages, list):
        msg = f"GitHub SBOM {source} field 'packages' must be a list"
        raise GithubSbomClientError(msg)
    if len(packages) > MAX_COMPONENTS:
        msg = f"GitHub SBOM {source} contains more than {MAX_COMPONENTS} packages"
        raise GithubSbomClientError(msg)

    repository_spdx_ids = _github_spdx_repository_package_ids(raw_sbom, source=source)
    components = tuple(
        component
        for package in packages
        for component in (
            _github_spdx_package_identity(
                package,
                source=source,
                repository_spdx_ids=repository_spdx_ids,
            ),
        )
        if component is not None
    )
    _validate_unique_component_refs(components)
    return tuple(
        sorted(
            _dedupe_components(components),
            key=lambda component: (component.purl.to_string(), component.ref),
        )
    )


def parse_github_repository(value: str) -> GithubRepository:
    """Parse `OWNER/REPO` repository text."""
    owner, separator, repo = value.strip().partition("/")
    if not separator or not owner or not repo or "/" in repo:
        msg = "--github-repo must use OWNER/REPO format"
        raise GithubSbomConfigurationError(msg)
    if owner in {".", ".."} or repo in {".", ".."}:
        msg = "--github-repo owner and repository must not be path traversal segments"
        raise GithubSbomConfigurationError(msg)
    if repo.endswith(".git"):
        repo = repo.removesuffix(".git")
    if not repo:
        msg = "--github-repo repository name must not be empty"
        raise GithubSbomConfigurationError(msg)
    return GithubRepository(owner=owner, repo=repo)


def normalize_github_api_url(value: str) -> str:
    """Normalize and validate a GitHub API base URL."""
    normalized = value.strip().rstrip("/")
    parsed = urlparse(normalized)
    if parsed.scheme != "https" or parsed.hostname is None:
        msg = "--github-api-url must be an HTTPS URL"
        raise GithubSbomConfigurationError(msg)
    if parsed.username is not None or parsed.password is not None:
        msg = "--github-api-url must not include userinfo"
        raise GithubSbomConfigurationError(msg)
    if parsed.params or parsed.query or parsed.fragment:
        msg = "--github-api-url must not include params, query, or fragment"
        raise GithubSbomConfigurationError(msg)
    return normalized


def resolve_github_token(
    *,
    api_url: str = DEFAULT_GITHUB_API_URL,
    token_env: str | None = None,
    allow_gh_cli: bool = True,
    environ: Mapping[str, str] | None = None,
) -> str | None:
    """Resolve a GitHub token from explicit env, standard env, or `gh auth token`."""
    environment = os.environ if environ is None else environ
    if token_env is not None:
        normalized_token_env = token_env.strip()
        if not normalized_token_env:
            msg = "--github-token-env must not be empty"
            raise GithubSbomConfigurationError(msg)
        token = environment.get(normalized_token_env)
        if token is None or token.strip() == "":
            msg = f"GitHub token environment variable {normalized_token_env!r} is not set"
            raise GithubSbomConfigurationError(msg)
        return token.strip()

    for env_name in _default_token_env_names(api_url):
        token = environment.get(env_name)
        if token is not None and token.strip() != "":
            return token.strip()

    if not allow_gh_cli:
        return None

    return _gh_auth_token(api_url)


def _default_token_env_names(api_url: str) -> tuple[str, ...]:
    if _github_cli_hostname(api_url) == "github.com":
        return ("GH_TOKEN", "GITHUB_TOKEN")
    return ("GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")


def _repository_sbom_path(repository: GithubRepository) -> str:
    owner = quote(repository.owner, safe="")
    repo = quote(repository.repo, safe="")
    return f"/repos/{owner}/{repo}/dependency-graph/sbom"


def _read_limited_response_content(response: httpx.Response) -> bytes:
    content = bytearray()
    for chunk in response.iter_bytes(chunk_size=GITHUB_RESPONSE_CHUNK_SIZE):
        content.extend(chunk)
        if len(content) > MAX_SBOM_BYTES:
            msg = f"GitHub SBOM response exceeds the {MAX_SBOM_BYTES} byte limit"
            raise GithubSbomClientError(msg)
    return bytes(content)


def _github_spdx_sbom_document(raw_response: Any, *, source: str) -> dict[str, Any]:
    if not isinstance(raw_response, dict):
        msg = f"GitHub SBOM {source} response must be a JSON object"
        raise GithubSbomClientError(msg)
    raw_sbom = raw_response.get("sbom")
    if not isinstance(raw_sbom, dict):
        msg = f"GitHub SBOM {source} response field 'sbom' must be an object"
        raise GithubSbomClientError(msg)
    spdx_version = raw_sbom.get("spdxVersion")
    if spdx_version != SUPPORTED_GITHUB_SPDX_VERSION:
        msg = (
            f"GitHub SBOM {source} has unsupported spdxVersion {spdx_version!r}; "
            f"supported: {SUPPORTED_GITHUB_SPDX_VERSION}"
        )
        raise GithubSbomClientError(msg)
    return raw_sbom


def _github_spdx_repository_package_ids(raw_sbom: dict[str, Any], *, source: str) -> frozenset[str]:
    relationships = raw_sbom.get("relationships", [])
    if not isinstance(relationships, list):
        msg = f"GitHub SBOM {source} field 'relationships' must be a list when present"
        raise GithubSbomClientError(msg)

    repository_spdx_ids: set[str] = set()
    for relationship in relationships:
        if not isinstance(relationship, dict):
            msg = f"GitHub SBOM {source} relationship entries must be objects"
            raise GithubSbomClientError(msg)
        if relationship.get("spdxElementId") != "SPDXRef-DOCUMENT":
            continue
        if relationship.get("relationshipType") != "DESCRIBES":
            continue
        related = relationship.get("relatedSpdxElement")
        if not isinstance(related, str) or related.strip() == "":
            msg = f"GitHub SBOM {source} DESCRIBES relationships must name a package"
            raise GithubSbomClientError(msg)
        repository_spdx_ids.add(related)
    return frozenset(repository_spdx_ids)


def _github_spdx_package_identity(
    package: Any,
    *,
    source: str,
    repository_spdx_ids: frozenset[str],
) -> ComponentIdentity | None:
    if not isinstance(package, dict):
        msg = f"GitHub SBOM {source} packages must be objects"
        raise GithubSbomClientError(msg)

    purl = _github_spdx_package_purl(package, source=source)
    if purl is None:
        return None

    spdx_id = package.get("SPDXID")
    if spdx_id is not None and not isinstance(spdx_id, str):
        msg = f"GitHub SBOM {source} package SPDXID values must be strings"
        raise GithubSbomClientError(msg)
    if _is_github_repository_package(
        spdx_id=spdx_id,
        purl=purl,
        repository_spdx_ids=repository_spdx_ids,
    ):
        return None

    name = package.get("name")
    if name is not None and not isinstance(name, str):
        msg = f"GitHub SBOM {source} package names must be strings"
        raise GithubSbomClientError(msg)

    version = package.get("versionInfo")
    if version is not None and not isinstance(version, str):
        msg = f"GitHub SBOM {source} package versionInfo values must be strings"
        raise GithubSbomClientError(msg)

    ref = spdx_id.strip() if isinstance(spdx_id, str) and spdx_id.strip() else purl.to_string()
    return ComponentIdentity(
        ref=ref,
        name=name or purl.name,
        version=version,
        purl=purl,
    )


def _is_github_repository_package(
    *,
    spdx_id: Any,
    purl: PackageURL,
    repository_spdx_ids: frozenset[str],
) -> bool:
    if purl.type != "github":
        return False
    if spdx_id == "SPDXRef-Repository":
        return True
    return isinstance(spdx_id, str) and spdx_id in repository_spdx_ids


def _github_spdx_package_purl(package: dict[str, Any], *, source: str) -> PackageURL | None:
    external_refs = package.get("externalRefs", [])
    if not isinstance(external_refs, list):
        msg = f"GitHub SBOM {source} package externalRefs values must be lists"
        raise GithubSbomClientError(msg)
    for external_ref in external_refs:
        if not isinstance(external_ref, dict):
            msg = f"GitHub SBOM {source} package externalRefs entries must be objects"
            raise GithubSbomClientError(msg)
        if external_ref.get("referenceCategory") != "PACKAGE-MANAGER":
            continue
        if external_ref.get("referenceType") != "purl":
            continue
        reference_locator = external_ref.get("referenceLocator")
        if not isinstance(reference_locator, str) or reference_locator.strip() == "":
            msg = f"GitHub SBOM {source} package purl referenceLocator values must be strings"
            raise GithubSbomClientError(msg)
        try:
            return PackageURL.from_string(reference_locator)
        except ValueError as exc:
            msg = f"GitHub SBOM {source} package purl is invalid: {exc}"
            raise GithubSbomClientError(msg) from exc
    return None


def _validate_unique_component_refs(components: tuple[ComponentIdentity, ...]) -> None:
    seen_refs: set[str] = set()
    duplicate_refs: set[str] = set()
    for component in components:
        if component.ref in seen_refs:
            duplicate_refs.add(component.ref)
        seen_refs.add(component.ref)
    if duplicate_refs:
        duplicate_list = ", ".join(sorted(duplicate_refs))
        msg = f"GitHub SBOM contains duplicate component bom-ref values: {duplicate_list}"
        raise GithubSbomClientError(msg)


def _dedupe_components(components: tuple[ComponentIdentity, ...]) -> tuple[ComponentIdentity, ...]:
    deduped: dict[tuple[str, str], ComponentIdentity] = {}
    for component in components:
        deduped[(component.ref, component.purl.to_string())] = component
    return tuple(deduped.values())


def _github_cli_hostname(api_url: str) -> str:
    parsed = urlparse(normalize_github_api_url(api_url))
    hostname = parsed.hostname
    if hostname is None:
        msg = "--github-api-url must be an HTTPS URL"
        raise GithubSbomConfigurationError(msg)
    normalized_hostname = hostname.lower()
    if normalized_hostname == "api.github.com":
        return "github.com"
    return normalized_hostname


def _gh_auth_token(api_url: str) -> str | None:
    hostname = _github_cli_hostname(api_url)
    try:
        completed = subprocess.run(  # noqa: S603
            # `gh` is intentionally resolved from PATH to match the user's CLI setup.
            ["gh", "auth", "token", "--hostname", hostname],  # noqa: S607
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return None

    if completed.returncode != 0:
        return None
    token = completed.stdout.strip()
    return token or None
