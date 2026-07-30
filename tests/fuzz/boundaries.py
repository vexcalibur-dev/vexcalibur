"""Shared deterministic oracles for untrusted-input fuzz targets."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
import unicodedata
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from xml.sax.saxutils import escape, quoteattr

import httpx
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError
from packageurl import PackageURL

from vexcalibur.domain import ComponentIdentity
from vexcalibur.generation_result import (
    MAX_EXECUTION_REPORT_BYTES,
    ExecutionReportOutputFormat,
    FindingSourceCategory,
    GenerationExecutionContext,
    GenerationResult,
    InventorySourceCategory,
)
from vexcalibur.github_sbom import (
    GithubSbomClientError,
    component_identities_from_github_spdx_sbom,
)
from vexcalibur.json_boundary import StrictJsonError, strict_json_loads
from vexcalibur.render import VexRenderError
from vexcalibur.sbom import SbomError, load_cyclonedx_sbom
from vexcalibur.sources.local import LocalFindingsError, load_local_findings
from vexcalibur.sources.osv import OsvClient, OsvClientError

MAX_FUZZ_INPUT_BYTES = 64 * 1024
OSV_PAGE_SEPARATOR = b"\n--vexcalibur-fuzz-page--\n"
FUZZ_TARGETS = (
    "json",
    "sbom",
    "github",
    "local",
    "osv",
    "identity",
    "report",
    "consumer",
)
_REPORT_CONSUMER_PATH = (
    Path(__file__).parents[2] / "docs" / "examples" / "validate_execution_report.py"
)
_REPORT_CONSUMER_SPEC = importlib.util.spec_from_file_location(
    "vexcalibur_fuzz_execution_report_consumer",
    _REPORT_CONSUMER_PATH,
)
if _REPORT_CONSUMER_SPEC is None or _REPORT_CONSUMER_SPEC.loader is None:
    raise RuntimeError("could not load execution-report consumer example")
_REPORT_CONSUMER = importlib.util.module_from_spec(_REPORT_CONSUMER_SPEC)
_REPORT_CONSUMER_SPEC.loader.exec_module(_REPORT_CONSUMER)
_REPORT_SCHEMA_BYTES = (
    Path(__file__).parents[2] / "docs" / "execution-report-v1.schema.json"
).read_bytes()
_REPORT_SCHEMA = json.loads(_REPORT_SCHEMA_BYTES)
_REPORT_VALIDATOR = Draft202012Validator(_REPORT_SCHEMA)
_CONSUMER_DOCUMENT = b"{}\n"
_CONSUMER_REPORT = (
    json.dumps(
        {
            "schema_version": 1,
            "command": "generate",
            "vexcalibur_version": "fuzz",
            "inventory_source": "custom",
            "finding_source": "custom",
            "output_format": "custom",
            "component_count": 0,
            "finding_count": 0,
            "analysis_state_counts": {},
            "document": {
                "sha256": hashlib.sha256(_CONSUMER_DOCUMENT).hexdigest(),
                "bytes": len(_CONSUMER_DOCUMENT),
            },
        },
        separators=(",", ":"),
    )
    + "\n"
).encode("ascii")
VALID_CONSUMER_SEED = b"R" + _CONSUMER_REPORT

Outcome = tuple[str, str]
Exercise = Callable[[bytes], str]


class _BytesStream(httpx.SyncByteStream):
    """Expose one raw HTTP response chunk without HTTPX pre-decoding it."""

    def __init__(self, content: bytes) -> None:
        self._content = content

    def __iter__(self) -> Iterator[bytes]:
        yield self._content


def deterministic_outcome(target: str, data: bytes) -> Outcome:
    """Return a stable accept/reject signature and propagate unexpected errors."""
    if len(data) > MAX_FUZZ_INPUT_BYTES:
        raise ValueError(f"fuzz input exceeds {MAX_FUZZ_INPUT_BYTES} bytes")
    try:
        exercise = _EXERCISES[target]
        expected_errors = _EXPECTED_ERRORS[target]
    except KeyError as exc:
        raise ValueError(f"unknown fuzz target: {target}") from exc

    try:
        return ("accepted", exercise(data))
    except expected_errors as exc:
        detail = exc.kind.value if isinstance(exc, StrictJsonError) else type(exc).__name__
        return ("rejected", detail)


def assert_deterministic_boundary(target: str, data: bytes) -> None:
    """Exercise a boundary twice and require the same normalized result."""
    first = deterministic_outcome(target, data)
    second = deterministic_outcome(target, data)
    if first != second:
        raise AssertionError(f"{target} boundary is nondeterministic: {first!r} != {second!r}")


def _exercise_json(data: bytes) -> str:
    value = strict_json_loads(data)
    canonical = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return _digest(canonical)


def _exercise_sbom(data: bytes) -> str:
    with TemporaryDirectory(prefix="vexcalibur-fuzz-sbom-") as directory:
        path = Path(directory, "input.sbom")
        path.write_bytes(data)
        return _component_signature(load_cyclonedx_sbom(path))


def _exercise_github(data: bytes) -> str:
    raw_response = strict_json_loads(data)
    components = component_identities_from_github_spdx_sbom(
        raw_response,
        source="fuzz/fixture",
    )
    return _component_signature(components)


def _exercise_local(data: bytes) -> str:
    components = (
        ComponentIdentity(
            ref="component-a",
            name="example-a",
            version="1.0.0",
            purl=PackageURL.from_string("pkg:pypi/example-a@1.0.0"),
        ),
        ComponentIdentity(
            ref="component-b",
            name="example-b",
            version="2.0.0",
            purl=PackageURL.from_string("pkg:npm/example-b@2.0.0"),
        ),
    )
    with TemporaryDirectory(prefix="vexcalibur-fuzz-findings-") as directory:
        path = Path(directory, "findings.json")
        path.write_bytes(data)
        findings = load_local_findings(path, components=components)
    signature = tuple(
        (
            finding.id,
            finding.component_ref,
            finding.purl,
            finding.analysis_state.value,
            finding.modified.isoformat() if finding.modified is not None else None,
        )
        for finding in findings
    )
    return _digest(repr(signature).encode())


def _exercise_osv(data: bytes) -> str:
    selector = data[0] if data else 0
    payload = data[1:] if data else b""
    response_payloads = payload.split(OSV_PAGE_SEPARATOR, maxsplit=2)
    operation = selector % 3
    wire_mode = (selector // 3) % 4
    status_code = 400 if selector % 13 == 12 else 200
    headers: dict[str, str] = {}

    if wire_mode == 1:
        headers["Content-Encoding"] = "gzip"
        wire_payloads = response_payloads
    elif wire_mode == 2:
        headers["Content-Encoding"] = "gzip"
        wire_payloads = [
            gzip.compress(response_payload, mtime=0) for response_payload in response_payloads
        ]
    elif wire_mode == 3:
        headers["Content-Encoding"] = "br"
        wire_payloads = response_payloads
    else:
        wire_payloads = response_payloads

    response_index = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal response_index
        wire_payload = wire_payloads[min(response_index, len(wire_payloads) - 1)]
        response_index += 1
        return httpx.Response(
            status_code,
            headers=headers,
            stream=_BytesStream(wire_payload),
            request=request,
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        client = OsvClient(
            base_url="https://osv.fuzz.invalid",
            client=http_client,
            max_pages=3,
            operation_timeout=2,
            max_response_bytes=16 * 1024,
            max_total_response_bytes=32 * 1024,
            max_encoded_response_bytes=17 * 1024,
            max_total_encoded_response_bytes=34 * 1024,
            max_queries=4,
            max_vulnerabilities_per_query=32,
            max_total_vulnerabilities=24,
            max_page_token_length=64,
            max_vulnerability_id_length=128,
        )
        purl = PackageURL.from_string("pkg:pypi/fuzz-target@1.0.0")
        if operation == 0:
            result = client.query(purl)
            _assert_terminal_safe_ids(summary.id for summary in result.vulnerabilities)
            signature: Any = (
                result.purl,
                result.version,
                tuple(
                    (
                        summary.id,
                        summary.modified.isoformat() if summary.modified is not None else None,
                    )
                    for summary in result.vulnerabilities
                ),
            )
        elif operation == 1:
            results = client.query_batch([purl])
            _assert_terminal_safe_ids(
                summary.id for result in results for summary in result.vulnerabilities
            )
            signature = tuple(
                (
                    result.purl,
                    tuple(summary.id for summary in result.vulnerabilities),
                )
                for result in results
            )
        else:
            vulnerability = client.get_vulnerability("CVE-2026-0001")
            _assert_terminal_safe_ids((vulnerability.id,))
            signature = (vulnerability.id, vulnerability.raw)
    return _digest(repr(signature).encode())


def _exercise_identity(data: bytes) -> str:
    fields = data.decode("utf-8", errors="replace").splitlines()
    name = _identity_token(fields[0] if fields else "", fallback="component", max_length=64)
    version = _identity_token(
        fields[1] if len(fields) > 1 else "",
        fallback="1.0.0",
        max_length=64,
    )
    reference_text = fields[2] if len(fields) > 2 else ""
    reference = _xml_safe_text(reference_text, max_length=128) or f"component:{name}"
    purl = PackageURL(type="generic", name=name, version=version).to_string()

    json_document = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": [
                {
                    "type": "library",
                    "bom-ref": reference,
                    "name": name,
                    "version": version,
                    "purl": purl,
                }
            ],
        },
        separators=(",", ":"),
    ).encode()
    xml_document = (
        '<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">'
        "<components>"
        f'<component type="library" bom-ref={quoteattr(reference)}>'
        f"<name>{escape(name)}</name><version>{escape(version)}</version>"
        f"<purl>{escape(purl)}</purl>"
        "</component></components></bom>"
    ).encode()

    with TemporaryDirectory(prefix="vexcalibur-fuzz-identity-") as directory:
        json_path = Path(directory, "input.json")
        xml_path = Path(directory, "input.xml")
        json_path.write_bytes(json_document)
        xml_path.write_bytes(xml_document)
        json_signature = _component_signature(load_cyclonedx_sbom(json_path))
        xml_signature = _component_signature(load_cyclonedx_sbom(xml_path))

    if json_signature != xml_signature:
        raise AssertionError(
            "equivalent CycloneDX JSON and XML produced different component identities"
        )
    return json_signature


def _exercise_report(data: bytes) -> str:
    rendered = data.decode("utf-8", errors="surrogateescape")
    result = GenerationResult(
        rendered_document=rendered,
        components=(),
        findings=(),
        execution_context=GenerationExecutionContext(
            inventory_source=InventorySourceCategory.CUSTOM,
            finding_source=FindingSourceCategory.CUSTOM,
            output_format=ExecutionReportOutputFormat.CUSTOM,
        ),
    )
    report = result.execution_report()
    serialized = report.to_json().encode("ascii")
    document = json.loads(serialized)
    _REPORT_VALIDATOR.validate(document)

    canonical = (
        json.dumps(
            document,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")
    if serialized != canonical:
        raise AssertionError("execution report is not canonical JSON")
    if len(serialized) > MAX_EXECUTION_REPORT_BYTES:
        raise AssertionError("execution report exceeded its production size limit")
    if report.document.bytes != len(data):
        raise AssertionError("execution report byte count does not match rendered UTF-8")
    if report.document.sha256 != hashlib.sha256(data).hexdigest():
        raise AssertionError("execution report digest does not match rendered UTF-8")
    return _digest(serialized)


def _exercise_consumer(data: bytes) -> str:
    selector = data[0] if data else 0
    payload = data[1:] if data else b""
    with TemporaryDirectory(prefix="vexcalibur-fuzz-report-consumer-") as directory:
        root = Path(directory)
        report_path = root / "execution-report.json"
        schema_path = root / "execution-report.schema.json"
        document_path = root / "vex.json"
        report_path.write_bytes(_CONSUMER_REPORT)
        schema_path.write_bytes(_REPORT_SCHEMA_BYTES)
        document_path.write_bytes(_CONSUMER_DOCUMENT)
        selected_path = report_path if selector % 2 == 0 else schema_path
        selected_path.write_bytes(payload)
        _REPORT_CONSUMER.validate_execution_report(
            report_path,
            document_path,
            schema_path,
        )
    return _digest(bytes((selector,)) + payload)


def _identity_token(value: str, *, fallback: str, max_length: int) -> str:
    allowed = "._+-"
    normalized = unicodedata.normalize("NFC", value)
    token = "".join(
        character for character in normalized if character.isalnum() or character in allowed
    )[:max_length]
    return token or fallback


def _xml_safe_text(value: str, *, max_length: int) -> str:
    normalized = unicodedata.normalize("NFC", value)
    return "".join(character for character in normalized if _is_xml_safe(character))[:max_length]


def _is_xml_safe(character: str) -> bool:
    codepoint = ord(character)
    if (codepoint & 0xFFFF) in {0xFFFE, 0xFFFF}:
        return False
    return (
        0x20 <= codepoint <= 0xD7FF
        or 0xE000 <= codepoint <= 0xFFFD
        or 0x10000 <= codepoint <= 0x10FFFF
    )


def _component_signature(components: tuple[ComponentIdentity, ...]) -> str:
    signature = tuple(
        (
            component.ref,
            component.name,
            component.version,
            component.purl.to_string(),
            component.type,
        )
        for component in components
    )
    return _digest(repr(signature).encode())


def _assert_terminal_safe_ids(values: Iterable[str]) -> None:
    for value in values:
        if any(
            unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"} for character in value
        ):
            raise AssertionError(f"accepted unsafe OSV identifier: {value!r}")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value, usedforsecurity=False).hexdigest()


_EXERCISES: dict[str, Exercise] = {
    "json": _exercise_json,
    "sbom": _exercise_sbom,
    "github": _exercise_github,
    "local": _exercise_local,
    "osv": _exercise_osv,
    "identity": _exercise_identity,
    "report": _exercise_report,
    "consumer": _exercise_consumer,
}

_EXPECTED_ERRORS: dict[str, tuple[type[Exception], ...]] = {
    "json": (StrictJsonError,),
    "sbom": (SbomError,),
    "github": (StrictJsonError, GithubSbomClientError),
    "local": (LocalFindingsError,),
    "osv": (OsvClientError,),
    "identity": (),
    "report": (VexRenderError,),
    "consumer": (
        SchemaError,
        UnicodeError,
        ValidationError,
        ValueError,
    ),
}
