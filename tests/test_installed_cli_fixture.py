"""Transport regression tests for the installed-CLI loopback fixture."""

from __future__ import annotations

import http.client
import io
import socket
import threading
from urllib.parse import urlsplit

import pytest

from tests.integration import check_installed_cli


def test_osv_failure_fixture_consumes_request_before_response(monkeypatch) -> None:
    body = b'{"queries":[]}'
    handler = object.__new__(check_installed_cli._OsvFailureHandler)
    handler.headers = {"Content-Length": str(len(body))}
    handler.rfile = io.BytesIO(body)
    handler.wfile = io.BytesIO()

    def assert_consumed(status: int) -> None:
        assert status == 503
        assert handler.rfile.read() == b""

    monkeypatch.setattr(handler, "send_response", assert_consumed)
    monkeypatch.setattr(handler, "send_header", lambda *args: None)
    monkeypatch.setattr(handler, "end_headers", lambda: None)
    handler.do_POST()


@pytest.mark.parametrize("body", [b"", b'{"queries":[]}', b"x" * 16384])
def test_osv_failure_fixture_drains_post_before_closing(monkeypatch, body: bytes) -> None:
    headers_received = threading.Event()
    body_sent = threading.Event()

    class CoordinatedHandler(check_installed_cli._OsvFailureHandler):
        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler hook.
            headers_received.set()
            if body_sent.wait(timeout=5):
                super().do_POST()

    monkeypatch.setattr(check_installed_cli, "_OsvFailureHandler", CoordinatedHandler)
    with check_installed_cli._local_osv_failure_server() as url:
        address = urlsplit(url)
        assert address.hostname is not None
        assert address.port is not None
        with socket.create_connection((address.hostname, address.port), timeout=5) as connection:
            try:
                connection.sendall(
                    (
                        "POST /v1/querybatch HTTP/1.0\r\n"
                        "Host: localhost\r\n"
                        f"Content-Length: {len(body)}\r\n\r\n"
                    ).encode("ascii")
                )
                assert headers_received.wait(timeout=5)
                # Keep the body out of the handler's buffered header read.
                connection.sendall(body)
            finally:
                body_sent.set()

            with http.client.HTTPResponse(connection) as response:
                response.begin()
                assert response.status == 503
                assert response.read() == b'{"error":"service unavailable"}'
                assert response.getheader("Content-Length") == "31"
            assert connection.recv(1) == b""
