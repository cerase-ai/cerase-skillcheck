"""Every completion the scanner makes says it is a scan.

The platform separates what a call COST by a label the LiteLLM hook writes, and
the label is declared by the caller rather than guessed from the prompt — a
label that changes a cost report must not come from a string match. The scanner
is a third-party library with no header hook of its own, so the one place it can
declare is the loopback proxy every one of its completions already passes
through.

Measured on a live appliance before this existed: over three days, 88 of the 158
calls the spend report labelled `turn` were skill scans, and they carried $1,74
of the $1,91 that label held. The report told an operator conversation had cost
eleven times what conversation cost.

Run from the package root::

    python -m pytest tests/test_scan_is_declared.py -v
"""
from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server  # noqa: E402


class _Upstream:
    """A stand-in LiteLLM that records the headers it was handed."""

    def __init__(self) -> None:
        self.seen: dict[str, str] = {}
        upstream = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *args) -> None:  # noqa: A002 - silence the server
                return

            def do_POST(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                upstream.seen = {k.lower(): v for k, v in self.headers.items()}
                body = json.dumps(
                    {"choices": [{"message": {"content": "ok"}}]}
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)


def _through_the_proxy(headers: dict[str, str]) -> dict[str, str]:
    """POST a completion through the real proxy, return what upstream saw."""
    upstream = _Upstream()
    proxy = server._CompletionProxy(upstream.url, server.Budget(30.0))
    proxy.start()
    try:
        httpx.post(
            f"{proxy.base_url}/chat/completions",
            json={"model": "core", "messages": [{"role": "user", "content": "x"}]},
            headers=headers,
            timeout=10.0,
        )
    finally:
        proxy.stop()
        upstream.stop()
    return upstream.seen


def test_a_forwarded_completion_declares_that_it_is_a_scan() -> None:
    seen = _through_the_proxy({"Authorization": "Bearer sk-test"})

    assert seen.get("x-cerase-call-type") == "scan"


def test_the_scanner_cannot_relabel_the_platform_s_spend() -> None:
    """The value is ours to state, not the library's to choose.

    A scanner that set the header itself — or a prompt that talked one into it —
    would otherwise move its cost onto the conversation line, which is exactly
    the mistake this label exists to stop.
    """
    seen = _through_the_proxy(
        {"Authorization": "Bearer sk-test", "x-cerase-call-type": "turn"}
    )

    assert seen.get("x-cerase-call-type") == "scan"


def test_the_authorization_header_still_passes_through_untouched() -> None:
    """The proxy relays identity; the label is the only thing it adds.

    A forwarder that rewrote the credential would send the scan out on whatever
    identity the proxy happened to hold, which is the failure the scoped service
    key exists to prevent.
    """
    seen = _through_the_proxy({"Authorization": "Bearer sk-scoped-service-key"})

    assert seen.get("authorization") == "Bearer sk-scoped-service-key"
