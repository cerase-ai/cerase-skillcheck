"""Findings must be explained in Italian without changing the report's shape.

The scan's findings are read by an Italian-speaking operator, but the model
writes ``explanation`` and ``remediation`` in English. The proxy that already
relays every completion is the one place that can ask for those two values in
Italian for every call, without the scanner knowing about it: one system
message is prepended to the conversation and the rest of the body is forwarded
unchanged.

The instruction must only change prose. Keys, ids, categories, severities,
verdicts and every other enum value keep the exact spelling the schema requires,
or the report stops validating. Bodies that are not a JSON object with a
``messages`` list are forwarded byte-for-byte, and a request that is not a
completion (a model listing, for instance) is never touched.

Run from the package root::

    python -m pytest tests/test_findings_language.py -v
"""
from __future__ import annotations

import json
import sys
import threading
import urllib.request
from collections import namedtuple
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server  # noqa: E402

_Seen = namedtuple("_Seen", ("method", "path", "body"))


class _RecordingLiteLLM:
    """A stand-in router that records every request body it is handed.

    It answers every request with a usable completion, so the proxy's counting
    and relaying behave exactly as they do against the real router.
    """

    def __init__(self) -> None:
        self.requests: list[_Seen] = []
        self._lock = threading.Lock()
        upstream = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args) -> None:  # noqa: ANN002
                pass

            def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
                self._record_and_reply("GET")

            def do_POST(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
                self._record_and_reply("POST")

            def _record_and_reply(self, method: str) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length > 0 else b""
                with upstream._lock:
                    upstream.requests.append(_Seen(method, self.path, body))
                data = json.dumps(
                    {"choices": [{"message": {"role": "assistant", "content": "ok"}}]}
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
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


def _forward(
    body: bytes | None, path: str = "/chat/completions", method: str = "POST"
) -> list[_Seen]:
    """Send one request through the real proxy and return what upstream saw."""
    upstream = _RecordingLiteLLM()
    proxy = server._CompletionProxy(upstream.url, server.Budget(server._SCAN_DEADLINE))
    proxy.start()
    try:
        request = urllib.request.Request(
            proxy.base_url + path,
            data=body if method == "POST" else None,
            headers={"Content-Type": "application/json"},
            method=method,
        )
        with urllib.request.urlopen(request, timeout=10.0) as resp:
            resp.read()
    finally:
        proxy.stop()
        upstream.stop()
    return upstream.requests


@pytest.fixture(autouse=True)
def _findings_language_is_present():
    """Every test here exercises this feature; a missing piece is a clear failure."""
    assert isinstance(server._ITALIAN_FINDINGS_INSTRUCTION, str)
    assert callable(server._with_findings_language)


def test_a_completion_gets_the_instruction_before_the_original_messages() -> None:
    body = {
        "model": "core",
        "messages": [
            {"role": "system", "content": "You review skills."},
            {"role": "user", "content": "analyse this skill"},
        ],
        "response_format": {"type": "json_object"},
        "tools": [{"type": "function", "function": {"name": "report"}}],
    }

    seen = _forward(json.dumps(body).encode())

    assert len(seen) == 1, "the proxy did not forward exactly one request"
    forwarded = json.loads(seen[0].body)
    assert forwarded["messages"][0] == {
        "role": "system",
        "content": server._ITALIAN_FINDINGS_INSTRUCTION,
    }
    assert forwarded["messages"][1:] == body["messages"]
    assert forwarded["model"] == body["model"]
    assert forwarded["response_format"] == body["response_format"]
    assert forwarded["tools"] == body["tools"]
    assert set(forwarded) == set(body)


def test_the_instruction_asks_for_italian_prose_and_unchanged_values() -> None:
    instruction = server._ITALIAN_FINDINGS_INSTRUCTION

    assert "explanation" in instruction
    assert "remediation" in instruction
    assert "Italian" in instruction


@pytest.mark.parametrize(
    "body",
    [
        json.dumps({"model": "core", "input": "no messages here"}).encode(),
        b"this is not JSON at all",
        b"",
    ],
    ids=["json-without-messages", "not-json", "empty"],
)
def test_bodies_without_messages_are_forwarded_byte_for_byte(body: bytes) -> None:
    seen = _forward(body)

    assert len(seen) == 1
    assert seen[0].body == body


def test_a_non_completion_path_is_forwarded_untouched() -> None:
    seen = _forward(None, path="/models", method="GET")

    assert len(seen) == 1
    assert seen[0].method == "GET"
    assert seen[0].path == "/v1/models"
    assert seen[0].body == b"", "the proxy gave a model listing a body"


def test_the_rewrite_does_not_prepend_the_instruction_twice() -> None:
    instruction_message = {
        "role": "system",
        "content": server._ITALIAN_FINDINGS_INSTRUCTION,
    }
    body = {
        "model": "core",
        "messages": [instruction_message, {"role": "user", "content": "analyse this skill"}],
    }
    raw = json.dumps(body).encode()

    once = server._with_findings_language(raw)
    twice = server._with_findings_language(once)

    rewritten = json.loads(twice)
    assert rewritten["messages"] == body["messages"]
    assert (
        sum(1 for message in rewritten["messages"] if message == instruction_message) == 1
    ), "a second instruction was prepended"
