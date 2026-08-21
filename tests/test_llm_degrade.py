"""An LLM stage that produced no completion must be reported as degraded.

These tests exist because it was not. With a LiteLLM key the router rejects,
every model call answered 401 in under a second, the scan of a bundle finished
in 2.4s instead of 187s, and the verdict came back ``SAFE / LOW / 0`` with no
findings and ``degraded: false`` — a clean bill of health produced by a scan
whose semantic analyzers never saw a single answer. Seven skills were scanned
in 18s that way, and the LiteLLM spend log held 21 rows with ``total_tokens =
0``, ``"status": "failure"``, ``"error_code": "401"``.

Why the report could not be trusted for this. skillspector marks a scan
degraded only when its ``llm_call_log`` holds no successful record, and three
of its four LLM nodes (``meta_analyzer``, ``semantic_developer_intent``,
``semantic_quality_policy``) run their batches through
``LLMAnalyzerBase.arun_batches``, which catches every per-batch exception,
drops the batch and returns the survivors. A node whose batches all failed
therefore returns an empty result set and records ``ok=True``, so
``meta_analysis_applied`` stays ``true`` and the metadata says an LLM pass
happened. The engine cannot read the truth out of that file; it has to observe
the traffic, which is what these tests drive.

The discriminator is "the stage was requested and produced nothing usable" —
never the specific error — so the rejection cases below are parametrised over
statuses and over a 200 that carries no completion.

Run from the package root::

    python -m pytest tests/test_llm_degrade.py -v
"""
from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server  # noqa: E402

# What the scanner writes when its LLM nodes swallowed their failures: an LLM
# pass is claimed, a couple of nodes are even counted as succeeded, and the
# verdict is clean. This is the file that was read as "Verified by Cerase".
DISHONEST_REPORT = {
    "skill": {"name": "probe-skill", "source": "/tmp/probe"},
    "risk_assessment": {"score": 0, "severity": "LOW", "recommendation": "SAFE"},
    "issues": [],
    "components": [{"path": "SKILL.md", "type": "manifest"}],
    "metadata": {
        "skillspector_version": "2.3.9",
        "llm_requested": True,
        "llm_available": True,
        "meta_analysis_applied": True,
        "llm_calls_attempted": 4,
        "llm_calls_succeeded": 3,
    },
}

GOOD_COMPLETION = {
    "id": "chatcmpl-probe",
    "object": "chat.completion",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": "{\"findings\": []}"}}],
    "usage": {"total_tokens": 42},
}

EMPTY_COMPLETION = {"id": "chatcmpl-probe", "object": "chat.completion", "choices": []}


class _FakeLiteLLM:
    """A stand-in router: a liveness endpoint plus a scripted completion reply.

    The liveness endpoint always answers, because that is the state the defect
    lives in — the router is up, and only the model call fails.
    """

    def __init__(self, status: int, body: dict) -> None:
        self.status = status
        self.body = body
        self.completion_requests = 0
        self.authorizations: list[str] = []
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args) -> None:  # noqa: ANN002
                pass

            def do_GET(self) -> None:  # noqa: N802
                self._reply(200, {"status": "healthy"})

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                with outer._lock:
                    outer.completion_requests += 1
                    outer.authorizations.append(self.headers.get("Authorization", ""))
                self._reply(outer.status, outer.body)

            def _reply(self, status: int, payload: dict) -> None:
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def __enter__(self) -> _FakeLiteLLM:
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:  # noqa: ANN002
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    @property
    def base_url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"


FAKE_SCANNER = '''#!/usr/bin/env python3
"""A stand-in skillspector: calls the model endpoint, then writes a clean report.

It reproduces the shape that produced the defect — the LLM calls are made and
their outcome is swallowed, so the report claims an applied LLM pass whatever
the endpoint answered.
"""
import json
import os
import sys
import urllib.error
import urllib.request

argv = sys.argv[1:]
out = argv[argv.index("--output") + 1]

base = os.environ.get("OPENAI_BASE_URL", "").rstrip("/")
key = os.environ.get("OPENAI_API_KEY", "")
if base:
    payload = json.dumps(
        {
            "model": os.environ.get("SKILLSPECTOR_MODEL", "core"),
            "messages": [{"role": "user", "content": "analyse this skill"}],
        }
    ).encode()
    for _ in range(3):
        request = urllib.request.Request(
            base + "/chat/completions",
            data=payload,
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + key},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as resp:
                resp.read()
        except Exception:
            pass

with open(out, "w", encoding="utf-8") as fh:
    json.dump(json.loads(os.environ["FAKE_REPORT"]), fh)
sys.exit(0)
'''


@pytest.fixture
def fake_scanner(tmp_path, monkeypatch):
    """Put a stand-in ``skillspector`` first on PATH and hand it the report."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "skillspector"
    script.write_text(FAKE_SCANNER, encoding="utf-8")
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_REPORT", json.dumps(DISHONEST_REPORT))
    return script


def _scan_against(upstream: _FakeLiteLLM, monkeypatch, tmp_path) -> server.Verdict:
    monkeypatch.setenv("LITELLM_BASE_URL", upstream.base_url)
    monkeypatch.setenv("SKILLCHECK_LLM_API_KEY", "sk-cerase-svc-skillcheck")
    target = tmp_path / "SKILL.md"
    target.write_text("---\nname: probe-skill\ndescription: fixture.\n---\n", encoding="utf-8")
    return server._scan_target(target, partial=True)


@pytest.mark.parametrize(
    ("status", "body", "why"),
    [
        (401, {"error": {"message": "Invalid proxy server token passed"}}, "rejected key"),
        (429, {"error": {"message": "rate limit"}}, "rate limited"),
        (500, {"error": {"message": "upstream exploded"}}, "router error"),
        (200, EMPTY_COMPLETION, "answered with no completion"),
    ],
)
def test_no_completion_is_degraded_static(status, body, why, fake_scanner, monkeypatch, tmp_path):
    """No usable completion → the verdict says static and degraded, whatever the cause."""
    with _FakeLiteLLM(status, body) as upstream:
        verdict = _scan_against(upstream, monkeypatch, tmp_path)

    assert upstream.completion_requests >= 1, "the scan never reached the model endpoint"
    assert verdict.degraded is True, f"{why}: verdict not flagged degraded"
    assert verdict.mode == server.MODE_STATIC, f"{why}: verdict still claims an LLM pass"


def test_usable_completions_keep_the_llm_verdict(fake_scanner, monkeypatch, tmp_path):
    """The honest case must stay honest, or ``degraded`` stops meaning anything."""
    with _FakeLiteLLM(200, GOOD_COMPLETION) as upstream:
        verdict = _scan_against(upstream, monkeypatch, tmp_path)

    assert upstream.completion_requests >= 1
    assert verdict.mode == server.MODE_LLM
    assert verdict.degraded is False


def test_the_service_key_still_reaches_the_router(fake_scanner, monkeypatch, tmp_path):
    """Whatever the engine puts between the scanner and LiteLLM must carry the key.

    A scan that lost the Authorization header would 401 at the router and look
    exactly like the defect above, so the credential is asserted on the wire.
    """
    with _FakeLiteLLM(200, GOOD_COMPLETION) as upstream:
        _scan_against(upstream, monkeypatch, tmp_path)

    assert upstream.authorizations
    assert all(a == "Bearer sk-cerase-svc-skillcheck" for a in upstream.authorizations)


# ---------------------------------------------------------------------------
# The mapping itself: the observed completion count outranks the metadata
# ---------------------------------------------------------------------------


def test_llm_outcome_zero_completions_outranks_an_applied_claim():
    data = {"metadata": {"llm_requested": True, "meta_analysis_applied": True}}
    assert server._llm_outcome(data, completions=0) == (server.MODE_STATIC, True)


def test_llm_outcome_completions_with_applied_claim_is_llm():
    data = {"metadata": {"llm_requested": True, "meta_analysis_applied": True}}
    assert server._llm_outcome(data, completions=3) == (server.MODE_LLM, False)


def test_llm_outcome_completions_do_not_override_a_degraded_report():
    """A report that admits the degradation is believed even with completions seen."""
    data = {"metadata": {"llm_requested": True, "meta_analysis_applied": False}}
    assert server._llm_outcome(data, completions=3) == (server.MODE_STATIC, True)


def test_llm_outcome_static_run_is_not_degraded_by_a_zero_count():
    """A ``--no-llm`` run has no completions to produce and must not be flagged."""
    data = {"metadata": {"llm_requested": False, "meta_analysis_applied": False}}
    assert server._llm_outcome(data, completions=0) == (server.MODE_STATIC, False)
