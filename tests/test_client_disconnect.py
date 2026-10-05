"""A scan whose client has gone must not keep a scan slot.

These tests exist because it did. The engine runs at most
``SKILLCHECK_MAX_CONCURRENT_SCANS`` scans at once (2 by default), and nothing
told a running scan that the client which asked for it had stopped waiting. The
work went on until the engine's own deadline, holding its slot, and every
request behind it queued for work whose result nobody would read. Measured on
an appliance: a scoped rescan gave up after 450.4s, while ``/healthz`` reported
``scans_in_flight: 2`` and ``oldest_scan_seconds: 475.5`` — both slots held by
scans nobody was waiting for.

What a hang-up must do, and what each test below holds:

  1. A running scan is stopped: the scanner's process group is killed, the
     scan's completion proxy is stopped, the static fallback is NOT started
     (it exists to give a waiting client a verdict, and there is none), and the
     slot is free within seconds, so ``/healthz`` stops counting it.
  2. A request still waiting for a slot stops waiting and never takes one.
  3. The next client in line gets the slot the abandoned scan held, and its
     verdict, without waiting for the abandoned work to run out its time. This
     is the milestone's done-when, end to end.

How these tests hang up. ``httpx.ASGITransport`` runs the application inside
the client's own task and reports a disconnect only once the response is
complete, so it cannot reproduce this. The tests speak ASGI directly, the way
uvicorn does: the request body is delivered, the next ``receive()`` blocks
until the connection closes, and then answers ``http.disconnect``. Hanging up
is closing that connection.

The scanner is a stand-in ``skillspector`` first on PATH. A SKILL.md naming
``slow-skill`` keeps it busy for 30 seconds with a child process of its own,
the way the real scanner keeps model calls in flight; any other skill is
answered at once. Every run is logged, so a fallback the engine should not
have started is visible.

Run from the package root::

    python -m pytest tests/test_client_disconnect.py -v
"""
from __future__ import annotations

import asyncio
import io
import json
import os
import signal
import socket
import sys
import threading
import time
import zipfile
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server  # noqa: E402

# How long the stand-in scanner works on a slow skill. Far longer than any
# bound below, so a scan that was not stopped is unmistakable.
SLOW_SCAN_SECONDS = 30

# How soon after the hang-up the slot must be free. A cancelled scan stops in
# well under a second; the margin is for a loaded CI runner, and is still two
# orders of magnitude below the engine's deadline.
RELEASE_WITHIN = 5.0

ENDPOINTS = ["/scan", "/scan/bundle"]

FAKE_SCANNER = r'''#!/usr/bin/env python3
"""A stand-in skillspector that logs each run and can be made slow."""
import json
import os
import subprocess
import sys
import time

argv = sys.argv[1:]
target = argv[1]
out = argv[argv.index("--output") + 1]
mode = "static" if "--no-llm" in argv else "llm"
manifest = os.path.join(target, "SKILL.md") if os.path.isdir(target) else target
with open(manifest, encoding="utf-8") as fh:
    slow = "slow-skill" in fh.read()

seconds = os.environ["FAKE_SCAN_SECONDS"]
record = {
    "pid": os.getpid(),
    "child": None,
    "mode": mode,
    "base_url": os.environ.get("OPENAI_BASE_URL", ""),
}
if slow:
    # Same process group as this scanner, as anything the real one starts is.
    # The log path is on its command line so the test can tell it from a
    # process that happens to reuse the pid.
    child = subprocess.Popen(
        [sys.executable, "-c", "import sys, time; time.sleep(float(sys.argv[1]))",
         seconds, os.environ["FAKE_SCAN_LOG"]]
    )
    record["child"] = child.pid
with open(os.environ["FAKE_SCAN_LOG"], "a", encoding="utf-8") as fh:
    fh.write(json.dumps(record) + "\n")
if slow:
    time.sleep(float(seconds))

report = {
    "skill": {"name": "slow-skill" if slow else "quick-skill", "source": target},
    "risk_assessment": {"score": 0, "severity": "LOW", "recommendation": "SAFE"},
    "issues": [],
    "components": [{"path": "SKILL.md", "type": "manifest"}],
    "metadata": {
        "skillspector_version": "2.3.9",
        "llm_requested": mode == "llm",
        "meta_analysis_applied": mode == "llm",
    },
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(report, fh)
sys.exit(0)
'''


# ---------------------------------------------------------------------------
# The stand-ins: scanner, router, slots
# ---------------------------------------------------------------------------


class _ScannerRuns:
    """What the stand-in scanner did, read back from its log."""

    def __init__(self, log: Path, marker: str) -> None:
        self.log = log
        self.marker = marker

    def all(self) -> list[dict[str, Any]]:
        if not self.log.exists():
            return []
        runs = []
        for line in self.log.read_text(encoding="utf-8").splitlines():
            try:
                runs.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # a line still being written
        return runs

    def alive(self, pid: int | None) -> bool:
        """Whether *pid* is one of this test's scanner processes and still running.

        A killed process that has not been reaped yet is a zombie with an empty
        command line, so it counts as dead, which is what it is.
        """
        if pid is None:
            return False
        try:
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().decode(errors="replace")
        except OSError:
            return False
        return self.marker in cmdline

    def kill_all(self) -> None:
        for run in self.all():
            for pid in (run["pid"], run["child"]):
                if self.alive(pid):
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass


@pytest.fixture
def scanner(tmp_path, monkeypatch):
    """Put the stand-in ``skillspector`` first on PATH, static mode by default."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "skillspector"
    script.write_text(FAKE_SCANNER, encoding="utf-8")
    script.chmod(0o755)
    log = tmp_path / "scanner-runs.jsonl"
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_SCAN_LOG", str(log))
    monkeypatch.setenv("FAKE_SCAN_SECONDS", str(SLOW_SCAN_SECONDS))
    monkeypatch.delenv("LITELLM_BASE_URL", raising=False)
    monkeypatch.delenv("SKILLCHECK_LLM_API_KEY", raising=False)
    runs = _ScannerRuns(log, str(tmp_path))
    yield runs
    runs.kill_all()


@pytest.fixture
def litellm(scanner, monkeypatch):
    """A LiteLLM that is up, so the scan takes the LLM path through its proxy.

    The stand-in scanner never asks it for a completion; it only has to answer
    the liveness probe the engine sends before an LLM scan.
    """

    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args) -> None:  # noqa: ANN002
            pass

        def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
            body = b'{"status": "healthy"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[:2]
    monkeypatch.setenv("LITELLM_BASE_URL", f"http://{host}:{port}")
    monkeypatch.setenv("SKILLCHECK_LLM_API_KEY", "sk-cerase-svc-skillcheck")
    yield
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=5)


class _Slots:
    """The engine's slot semaphore, recording which threads have asked for one."""

    def __init__(self, count: int) -> None:
        self.count = count
        self._sem = threading.BoundedSemaphore(count)
        self._lock = threading.Lock()
        self._askers: set[int] = set()
        self._held = 0

    def acquire(self, blocking: bool = True, timeout: float | None = None) -> bool:
        with self._lock:
            self._askers.add(threading.get_ident())
        return self._sem.acquire(blocking, timeout)

    def release(self) -> None:
        self._sem.release()

    @property
    def askers(self) -> int:
        with self._lock:
            return len(self._askers)

    def hold_all(self) -> None:
        """Take every slot, standing in for scans already running."""
        for _ in range(self.count):
            self._sem.acquire()
            self._held += 1

    def release_held(self) -> None:
        while self._held:
            self._held -= 1
            self._sem.release()

    def free(self) -> int:
        """How many slots could be taken right now. Gives them straight back."""
        taken = 0
        while self._sem.acquire(blocking=False):
            taken += 1
        for _ in range(taken):
            self._sem.release()
        return taken


def _install_slots(monkeypatch, count: int) -> _Slots:
    slots = _Slots(count)
    monkeypatch.setattr(server, "_scan_slots", slots)
    monkeypatch.setattr(server, "_MAX_CONCURRENT_SCANS", count)
    return slots


# ---------------------------------------------------------------------------
# One HTTP connection, spoken to the app the way uvicorn speaks to it
# ---------------------------------------------------------------------------


class _Connection:
    """One request to the ASGI app over a connection the test can close.

    ``receive()`` hands over the whole body, then blocks until the connection
    closes and answers ``http.disconnect``, which is what uvicorn's does. The
    connection closes when the test hangs up or when the response is complete.
    """

    def __init__(self, method: str, path: str, body: bytes, headers: list[tuple[bytes, bytes]]) -> None:
        self.scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "root_path": "",
            "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 50000),
            "server": ("skillcheck.test", 80),
            "state": {},
        }
        self._body = body
        self._delivered = False
        self._closed = asyncio.Event()
        self.status: int | None = None
        self.body = b""
        self.task: asyncio.Task | None = None

    async def _receive(self) -> dict[str, Any]:
        if not self._delivered:
            self._delivered = True
            return {"type": "http.request", "body": self._body, "more_body": False}
        await self._closed.wait()
        return {"type": "http.disconnect"}

    async def _send(self, message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            self.status = message["status"]
        elif message["type"] == "http.response.body":
            self.body += message.get("body", b"")
            if not message.get("more_body", False):
                self._closed.set()

    def open(self) -> _Connection:
        self.task = asyncio.ensure_future(server.app(self.scope, self._receive, self._send))
        return self

    def hang_up(self) -> None:
        self._closed.set()

    def json(self) -> Any:
        return json.loads(self.body)


def _skill_md(name: str) -> str:
    return f"---\nname: {name}\ndescription: disconnect fixture.\n---\nSay hello.\n"


def _scan_request(endpoint: str, skill: str) -> _Connection:
    """A scan request for *skill*, encoded as a real client would send it."""
    if endpoint == "/scan":
        request = httpx.Request("POST", "http://skillcheck.test/scan", json={"skill_md": _skill_md(skill)})
    else:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("SKILL.md", _skill_md(skill))
        request = httpx.Request(
            "POST",
            "http://skillcheck.test/scan/bundle",
            files={"file": ("skill.zip", buf.getvalue(), "application/zip")},
        )
    body = request.read()
    headers = [(k.lower().encode(), v.encode()) for k, v in request.headers.items()]
    return _Connection("POST", endpoint, body, headers)


async def _healthz() -> dict[str, Any]:
    conn = _Connection("GET", "/healthz", b"", [(b"host", b"skillcheck.test")]).open()
    await asyncio.wait_for(conn.task, 5)
    assert conn.status == 200
    return conn.json()


async def _wait_for(probe: Callable[[], Any], failure: str, timeout: float = 15.0) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = probe()
        if value:
            return value
        await asyncio.sleep(0.05)
    pytest.fail(failure)


async def _finishes_within(conn: _Connection, seconds: float, failure: str) -> None:
    await asyncio.wait({conn.task}, timeout=seconds)
    assert conn.task.done(), failure


async def _drain(conn: _Connection | None, runs: _ScannerRuns, limit: float = 90.0) -> None:
    """Leave no request running and no scanner alive, whatever the test found.

    Without this, a scan the code under test failed to stop would keep its
    worker thread and its slot into the next test.
    """
    if conn is None or conn.task is None:
        return
    conn.hang_up()
    deadline = time.monotonic() + limit
    while not conn.task.done() and time.monotonic() < deadline:
        runs.kill_all()
        await asyncio.wait({conn.task}, timeout=0.2)
    if conn.task.done() and not conn.task.cancelled():
        conn.task.exception()


def _refuses_connections(base_url: str) -> bool:
    parts = urlsplit(base_url)
    try:
        with socket.create_connection((parts.hostname, parts.port), timeout=1):
            return False
    except OSError:
        return True


# ---------------------------------------------------------------------------
# The tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("endpoint", ENDPOINTS)
def test_an_abandoned_scan_is_stopped_and_frees_its_slot(endpoint, scanner, litellm, monkeypatch):
    """The client hangs up mid-scan: process group killed, proxy stopped, no fallback, slot free.

    The LLM path, because it is the one with the most to leave behind: a proxy
    thread, a scanner with a child, and a static fallback that a ``ScanError``
    would start. On the code this was written against the request is still
    running long after the hang-up, because nothing is listening for it.
    """
    slots = _install_slots(monkeypatch, 2)

    async def scenario() -> None:
        conn = _scan_request(endpoint, "slow-skill").open()
        try:
            run = await _wait_for(
                lambda: next((r for r in scanner.all() if r["mode"] == "llm"), None),
                "the LLM scan never started",
            )
            assert scanner.alive(run["pid"]) and scanner.alive(run["child"])
            assert (await _healthz())["scans_in_flight"] == 1

            conn.hang_up()
            await _finishes_within(
                conn,
                RELEASE_WITHIN,
                f"the scan was still running {RELEASE_WITHIN:.0f}s after its client hung up",
            )

            assert (await _healthz())["scans_in_flight"] == 0
            assert slots.free() == 2, "the abandoned scan still holds a slot"
            assert not scanner.alive(run["pid"]), "the scanner was not killed"
            assert not scanner.alive(run["child"]), "the scanner's process group was not killed"
            assert _refuses_connections(run["base_url"]), "the completion proxy is still serving"
            assert [r["mode"] for r in scanner.all()] == ["llm"], (
                "a static fallback was started for a client that had gone"
            )
        finally:
            await _drain(conn, scanner)

    asyncio.run(scenario())


@pytest.mark.parametrize("endpoint", ENDPOINTS)
def test_an_abandoned_wait_for_a_slot_takes_no_slot(endpoint, scanner, monkeypatch):
    """Every slot is busy, the client waiting for one hangs up: it stops waiting.

    On the code this was written against, the waiter keeps waiting for as long
    as its deadline allows, and takes the first slot that frees up to run a
    scan whose verdict nobody will read.
    """
    slots = _install_slots(monkeypatch, 1)
    slots.hold_all()

    async def scenario() -> None:
        conn = _scan_request(endpoint, "quick-skill").open()
        try:
            await _wait_for(lambda: slots.askers >= 1, "the request never asked for a slot")

            conn.hang_up()
            await _finishes_within(
                conn,
                RELEASE_WITHIN,
                f"the request was still waiting for a slot {RELEASE_WITHIN:.0f}s after "
                "its client hung up",
            )

            slots.release_held()
            assert slots.free() == 1, "the abandoned request took the slot"
            assert scanner.all() == [], "the abandoned request ran a scan"
            assert (await _healthz())["scans_in_flight"] == 0
        finally:
            slots.release_held()
            await _drain(conn, scanner)

    asyncio.run(scenario())


@pytest.mark.parametrize("endpoint", ENDPOINTS)
def test_the_next_client_gets_the_slot_an_abandoned_scan_held(endpoint, scanner, monkeypatch):
    """One slot. A slow scan is abandoned; the client queued behind it gets its verdict.

    The client that stays must receive the verdict its scan produced, within
    seconds of the other client leaving rather than after the abandoned scan
    has run out its 30 seconds. On the code this was written against it waits
    the full time.
    """
    slots = _install_slots(monkeypatch, 1)

    async def scenario() -> None:
        gone = _scan_request(endpoint, "slow-skill").open()
        staying = None
        try:
            await _wait_for(scanner.all, "the first scan never started")
            staying = _scan_request(endpoint, "quick-skill").open()
            await _wait_for(
                lambda: slots.askers >= 2,
                "the second request never asked for a slot",
            )

            gone.hang_up()
            await _finishes_within(
                staying,
                RELEASE_WITHIN,
                f"the client that stayed had no verdict {RELEASE_WITHIN:.0f}s after the "
                "slot's holder hung up",
            )

            assert staying.status == 200, staying.body
            verdict = staying.json()
            assert verdict["skill_name"] == "quick-skill"
            assert verdict["recommendation"] == "SAFE"
            assert verdict["mode"] == server.MODE_STATIC
            assert verdict["degraded"] is False
            assert gone.task.done()
        finally:
            await _drain(gone, scanner)
            await _drain(staying, scanner)

    asyncio.run(scenario())
