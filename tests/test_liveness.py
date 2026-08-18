"""The scanner must stay answerable while it is scanning.

These tests exist because it was not. ``POST /scan/bundle`` was an ``async def``
that called the blocking scan directly, so it held uvicorn's only event loop for
the whole scan and every request behind it — the health probe included — waited.
Measured against the live service: one real bundle scan ran 237 seconds, and
across those 237 seconds **19 consecutive /healthz probes hit their 10s ceiling
and returned nothing**; the first probe served afterwards took 7.0s, because it
had been queued the entire time. The container was marked unhealthy for doing
the one thing it exists for, and the caller read that as an outage.

Nothing in the previous suite could have caught it: every test either drove a
live service one request at a time, or exercised pure helpers. The defect only
exists when a second request arrives during the first.

Three kinds of guard, deliberately different:

  1. **Behavioural** — drive the ASGI app with two concurrent requests and
     require the health probe to finish FIRST. Run against the pre-fix code the
     scan finishes first, every time, because the loop cannot do anything else.
  2. **Structural** — no ``async def`` in server.py may call a blocking function
     directly. This catches the next endpoint written the same way, before it
     ships, without needing a slow scan to reproduce.
  3. **The image** — the HEALTHCHECK numbers and the init that reaps its probes.
     They are what the container the fleet runs actually gets, because the
     control-plane's starter creates it with ``docker run``.

Run from the package root::

    python -m pytest tests/test_liveness.py -v
"""
from __future__ import annotations

import ast
import asyncio
import io
import re
import sys
import threading
import time
import zipfile
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server  # noqa: E402

# How long the stand-in scan blocks its worker. Long enough that a blocked event
# loop is unmistakable, short enough to keep the suite fast.
FAKE_SCAN_SECONDS = 2.0


def _bundle_bytes() -> bytes:
    """A minimal, valid .zip skill bundle for the upload path."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("SKILL.md", "---\nname: probe\ndescription: liveness fixture.\n---\n")
    return buf.getvalue()


def _fake_verdict() -> server.Verdict:
    return server.Verdict(
        score=0,
        severity="LOW",
        recommendation="SAFE",
        findings=[],
        scanner_version="test",
        mode=server.MODE_STATIC,
    )


@pytest.fixture
def slow_scan(monkeypatch):
    """Replace the scanner with a call that blocks its thread, as a real one does.

    It also enters the real scan-slot bookkeeping, so ``scans_in_flight`` is
    exercised rather than assumed.
    """
    entered = threading.Event()

    def _blocking_scan(target, *, partial):  # noqa: ANN001, ARG001
        budget = server.Budget(server._SCAN_DEADLINE)
        with server._scan_slot(budget):
            entered.set()
            time.sleep(FAKE_SCAN_SECONDS)
            return _fake_verdict()

    monkeypatch.setattr(server, "_scan_target", _blocking_scan)
    return entered


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=server.app),
        base_url="http://skillcheck.test",
        timeout=FAKE_SCAN_SECONDS * 10,
    )


def test_healthz_answers_before_a_bundle_scan_finishes(slow_scan):
    """/healthz must come back while /scan/bundle is still working.

    The scan request is created first, so the loop reaches it first. If it runs
    the scan inline, the health request cannot even start until the scan is
    done and the assertion below fails — which is precisely the shipped
    behaviour this test was written against.
    """

    async def scenario() -> None:
        async with _client() as client:
            scan = asyncio.create_task(
                client.post(
                    "/scan/bundle",
                    files={"file": ("skill.zip", _bundle_bytes(), "application/zip")},
                )
            )
            health = asyncio.create_task(client.get("/healthz"))

            done, _ = await asyncio.wait({scan, health}, return_when=asyncio.FIRST_COMPLETED)
            assert health in done, (
                "/healthz did not answer until the scan had finished — the scan is "
                "holding the event loop"
            )
            assert health.result().status_code == 200

            assert (await scan).status_code == 200

    asyncio.run(scenario())


def test_healthz_reports_the_scan_it_is_running(slow_scan):
    """A busy scanner says it is busy, instead of saying nothing.

    ``scans_in_flight`` is what lets a caller tell "working" from "wedged"; a
    probe that only ever answers ``ok`` forces the reader to infer it from a
    silence, and the inference it invites is that the service is down.
    """

    async def scenario() -> None:
        async with _client() as client:
            idle = await client.get("/healthz")
            assert idle.json()["scans_in_flight"] == 0
            assert idle.json()["busy"] is False

            scan = asyncio.create_task(
                client.post(
                    "/scan/bundle",
                    files={"file": ("skill.zip", _bundle_bytes(), "application/zip")},
                )
            )
            await asyncio.to_thread(slow_scan.wait, 10)

            busy = await client.get("/healthz")
            assert busy.status_code == 200
            body = busy.json()
            assert body["scans_in_flight"] == 1
            assert body["busy"] is True
            assert body["oldest_scan_seconds"] >= 0

            await scan
            assert (await client.get("/healthz")).json()["scans_in_flight"] == 0

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Structural guard — the shape that caused it must not come back
# ---------------------------------------------------------------------------

# Functions that block their thread. Called from an `async def` they block the
# event loop, which is the whole service.
BLOCKING_CALLS = {
    "_scan_target",
    "_scan_bundle_payload",
    "_run_skillspector",
    "_litellm_reachable",
    "_safe_extract_zip",
}


def test_no_async_handler_calls_a_blocking_function_directly():
    """An ``async def`` may name a blocking function, never call one.

    Handing it to ``run_in_threadpool`` passes the name as an argument and so is
    allowed; invoking it puts a subprocess wait on the event loop. That
    distinction is the entire fix, so the guard matches the call and not the
    mention.
    """
    source = Path(server.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef):
            continue
        for inner in ast.walk(node):
            if not isinstance(inner, ast.Call):
                continue
            func = inner.func
            name = func.id if isinstance(func, ast.Name) else None
            if name in BLOCKING_CALLS:
                offenders.append(f"{node.name}() calls {name}() on line {inner.lineno}")
            if isinstance(func, ast.Attribute) and func.attr in {"run", "communicate", "urlopen", "sleep"}:
                base = func.value
                if isinstance(base, ast.Name) and base.id in {"subprocess", "time"}:
                    offenders.append(f"{node.name}() calls {base.id}.{func.attr}() on line {inner.lineno}")

    assert offenders == [], (
        "blocking work on the event loop — hand it to run_in_threadpool instead:\n  "
        + "\n  ".join(offenders)
    )


def test_healthz_is_an_async_handler():
    """Liveness is answered on the loop, not from a worker it has to compete for.

    A sync ``def`` handler is dispatched to the threadpool, so a burst of scans
    can starve the probe of a thread even with the loop free. The one endpoint
    that must always answer is the one that must not need a worker.
    """
    assert asyncio.iscoroutinefunction(server.healthz)


# ---------------------------------------------------------------------------
# The image, which is where this container's real healthcheck comes from
# ---------------------------------------------------------------------------

DOCKERFILE = Path(__file__).resolve().parent.parent / "Dockerfile"

# cerase-core's docker-compose.yml declares a healthcheck for this service too,
# and the two are NOT overrides of each other: the container the fleet runs is
# created by the control-plane's on-demand starter with `docker run`, which
# carries the image's and nothing from compose. They disagreed once — 5s in the
# file being read, 10s on the container being debugged — and an operator spent
# an afternoon on the gap. Each repo pins the pair from its own end, because CI
# checks out one repo and a test that reads the other runs nowhere that stops a
# push. Change these and change tests/unit/skillcheck_liveness.bats over there.
EXPECTED_HEALTHCHECK_FLAGS = {
    "interval": "30s",
    "timeout": "10s",
    "start-period": "40s",
    "retries": "3",
}


def _healthcheck_instruction() -> str:
    text = DOCKERFILE.read_text(encoding="utf-8")
    match = re.search(r"^HEALTHCHECK .*?(?=\n[A-Z]+ |\Z)", text, re.M | re.S)
    assert match, "the image declares no HEALTHCHECK"
    return match.group(0)


def test_the_image_healthcheck_matches_what_compose_was_pinned_to():
    instruction = _healthcheck_instruction()
    wrong = {}
    for flag, expected in EXPECTED_HEALTHCHECK_FLAGS.items():
        found = re.search(rf"--{flag}=(\S+)", instruction)
        actual = found.group(1) if found else None
        if actual != expected:
            wrong[flag] = (actual, expected)
    assert not wrong, f"healthcheck flags drifted from the compose pin: {wrong}"


def test_the_probe_carries_its_own_timeout():
    """A probe the daemon has to kill logs an empty line instead of a reason.

    The health log the operator read said only "Health check exceeded timeout
    (10s)" with no output at all, because the daemon killed a probe that had no
    deadline of its own.
    """
    instruction = _healthcheck_instruction()
    assert "/healthz" in instruction
    assert "timeout=5" in instruction


def test_pid_one_is_an_init():
    """A process the daemon execs in is reparented to PID 1, which must reap it.

    uvicorn reaps only when its event loop runs, so a blocked loop accumulates
    them: eleven zombies were counted in a container whose loop a scan was
    holding, and zero in the same container once it was free. In the image
    rather than a compose `init: true`, for the same reason as the healthcheck
    above.
    """
    text = DOCKERFILE.read_text(encoding="utf-8")
    entrypoint = re.search(r"^ENTRYPOINT .*$", text, re.M)
    assert entrypoint, "no ENTRYPOINT"
    assert '"/usr/bin/tini"' in entrypoint.group(0), (
        f"PID 1 is not an init: {entrypoint.group(0)}"
    )
