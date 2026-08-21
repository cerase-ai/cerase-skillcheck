#!/usr/bin/env python3
"""cerase-skillcheck — defensive security scan for third-party skills.

A small HTTP service (FastAPI) that wraps the NVIDIA **skillspector** scanner
(Apache-2.0, https://github.com/NVIDIA/skillspector) so the Cerase platform can
WARN a user, in plain language, before they install a risky third-party skill.

This is DEFENSIVE tooling: the verdict is **advisory only** — it never blocks
an install and never quarantines anything. A caller (the control-plane at an
import chokepoint, or an agent via a CLI recipe) POSTs a skill and gets back a
risk verdict it can surface to the user, who always retains the final choice.

Analysis modes (M-SKILLSCAN-2)
  - **static**  — skillspector's local ruleset only (`--no-llm`). Always
    available, dependency-free, no egress.
  - **llm**     — static ruleset PLUS skillspector's LLM intent analysis,
    routed through **our** LiteLLM (never a third-party endpoint). Enabled
    only when `LITELLM_BASE_URL` + `SKILLCHECK_LLM_API_KEY` are configured.

  LLM mode routes skillspector's OpenAI provider at our LiteLLM: it honours a
  custom `OPENAI_BASE_URL` and reads `OPENAI_API_KEY` (verified against the
  pinned source), so we point it at `${LITELLM_BASE_URL}/v1` with the service
  virtual key `cerase-svc-skillcheck` and the `core` model alias. No new
  sub-processor: whatever `core` maps to is our existing routing/metering.

  **Degrade to static** — a model outage must never block a scan. When LiteLLM
  is unreachable, misconfigured, or the LLM stage fails at runtime, the scan
  still returns a *static* verdict flagged `degraded: true` instead of erroring.

  **What counts as an LLM pass is measured, not read off the report.** The
  scanner's own `meta_analysis_applied` cannot carry this fact: three of its
  four LLM nodes run their batches through `LLMAnalyzerBase.arun_batches`,
  which drops a failed batch and returns the survivors, so a node whose every
  call was rejected still records a successful LLM call and the report claims
  an applied LLM pass. Measured with a key the router rejects: every call 401s,
  a bundle finishes in 2.4s instead of 187s, and the verdict was `SAFE / LOW /
  0` with `degraded: false`. So the LLM traffic is routed through a loopback
  forwarder (`_CompletionProxy`) that counts the responses actually carrying
  output; a stage that was requested and produced none is `static` +
  `degraded: true`, exactly like one that ran out of time. The count is the
  discriminator, never the reason for the failure — a rejected key, a rate
  limit, a refused connection and a 200 with an empty `choices` array are all
  the same fact to a caller.

Endpoints
  GET  /healthz        liveness + scanner version + LLM configuration + how many
                       scans are running right now.
  POST /scan           JSON {path?|skill_md?} → verdict (mounted dir/file, or
                       raw SKILL.md content).
  POST /scan/bundle    multipart upload of a .zip skill bundle → verdict.

Liveness while busy
  A scan is a blocking subprocess that can run for minutes. Every scan therefore
  runs in the threadpool and NEVER on the event loop, so ``/healthz`` — an async
  handler that touches nothing but memory — is answered while scans are in
  flight. This is not a refinement: an ``async def`` endpoint that called the
  scan directly held the only event loop for the whole scan, and every request
  behind it, health probe included, sat unanswered until the scan returned. The
  container was then marked unhealthy for doing the one thing it exists for, and
  the caller read that as an outage.

  ``/healthz`` reports ``scans_in_flight`` and ``busy`` so a reader can tell a
  working scanner from a stuck one instead of inferring it from a silence.

Verdict JSON
  {
    "score": 0-100,                              # skillspector risk score
    "severity": "LOW|MEDIUM|HIGH|CRITICAL",
    "recommendation": "SAFE|CAUTION|DO_NOT_INSTALL",
    "findings": [ ... ],                         # skillspector issues[]
    "scanner_version": "2.3.9",
    "mode": "static" | "llm",                    # analysis actually performed
    "degraded": bool,                            # LLM requested but fell back
    "partial": bool,                             # true = SKILL.md-only scan
    "skill_name": str|null,
    "components_scanned": int
  }

skillspector invocation
  We shell out to the pinned CLI:
      skillspector scan <target> [--no-llm] --format json --output <tmp.json>
  and read the JSON report from the output file (decoupled from any console
  chatter on stdout). Exit code 0 (score<=50) and 1 (score>50) both produce a
  valid report; exit 2 is a real error (mapped to a degrade fallback in LLM
  mode). skillspector's SC4 supply-chain check may reach out to OSV.dev; when
  the network is unavailable it degrades automatically to a built-in fallback
  list, so the verdict is still returned offline.

Env
  PORT                       listen port (default 8000).
  SKILLCHECK_SCAN_TIMEOUT    static-scan subprocess timeout, seconds (def 180).
  SKILLCHECK_LLM_SCAN_TIMEOUT LLM-scan subprocess timeout, seconds (def 300).
  SKILLCHECK_SCAN_DEADLINE   wall-clock ceiling for ONE request, seconds (def
                             420), covering the LLM attempt AND the static
                             fallback AND any wait for a scan slot. Without it
                             the two step timeouts add up (300 + 180) and no
                             single number bounds a request.
  SKILLCHECK_MAX_CONCURRENT_SCANS how many skillspector subprocesses may run at
                             once (default 2). Each is a heavy tree; further
                             requests wait for a slot inside their own deadline.
  SKILLCHECK_MAX_UPLOAD      max bundle upload size, bytes (default 25 MiB).
  LITELLM_BASE_URL           our LiteLLM base (e.g. http://cerase-litellm:4000).
                             Enables LLM mode when set together with the key.
  SKILLCHECK_LLM_API_KEY     the LiteLLM service virtual key (cerase-svc-
                             skillcheck). NEVER the master key. Enables LLM mode.
  SKILLCHECK_LLM_MODEL       model alias to route at (default "core"; a cheaper
                             switch is e.g. "spark").
  SKILLCHECK_LLM_PROBE_TIMEOUT reachability-probe timeout, seconds (default 5).
"""
from __future__ import annotations

import contextlib
import itertools
import json
import logging
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, UploadFile
from pydantic import BaseModel, Field, model_validator
from starlette.concurrency import run_in_threadpool

logger = logging.getLogger("cerase-skillcheck")

MODE_STATIC = "static"
MODE_LLM = "llm"
_VALID_RECOMMENDATIONS = {"SAFE", "CAUTION", "DO_NOT_INSTALL"}
_VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

_SCAN_TIMEOUT = int(os.environ.get("SKILLCHECK_SCAN_TIMEOUT", "180"))
_LLM_SCAN_TIMEOUT = int(os.environ.get("SKILLCHECK_LLM_SCAN_TIMEOUT", "300"))
_SCAN_DEADLINE = float(os.environ.get("SKILLCHECK_SCAN_DEADLINE", "420"))
_MAX_CONCURRENT_SCANS = max(1, int(os.environ.get("SKILLCHECK_MAX_CONCURRENT_SCANS", "2")))
_MAX_UPLOAD = int(os.environ.get("SKILLCHECK_MAX_UPLOAD", str(25 * 1024 * 1024)))
_PROBE_TIMEOUT = float(os.environ.get("SKILLCHECK_LLM_PROBE_TIMEOUT", "5"))
_DEFAULT_LLM_MODEL = "core"

app = FastAPI(
    title="cerase-skillcheck",
    summary="Defensive security scan for third-party agent skills.",
    version="2",
)

_SCANNER_VERSION: str | None = None


def _scanner_version() -> str:
    """skillspector package version, resolved once and then held in memory.

    ``/healthz`` reads this on the event loop, so it must never reach the disk
    after the first call: reading package metadata is cheap but it is still I/O,
    and the whole point of that handler is that it can answer while every worker
    is busy.
    """
    global _SCANNER_VERSION
    if _SCANNER_VERSION is None:
        try:
            _SCANNER_VERSION = _pkg_version("skillspector")
        except PackageNotFoundError:
            _SCANNER_VERSION = "unknown"
    return _SCANNER_VERSION


# ---------------------------------------------------------------------------
# Scan admission: a wall-clock budget per request + a bounded number of slots
# ---------------------------------------------------------------------------


class Budget:
    """The wall-clock allowance for ONE scan request, shared by every step.

    A scan can run the LLM stage, fail, and then run a full static fallback; the
    two step timeouts are independent, so before this the only ceiling on a
    request was their sum. Every blocking step asks the budget how much time is
    left and takes the smaller of that and its own timeout, so one request has
    one number bounding it end to end.
    """

    def __init__(self, seconds: float) -> None:
        self.total = max(1.0, float(seconds))
        self._deadline = time.monotonic() + self.total

    def remaining(self) -> float:
        return self._deadline - time.monotonic()


_scan_slots = threading.BoundedSemaphore(_MAX_CONCURRENT_SCANS)
_scan_registry_lock = threading.Lock()
_scan_registry: dict[int, float] = {}
_scan_ids = itertools.count(1)


@contextlib.contextmanager
def _scan_slot(budget: Budget) -> Iterator[None]:
    """Hold one scan slot for the duration of a scan, or fail inside the budget.

    Each skillspector run is a heavy subprocess, so the number that may run at
    once is bounded rather than left to however many requests arrive. A request
    that cannot get a slot waits only as long as its own budget allows and then
    fails as a scan error — never indefinitely, and never silently.
    """
    wait = budget.remaining()
    if wait <= 0 or not _scan_slots.acquire(timeout=wait):
        raise ScanError(
            f"no scan slot free within {budget.total:.0f}s "
            f"({_MAX_CONCURRENT_SCANS} concurrent scans allowed)"
        )
    scan_id = next(_scan_ids)
    with _scan_registry_lock:
        _scan_registry[scan_id] = time.monotonic()
    try:
        yield
    finally:
        with _scan_registry_lock:
            _scan_registry.pop(scan_id, None)
        _scan_slots.release()


def _scans_in_flight() -> tuple[int, float]:
    """(how many scans are running, how long the oldest has been running)."""
    with _scan_registry_lock:
        started = list(_scan_registry.values())
    if not started:
        return 0, 0.0
    return len(started), time.monotonic() - min(started)


# ---------------------------------------------------------------------------
# LLM configuration (routes skillspector's OpenAI provider at our LiteLLM)
# ---------------------------------------------------------------------------


def _litellm_base_url() -> str:
    return os.environ.get("LITELLM_BASE_URL", "").strip()


def _llm_api_key() -> str:
    return os.environ.get("SKILLCHECK_LLM_API_KEY", "").strip()


def _llm_model() -> str:
    return os.environ.get("SKILLCHECK_LLM_MODEL", "").strip() or _DEFAULT_LLM_MODEL


def _llm_configured() -> bool:
    """LLM mode is available only when BOTH a base URL and a key are set.

    We deliberately require an explicit service key — never fall back to any
    ambient/master credential — so a scan cannot silently egress on the wrong
    identity. Absent either, the service runs static-only.
    """
    return bool(_litellm_base_url()) and bool(_llm_api_key())


def _litellm_root() -> str:
    """``LITELLM_BASE_URL`` without a trailing slash or ``/v1`` suffix.

    The variable is set both ways in the fleet. The scanner's endpoint, the
    liveness probe and the proxy's upstream are all built from this one root, so
    none of them can be pointed at ``/v1/v1`` or at ``/v1/health/liveliness``.
    """
    base = _litellm_base_url().rstrip("/")
    if base.endswith("/v1"):
        base = base[: -len("/v1")]
    return base


def _openai_base_url() -> str:
    """The OpenAI-compatible endpoint skillspector should call.

    skillspector's OpenAI provider passes ``OPENAI_BASE_URL`` straight into
    ``ChatOpenAI(base_url=...)``, whose client expects a ``/v1`` suffix. We
    normalise ``LITELLM_BASE_URL`` (the routing root, matching cerase-search's
    convention) into that shape.
    """
    return _litellm_root() + "/v1"


def _litellm_health_url() -> str:
    """LiteLLM's unauthenticated liveness endpoint (not under /v1)."""
    return _litellm_root() + "/health/liveliness"


def _base_scan_env() -> dict[str, str]:
    """Baseline environment for the skillspector subprocess.

    LangSmith tracing is force-disabled so a scan never phones home; HOME stays
    writable for any cache the scanner touches.
    """
    env = dict(os.environ)
    env["LANGCHAIN_TRACING_V2"] = "false"
    env["LANGCHAIN_TRACING"] = "false"
    env.setdefault("SKILLSPECTOR_LOG_LEVEL", "ERROR")
    # Strip any ambient OpenAI creds so a static run never has a stray endpoint.
    for key in ("OPENAI_API_KEY", "OPENAI_BASE_URL", "SKILLSPECTOR_PROVIDER", "SKILLSPECTOR_MODEL"):
        env.pop(key, None)
    return env


def _llm_scan_env(base_url: str | None = None) -> dict[str, str]:
    """Environment that points skillspector's OpenAI provider at our LiteLLM.

    Selects the OpenAI provider explicitly, supplies the service virtual key and
    our LiteLLM base_url, and pins every analyzer slot to the configured model
    alias (``SKILLSPECTOR_MODEL`` flows through ``constants.MODEL_CONFIG`` to
    all slots). NOT the master key, NOT CERASE_LLM_API_BASE.

    *base_url* overrides the endpoint the scanner calls. A scan passes the
    loopback address of its :class:`_CompletionProxy` there, which forwards to
    the same LiteLLM and counts what comes back; with it omitted the scanner
    talks to LiteLLM directly and nothing observes the completions.
    """
    env = _base_scan_env()
    env["SKILLSPECTOR_PROVIDER"] = "openai"
    env["OPENAI_API_KEY"] = _llm_api_key()
    env["OPENAI_BASE_URL"] = base_url or _openai_base_url()
    env["SKILLSPECTOR_MODEL"] = _llm_model()
    return env


def _litellm_reachable() -> bool:
    """Best-effort reachability probe for LiteLLM's liveness endpoint.

    Any HTTP response (even 4xx/5xx) means the host answered → reachable. Only a
    transport failure (DNS, connection refused, timeout) counts as unreachable,
    which lets a scan skip straight to a fast static degrade instead of waiting
    on per-call LLM timeouts against a dead endpoint.
    """
    url = _litellm_health_url()
    try:
        with urllib.request.urlopen(url, timeout=_PROBE_TIMEOUT):  # noqa: S310 (internal host)
            return True
    except urllib.error.HTTPError:
        # The server responded with an error status — it is reachable.
        return True
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        logger.warning("LiteLLM probe failed (%s): %s — degrading to static", url, exc)
        return False


# ---------------------------------------------------------------------------
# Counting the completions an LLM scan actually got back
# ---------------------------------------------------------------------------

# Hop-by-hop headers belong to one connection and must not be relayed onto the
# next; Host and Content-Length are rebuilt for the forwarded request.
_HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "content-length",
        "host",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }
)

# Endpoints whose answer IS the model's work. Everything else a client may call
# (model listings, health) is forwarded but never counted, so a scan cannot look
# like it got a completion because its client listed the models first.
_COMPLETION_PATHS = ("/chat/completions", "/completions", "/responses", "/messages")


def _choice_carries_output(choice: Any) -> bool:
    """Whether one element of ``choices`` holds text or a tool call."""
    if not isinstance(choice, dict):
        return False
    message = choice.get("message")
    if isinstance(message, dict) and (
        message.get("content") or message.get("tool_calls") or message.get("function_call")
    ):
        return True
    delta = choice.get("delta")
    if isinstance(delta, dict) and (delta.get("content") or delta.get("tool_calls")):
        return True
    return bool(choice.get("text"))


def _is_usable_completion(status: int, payload: bytes) -> bool:
    """Whether one model response carried output the analysis could use.

    A rejected key, a rate limit, a router error, an empty body and a 200 whose
    ``choices`` array is empty are one fact here: the analyzer that asked got
    nothing back. What produced the emptiness is the scanner's business, not the
    verdict's.
    """
    if not (200 <= status < 300) or not payload.strip():
        return False
    try:
        data = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        # A 2xx body that is not JSON is a stream of tokens, which is output.
        return True
    if not isinstance(data, dict) or data.get("error"):
        return False
    choices = data.get("choices")
    if choices is None:
        # An OpenAI-compatible endpoint of another shape answered 2xx with a
        # body; nothing here can prove it empty, so it counts.
        return True
    if not isinstance(choices, list) or not choices:
        return False
    return any(_choice_carries_output(c) for c in choices)


class _CompletionProxy:
    """Loopback forwarder between the scanner and LiteLLM that counts answers.

    The scan runs as a subprocess, so the only place the engine can see whether
    the LLM stage produced anything is the connection it opens. The proxy binds
    an ephemeral port on 127.0.0.1, relays every request to LiteLLM unchanged
    (Authorization included) and returns the answer verbatim, so the scanner
    behaves exactly as it does against the router itself. What it adds is the
    count of responses that carried output.

    It never logs a request body or a header: those hold the prompts and the
    service key.
    """

    def __init__(self, upstream: str, budget: Budget) -> None:
        self._upstream = upstream.rstrip("/")
        self._budget = budget
        self._lock = threading.Lock()
        self._attempted = 0
        self._usable = 0
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- counters -----------------------------------------------------------

    def _record(self, usable: bool) -> None:
        with self._lock:
            self._attempted += 1
            if usable:
                self._usable += 1

    @property
    def attempted_completions(self) -> int:
        with self._lock:
            return self._attempted

    @property
    def usable_completions(self) -> int:
        with self._lock:
            return self._usable

    # -- lifecycle ----------------------------------------------------------

    @property
    def base_url(self) -> str:
        """The value to hand the scanner as ``OPENAI_BASE_URL``."""
        if self._httpd is None:
            raise RuntimeError("completion proxy is not running")
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}/v1"

    def start(self) -> None:
        """Bind and serve. Raises OSError when no port can be opened."""
        proxy = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args: Any) -> None:
                pass

            def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
                proxy._forward(self, "GET")

            def do_POST(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
                proxy._forward(self, "POST")

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, name="skillcheck-llm-proxy", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop serving. Safe to call twice; the counts stay readable after."""
        if self._httpd is None:
            return
        httpd, self._httpd = self._httpd, None
        httpd.shutdown()
        httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=10)
            self._thread = None

    # -- forwarding ---------------------------------------------------------

    def _timeout(self) -> float:
        return max(1.0, min(float(_LLM_SCAN_TIMEOUT), self._budget.remaining()))

    def _forward(self, handler: BaseHTTPRequestHandler, method: str) -> None:
        length = int(handler.headers.get("Content-Length") or 0)
        body = handler.rfile.read(length) if length > 0 else b""
        headers = {
            key: value
            for key, value in handler.headers.items()
            if key.lower() not in _HOP_BY_HOP_HEADERS and key.lower() != "accept-encoding"
        }
        # The scanner's HTTP client asks for gzip, and urlopen hands back the
        # compressed bytes. Relaying those without their Content-Encoding would
        # give the client a body it cannot read and give the count below a body
        # it cannot parse, so the forwarded request asks for none.
        headers["Accept-Encoding"] = "identity"
        request = urllib.request.Request(  # noqa: S310 (internal host)
            self._upstream + handler.path,
            data=body if method == "POST" else None,
            headers=headers,
            method=method,
        )
        content_type = "application/json"
        content_encoding = None
        try:
            with urllib.request.urlopen(request, timeout=self._timeout()) as resp:
                status = resp.status
                payload = resp.read()
                content_type = resp.headers.get("Content-Type", content_type)
                content_encoding = resp.headers.get("Content-Encoding")
        except urllib.error.HTTPError as exc:
            status = exc.code
            payload = exc.read()
            if exc.headers is not None:
                content_type = exc.headers.get("Content-Type", content_type)
                content_encoding = exc.headers.get("Content-Encoding")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            # The router never answered. The scanner is told in the shape its
            # client understands, and the call counts as producing nothing.
            status = 502
            payload = json.dumps(
                {"error": {"message": f"LiteLLM did not answer: {exc}", "type": "upstream_error"}}
            ).encode("utf-8")

        # Matched without the query string, so a client that appends one (an
        # api-version, a deployment) is still counted and its scan is not
        # degraded for a call it did make.
        if handler.path.split("?", 1)[0].endswith(_COMPLETION_PATHS):
            self._record(_is_usable_completion(status, payload))

        handler.send_response(status)
        handler.send_header("Content-Type", content_type)
        # Kept only for a router that compresses anyway: the body relayed below
        # is byte-for-byte what came back, so the client must be told how to
        # read it.
        if content_encoding and content_encoding.lower() != "identity":
            handler.send_header("Content-Encoding", content_encoding)
        handler.send_header("Content-Length", str(len(payload)))
        handler.end_headers()
        handler.wfile.write(payload)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """Scan input: exactly one of a mounted path or raw SKILL.md content."""

    path: str | None = Field(
        default=None,
        description="Path (already mounted in this container) to a skill directory "
        "or a single SKILL.md file to scan.",
    )
    skill_md: str | None = Field(
        default=None,
        description="Raw SKILL.md content to scan directly (SKILL.md-only = partial "
        "coverage; used when only the manifest is available).",
    )

    @model_validator(mode="after")
    def _exactly_one(self) -> ScanRequest:
        if bool(self.path) == bool(self.skill_md):
            raise ValueError("provide exactly one of 'path' or 'skill_md'")
        return self


class Verdict(BaseModel):
    score: int
    severity: str
    recommendation: str
    findings: list[dict[str, Any]]
    scanner_version: str
    mode: str = MODE_STATIC
    degraded: bool = False
    partial: bool = False
    skill_name: str | None = None
    components_scanned: int = 0


class ScanError(RuntimeError):
    """skillspector failed to produce a report (non-verdict error)."""


# ---------------------------------------------------------------------------
# skillspector subprocess + verdict mapping
# ---------------------------------------------------------------------------


def _kill_process_tree(proc: subprocess.Popen[str]) -> None:
    """Kill the scan subprocess AND anything it started.

    The scanner is launched in its own session, so one signal to the process
    group reaches whatever it spawned. Killing the direct child alone leaves an
    orphan holding the upstream connection we are timing out on, which is the
    opposite of a bounded scan.
    """
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        with contextlib.suppress(ProcessLookupError, OSError):
            proc.kill()


def _run_skillspector(
    target: Path, *, use_llm: bool, budget: Budget, llm_base_url: str | None = None
) -> dict[str, Any]:
    """Run skillspector on *target* and return its parsed JSON report.

    ``use_llm=False`` passes ``--no-llm`` (static-only). ``use_llm=True`` runs
    the full analysis with skillspector's OpenAI provider pointed at
    *llm_base_url* (the scan's completion proxy) or, absent one, straight at our
    LiteLLM. The step timeout is the smaller of its own ceiling and what is left
    of the request's *budget*. Raises :class:`ScanError` when no report is
    produced.

    ALWAYS runs on a worker thread, never on the event loop — see the module
    docstring. It blocks for as long as the scan takes.
    """
    env = _llm_scan_env(llm_base_url) if use_llm else _base_scan_env()
    step = float(_LLM_SCAN_TIMEOUT if use_llm else _SCAN_TIMEOUT)
    timeout = min(step, budget.remaining())
    if timeout <= 0:
        raise ScanError(f"scan budget of {budget.total:.0f}s exhausted before the scan could start")

    with tempfile.TemporaryDirectory(prefix="skillcheck-out-") as outdir:
        report_path = Path(outdir) / "report.json"
        cmd = ["skillspector", "scan", str(target)]
        if not use_llm:
            cmd.append("--no-llm")
        cmd += ["--format", "json", "--output", str(report_path)]
        try:
            proc = subprocess.Popen(  # noqa: S603 (fixed argv, no shell)
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                start_new_session=True,
            )
        except FileNotFoundError as exc:  # skillspector binary missing
            raise ScanError("skillspector executable not found") from exc

        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            _kill_process_tree(proc)
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.communicate(timeout=10)
            raise ScanError(f"scan timed out after {timeout:.0f}s and was killed") from exc

        # Exit 0 = clean/low, 1 = risky (score>50) — both still write a report.
        # Exit 2 (or any other) = a real scan error (e.g. an LLM misconfig that
        # aborts the graph), surfaced as ScanError so the caller can degrade.
        if not report_path.exists():
            detail = (stderr or stdout or "").strip()[:2000]
            raise ScanError(detail or f"skillspector exited {proc.returncode} with no report")

        try:
            return json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ScanError(f"could not parse skillspector report: {exc}") from exc


def _llm_outcome(data: dict[str, Any], *, completions: int) -> tuple[str, bool]:
    """Derive ``(mode, degraded)`` from the report AND the completions observed.

    Two independent sources, and either one alone can degrade the verdict:

      - the report's ``metadata`` — ``llm_requested`` (the stage was asked for,
        i.e. not --no-llm) and ``meta_analysis_applied`` (skillspector's own
        account of whether it ran);
      - *completions*, how many model responses carried output back through the
        scan's :class:`_CompletionProxy`.

    The second exists because the first can claim a pass that never happened:
    skillspector's LLM nodes drop a failed batch and still record a successful
    call, so a scan whose every request was rejected reports
    ``meta_analysis_applied: true``. A stage that was requested and produced no
    completion is therefore ``static`` + ``degraded``, on the same footing as
    one killed by a timeout — the count decides, not the reason it is zero.

    *completions* is required rather than defaulted so no caller can fall back
    to trusting the metadata by omission.
    """
    meta = data.get("metadata") or {}
    requested = bool(meta.get("llm_requested"))
    applied = bool(meta.get("meta_analysis_applied"))
    if not requested:
        return MODE_STATIC, False
    if applied and completions > 0:
        return MODE_LLM, False
    return MODE_STATIC, True


def _to_verdict(data: dict[str, Any], *, partial: bool, mode: str, degraded: bool) -> Verdict:
    """Map a skillspector JSON report into our advisory Verdict.

    Defensive: clamps/normalises every field so a schema drift in the scanner
    degrades to a well-formed verdict rather than a 500.
    """
    risk = data.get("risk_assessment") or {}
    meta = data.get("metadata") or {}
    skill = data.get("skill") or {}

    try:
        score = int(risk.get("score", 0))
    except (TypeError, ValueError):
        score = 0
    score = max(0, min(100, score))

    severity = str(risk.get("severity", "LOW")).upper()
    if severity not in _VALID_SEVERITIES:
        severity = "LOW"

    recommendation = str(risk.get("recommendation", "CAUTION")).upper()
    if recommendation not in _VALID_RECOMMENDATIONS:
        recommendation = "CAUTION"

    findings = data.get("issues")
    if not isinstance(findings, list):
        findings = []

    components = data.get("components")
    components_scanned = len(components) if isinstance(components, list) else 0

    return Verdict(
        score=score,
        severity=severity,
        recommendation=recommendation,
        findings=findings,
        scanner_version=str(meta.get("skillspector_version") or _scanner_version()),
        mode=mode,
        degraded=degraded,
        partial=partial,
        skill_name=skill.get("name"),
        components_scanned=components_scanned,
    )


def _scan_target(target: Path, *, partial: bool) -> Verdict:
    """Scan *target*, running LLM-assisted analysis when configured.

    Order of preference, always producing a verdict (never an error) when
    skillspector can run at all:
      1. LLM not configured        → static scan, mode=static.
      2. LLM configured, LiteLLM
         unreachable               → static scan, mode=static, degraded=true.
      3. LLM configured + reachable → LLM scan through the completion proxy;
         mode/degraded come from the report metadata AND the number of
         completions the proxy saw, so a stage that answered nothing is a
         static verdict flagged degraded.
      4. LLM scan raises (exit 2 /
         timeout / no report), or
         the proxy cannot bind      → static fallback, mode=static,
                                      degraded=true.

    The whole sequence runs inside ONE budget and holds ONE scan slot, so a
    request cannot outlive ``SKILLCHECK_SCAN_DEADLINE`` however many steps it
    takes. Blocking throughout — callers must reach it off the event loop.
    """
    budget = Budget(_SCAN_DEADLINE)
    with _scan_slot(budget):
        if not _llm_configured():
            data = _run_skillspector(target, use_llm=False, budget=budget)
            return _to_verdict(data, partial=partial, mode=MODE_STATIC, degraded=False)

        if not _litellm_reachable():
            data = _run_skillspector(target, use_llm=False, budget=budget)
            return _to_verdict(data, partial=partial, mode=MODE_STATIC, degraded=True)

        proxy = _CompletionProxy(_litellm_root(), budget)
        try:
            proxy.start()
        except OSError as exc:
            # Nothing would be watching the LLM traffic, and an unwatched LLM
            # scan cannot be told apart from one that answered nothing.
            logger.warning("completion proxy did not start (%s) — scanning static", exc)
            data = _run_skillspector(target, use_llm=False, budget=budget)
            return _to_verdict(data, partial=partial, mode=MODE_STATIC, degraded=True)

        try:
            try:
                data = _run_skillspector(
                    target, use_llm=True, budget=budget, llm_base_url=proxy.base_url
                )
            finally:
                proxy.stop()
        except ScanError as exc:
            # LLM run aborted (e.g. graph-level misconfig) — never block the
            # scan; fall back to a static run on whatever budget is left and
            # flag the degradation.
            logger.warning("LLM scan failed (%s) — falling back to static", exc)
            data = _run_skillspector(target, use_llm=False, budget=budget)
            return _to_verdict(data, partial=partial, mode=MODE_STATIC, degraded=True)

        completions = proxy.usable_completions
        if completions == 0:
            logger.warning(
                "LLM stage produced no usable completion in %d call(s) — verdict is "
                "static and degraded",
                proxy.attempted_completions,
            )
        mode, degraded = _llm_outcome(data, completions=completions)
        return _to_verdict(data, partial=partial, mode=mode, degraded=degraded)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    """Liveness probe + scanner identity + LLM configuration + current load.

    ``async`` and free of I/O on purpose: it is answered directly on the event
    loop, so it stays available no matter how many worker threads are inside a
    scan. A probe that queues behind the work reports a busy service as a dead
    one, which is exactly what it used to do.

    ``scans_in_flight`` / ``busy`` let a caller distinguish the two states this
    endpoint used to collapse into silence.
    """
    version = _scanner_version()
    llm_on = _llm_configured()
    in_flight, oldest_age = _scans_in_flight()
    return {
        "status": "ok",
        "service": "cerase-skillcheck",
        "scanner": "skillspector",
        "scanner_version": version,
        "scanner_available": version != "unknown",
        "llm_configured": llm_on,
        "llm_model": _llm_model() if llm_on else None,
        "mode": MODE_LLM if llm_on else MODE_STATIC,
        "scans_in_flight": in_flight,
        "busy": in_flight > 0,
        "oldest_scan_seconds": round(oldest_age, 1),
        "max_concurrent_scans": _MAX_CONCURRENT_SCANS,
        "scan_deadline_seconds": _SCAN_DEADLINE,
    }


@app.post("/scan", response_model=Verdict)
def scan(req: ScanRequest) -> Verdict:
    """Scan a mounted path or raw SKILL.md content.

    A directory is a full scan; a lone `.md` file or `skill_md` content is a
    SKILL.md-only (partial) scan whose weaker coverage is flagged in `partial`.
    LLM-assisted analysis runs when configured, else static-only; either way a
    verdict is returned (a model outage degrades to static, never a 5xx).
    """
    if req.path:
        target = Path(req.path)
        if not target.exists():
            raise HTTPException(status_code=404, detail=f"path not found: {req.path}")
        partial = target.is_file() and target.suffix.lower() == ".md"
        try:
            return _scan_target(target, partial=partial)
        except ScanError as exc:
            raise HTTPException(status_code=422, detail=f"scan failed: {exc}") from exc

    # skill_md — write to a temp SKILL.md and scan (always partial coverage).
    with tempfile.TemporaryDirectory(prefix="skillcheck-md-") as tmp:
        md_path = Path(tmp) / "SKILL.md"
        md_path.write_text(req.skill_md or "", encoding="utf-8")
        try:
            return _scan_target(md_path, partial=True)
        except ScanError as exc:
            raise HTTPException(status_code=422, detail=f"scan failed: {exc}") from exc


@app.post("/scan/bundle", response_model=Verdict)
async def scan_bundle(file: UploadFile) -> Verdict:
    """Scan an uploaded **.zip** skill bundle (full directory scan).

    Only the upload is awaited here. Extraction and the scan are blocking and go
    to the threadpool, because this handler runs on the event loop and calling
    them directly stopped the whole service — health probe included — for the
    length of the scan.
    """
    name = (file.filename or "").lower()
    if not name.endswith(".zip"):
        raise HTTPException(status_code=415, detail="only .zip bundles are supported")

    payload = await file.read()
    if len(payload) > _MAX_UPLOAD:
        raise HTTPException(
            status_code=413, detail=f"bundle exceeds {_MAX_UPLOAD} bytes"
        )

    return await run_in_threadpool(_scan_bundle_payload, payload)


def _scan_bundle_payload(payload: bytes) -> Verdict:
    """Extract an uploaded bundle and scan it. Blocking — threadpool only."""
    tmp = tempfile.mkdtemp(prefix="skillcheck-bundle-")
    try:
        extract_dir = Path(tmp) / "skill"
        extract_dir.mkdir()
        try:
            with zipfile.ZipFile(_bytes_io(payload)) as zf:
                _safe_extract_zip(zf, extract_dir)
        except zipfile.BadZipFile as exc:
            raise HTTPException(status_code=400, detail="invalid .zip bundle") from exc

        root = _skill_root(extract_dir)
        try:
            return _scan_target(root, partial=False)
        except ScanError as exc:
            raise HTTPException(status_code=422, detail=f"scan failed: {exc}") from exc
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _bytes_io(payload: bytes):
    import io

    return io.BytesIO(payload)


def _safe_extract_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    """Extract a zip, refusing path traversal (zip-slip) entries."""
    dest = dest.resolve()
    for member in zf.namelist():
        target = (dest / member).resolve()
        if not str(target).startswith(str(dest)):
            raise HTTPException(status_code=400, detail="unsafe path in bundle")
    zf.extractall(dest)


def _skill_root(extracted: Path) -> Path:
    """Find the directory that holds SKILL.md (bundles often nest one level)."""
    if (extracted / "SKILL.md").exists():
        return extracted
    for child in sorted(extracted.iterdir()):
        if child.is_dir() and (child / "SKILL.md").exists():
            return child
    return extracted
