"""A scan is degraded when any semantic analyser got no usable answer.

skillspector's three semantic analysers run on every LLM scan, so an answer
from the meta analyser alone is not an LLM pass. The verdict is ``mode="static"``
and ``degraded=True`` whenever one of them produced no usable completion, even
if the other analysers and the meta analyser answered.

Run from the package root::

    python -m pytest tests/test_a_silent_analyser_degrades.py -v
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
sys.path.insert(0, str(Path(__file__).resolve().parent))
import server  # noqa: E402
from test_llm_degrade import (  # noqa: E402
    DISHONEST_REPORT,
    EMPTY_COMPLETION,
    GOOD_COMPLETION,
)

# The exact text each analyser's prompt starts with, in the pinned skillspector.
ANALYSER_OPENINGS = {
    "semantic_developer_intent": "You are a developer-intent auditor for AI agent skills.",
    "semantic_quality_policy": "You are a quality and safety auditor for AI agent skills.",
    "semantic_security_discovery": "You are a security analyzer for AI agent skill files.",
    "meta_analyzer": "You are a security analyst evaluating an agent skill for vulnerabilities.",
}
ALL_ANALYSERS = tuple(ANALYSER_OPENINGS)
SEMANTIC_ANALYSERS = (
    "semantic_developer_intent",
    "semantic_quality_policy",
    "semantic_security_discovery",
)

DOCKERFILE = Path(__file__).resolve().parent.parent / "Dockerfile"

EXPECTED_PROMPTS = (
    (
        "semantic_developer_intent",
        "nodes/analyzers/semantic_developer_intent.py",
        "ANALYZER_PROMPT",
        "You are a developer-intent auditor for AI agent skills.",
    ),
    (
        "semantic_quality_policy",
        "nodes/analyzers/semantic_quality_policy.py",
        "ANALYZER_PROMPT",
        "You are a quality and safety auditor for AI agent skills.",
    ),
    (
        "semantic_security_discovery",
        "nodes/analyzers/semantic_security_discovery.py",
        "ANALYZER_PROMPT",
        "You are a security analyzer for AI agent skill files.",
    ),
    (
        "meta_analyzer",
        "nodes/meta_analyzer.py",
        "PER_FILE_ANALYSIS_PROMPT",
        "You are a security analyst evaluating an agent skill for vulnerabilities.",
    ),
)

PINNED_SOURCES = {
    "semantic_developer_intent": (
        'ANALYZER_PROMPT = """\\\n'
        "You are a developer-intent auditor for AI agent skills.  Your job is to\n"
        "read the skill and return findings.\n"
        '"""\n'
    ),
    "semantic_quality_policy": (
        'ANALYZER_PROMPT = """\\\n'
        "You are a quality and safety auditor for AI agent skills.  Review the\n"
        "skill against the policy.\n"
        '"""\n'
    ),
    "semantic_security_discovery": (
        'ANALYZER_PROMPT = """\\\n'
        "You are a security analyzer for AI agent skill files.  Read every file.\n"
        '"""\n'
    ),
    "meta_analyzer": (
        'PER_FILE_ANALYSIS_PROMPT = """\\\n'
        "You are a security analyst evaluating an agent skill for vulnerabilities.\n"
        "Return a JSON object.\n"
        '"""\n'
    ),
}


def _first_user_text(body: bytes) -> str | None:
    """The first user message's text in *body*, or ``None`` when there is none."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    messages = data.get("messages")
    if not isinstance(messages, list):
        return None
    for message in messages:
        if not isinstance(message, dict) or message.get("role") != "user":
            continue
        content = message.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            for part in content:
                if (
                    isinstance(part, dict)
                    and part.get("type") == "text"
                    and isinstance(part.get("text"), str)
                ):
                    return part["text"]
        return None
    return None


def _classify(body: bytes) -> str | None:
    """The analyser whose opening the first user message starts with."""
    text = _first_user_text(body)
    if text is None:
        return None
    text = text.lstrip()
    for analyser, opening in ANALYSER_OPENINGS.items():
        if text.startswith(opening):
            return analyser
    return None


class _AnalyserRouter:
    """A stand-in router that answers according to the analyser that asked."""

    def __init__(self, overrides: dict[str, tuple[int, dict]] | None = None) -> None:
        self.overrides = dict(overrides or {})
        self.requests_by_analyser: dict[str, int] = {}
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
                body = self.rfile.read(length)
                analyser = _classify(body)
                with outer._lock:
                    if analyser is not None:
                        outer.requests_by_analyser[analyser] = (
                            outer.requests_by_analyser.get(analyser, 0) + 1
                        )
                status, payload = outer.overrides.get(analyser, (200, GOOD_COMPLETION))
                self._reply(status, payload)

            def _reply(self, status: int, payload: dict) -> None:
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    def __enter__(self) -> _AnalyserRouter:
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
"""A stand-in skillspector: one completion per analyser, then a clean report.

It sends every analyser's prompt as one user message, swallows the outcome, and
writes a report that claims an applied LLM pass whatever the router answered.
"""
import json
import os
import sys
import urllib.request

ANALYSERS = {
    "semantic_developer_intent": "You are a developer-intent auditor for AI agent skills.",
    "semantic_quality_policy": "You are a quality and safety auditor for AI agent skills.",
    "semantic_security_discovery": "You are a security analyzer for AI agent skill files.",
    "meta_analyzer": "You are a security analyst evaluating an agent skill for vulnerabilities.",
}

argv = sys.argv[1:]
out = argv[argv.index("--output") + 1]

base = os.environ.get("OPENAI_BASE_URL", "").rstrip("/")
key = os.environ.get("OPENAI_API_KEY", "")
selected = [
    name
    for name in os.environ.get(
        "FAKE_SCANNER_ANALYSERS", ",".join(ANALYSERS)
    ).split(",")
    if name
]
skill_text = (
    "A skill that reviews a spreadsheet.\\n"
    + os.environ.get("FAKE_SCANNER_EXTRA_TEXT", "")
)
if base:
    for name in selected:
        payload = json.dumps(
            {
                "model": os.environ.get("SKILLSPECTOR_MODEL", "core"),
                "messages": [
                    {"role": "user", "content": ANALYSERS[name] + "\\n\\n" + skill_text}
                ],
            }
        ).encode()
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
    json.dump(json.loads(__REPORT__), fh)
sys.exit(0)
'''.replace("__REPORT__", repr(json.dumps(DISHONEST_REPORT)))


@pytest.fixture
def fake_scanner(tmp_path, monkeypatch):
    """Put a stand-in ``skillspector`` first on PATH."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "skillspector"
    script.write_text(FAKE_SCANNER, encoding="utf-8")
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    return script


def _scan_against(router: _AnalyserRouter, monkeypatch, tmp_path) -> server.Verdict:
    monkeypatch.setenv("LITELLM_BASE_URL", router.base_url)
    monkeypatch.setenv("SKILLCHECK_LLM_API_KEY", "sk-cerase-svc-skillcheck")
    target = tmp_path / "SKILL.md"
    target.write_text("---\nname: probe-skill\ndescription: fixture.\n---\n", encoding="utf-8")
    return server._scan_target(target, partial=True)


# ---------------------------------------------------------------------------
# End to end: every semantic analyser must answer for an LLM pass
# ---------------------------------------------------------------------------

FAILURE_SHAPES = (
    (401, {"error": {"message": "Invalid proxy server token passed"}}),
    (200, EMPTY_COMPLETION),
)


@pytest.mark.parametrize("analyser", SEMANTIC_ANALYSERS)
@pytest.mark.parametrize(("status", "body"), FAILURE_SHAPES, ids=["rejected", "empty"])
def test_one_silent_semantic_analyser_degrades_the_scan(
    analyser, status, body, fake_scanner, monkeypatch, tmp_path
):
    """One semantic analyser with no usable answer is enough to degrade."""
    with _AnalyserRouter({analyser: (status, body)}) as router:
        verdict = _scan_against(router, monkeypatch, tmp_path)

    assert set(router.requests_by_analyser) == set(ALL_ANALYSERS), (
        "the scan did not ask every analyser"
    )
    assert verdict.degraded is True
    assert verdict.mode == server.MODE_STATIC


def test_all_four_analysers_answering_keeps_the_llm_verdict(
    fake_scanner, monkeypatch, tmp_path
):
    with _AnalyserRouter() as router:
        verdict = _scan_against(router, monkeypatch, tmp_path)

    assert set(router.requests_by_analyser) == set(ALL_ANALYSERS)
    assert verdict.mode == server.MODE_LLM
    assert verdict.degraded is False


def test_a_failed_meta_analyser_alone_does_not_degrade(
    fake_scanner, monkeypatch, tmp_path
):
    """A failed meta call leaves the static findings in place; it is not a degrade."""
    with _AnalyserRouter(
        {"meta_analyzer": (401, {"error": {"message": "Invalid proxy server token passed"}})}
    ) as router:
        verdict = _scan_against(router, monkeypatch, tmp_path)

    assert set(router.requests_by_analyser) == set(ALL_ANALYSERS)
    assert verdict.mode == server.MODE_LLM
    assert verdict.degraded is False


@pytest.mark.parametrize("analyser", SEMANTIC_ANALYSERS)
def test_a_semantic_analyser_that_was_never_called_degrades(
    analyser, fake_scanner, monkeypatch, tmp_path
):
    """A call that was never made is a semantic analyser with no usable answer."""
    called = [name for name in ALL_ANALYSERS if name != analyser]
    monkeypatch.setenv("FAKE_SCANNER_ANALYSERS", ",".join(called))

    with _AnalyserRouter() as router:
        verdict = _scan_against(router, monkeypatch, tmp_path)

    assert analyser not in router.requests_by_analyser
    assert verdict.degraded is True
    assert verdict.mode == server.MODE_STATIC


def test_a_quoted_opening_does_not_count_as_that_analysers_answer(
    fake_scanner, monkeypatch, tmp_path
):
    """An opening further in the skill text is a quotation, not an answer."""
    quoted = ANALYSER_OPENINGS["semantic_security_discovery"]
    monkeypatch.setenv(
        "FAKE_SCANNER_EXTRA_TEXT", "\n\nAnother skill quotes: " + quoted + "\n"
    )

    with _AnalyserRouter(
        {
            "semantic_security_discovery": (
                401,
                {"error": {"message": "Invalid proxy server token passed"}},
            )
        }
    ) as router:
        verdict = _scan_against(router, monkeypatch, tmp_path)

    assert set(router.requests_by_analyser) == set(ALL_ANALYSERS)
    assert verdict.degraded is True
    assert verdict.mode == server.MODE_STATIC


# ---------------------------------------------------------------------------
# Classifying a request: only the start of the first user message counts
# ---------------------------------------------------------------------------


def _body(*messages: dict) -> bytes:
    return json.dumps({"model": "core", "messages": list(messages)}).encode()


@pytest.mark.parametrize("analyser", ALL_ANALYSERS)
def test_each_opening_classifies(analyser):
    body = _body(
        {"role": "user", "content": ANALYSER_OPENINGS[analyser] + "\n\nsome skill text"}
    )

    assert server._analyser_of(body) == analyser


def test_the_proxy_language_messages_do_not_hide_the_analyser():
    plain = _body(
        {
            "role": "user",
            "content": ANALYSER_OPENINGS["semantic_quality_policy"] + "\n\nsome skill text",
        }
    )

    assert server._analyser_of(server._with_findings_language(plain)) == (
        "semantic_quality_policy"
    )


def test_list_of_parts_content_classifies():
    body = _body(
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": ANALYSER_OPENINGS["semantic_security_discovery"]
                    + "\n\nsome skill text",
                }
            ],
        }
    )

    assert server._analyser_of(body) == "semantic_security_discovery"


def test_a_body_that_is_not_json_is_unclassified():
    assert server._analyser_of(b"not json") is None


def test_a_body_without_a_user_message_is_unclassified():
    body = _body({"role": "system", "content": ANALYSER_OPENINGS["meta_analyzer"]})

    assert server._analyser_of(body) is None


def test_an_opening_after_other_text_is_unclassified():
    body = _body(
        {
            "role": "user",
            "content": "The skill quotes another analyser:\n\n"
            + ANALYSER_OPENINGS["semantic_developer_intent"],
        }
    )

    assert server._analyser_of(body) is None


# ---------------------------------------------------------------------------
# The decision helpers
# ---------------------------------------------------------------------------


def test_unanswered_lists_all_semantic_analysers_when_none_answered():
    assert server._unanswered_analysers({}) == server._SEMANTIC_ANALYSERS


def test_unanswered_lists_only_the_silent_analysers_in_order():
    usable = {
        "semantic_developer_intent": 1,
        "semantic_security_discovery": 2,
        "meta_analyzer": 1,
    }

    assert server._unanswered_analysers(usable) == ("semantic_quality_policy",)


def test_a_zero_count_is_unanswered():
    usable = {
        "semantic_developer_intent": 1,
        "semantic_quality_policy": 0,
        "semantic_security_discovery": 1,
    }

    assert server._unanswered_analysers(usable) == ("semantic_quality_policy",)


def test_unanswered_is_empty_when_every_semantic_analyser_answered():
    usable = {analyser: 1 for analyser in server._SEMANTIC_ANALYSERS}

    assert server._unanswered_analysers(usable) == ()


def test_a_silent_analyser_outranks_answered_completions():
    data = {"metadata": {"llm_requested": True, "meta_analysis_applied": True}}

    assert server._llm_outcome(
        data,
        completions=5,
        unanswered=("semantic_security_discovery",),
    ) == (server.MODE_STATIC, True)


def test_no_silent_analyser_keeps_the_llm_verdict():
    data = {"metadata": {"llm_requested": True, "meta_analysis_applied": True}}

    assert server._llm_outcome(data, completions=5, unanswered=()) == (
        server.MODE_LLM,
        False,
    )


# ---------------------------------------------------------------------------
# Build time: the prompt table and the check that a pinned bump fails loudly
# ---------------------------------------------------------------------------


def test_the_analyser_prompt_table_is_the_pinned_four():
    assert server._ANALYSER_PROMPTS == EXPECTED_PROMPTS


@pytest.mark.parametrize("row", EXPECTED_PROMPTS, ids=[row[0] for row in EXPECTED_PROMPTS])
def test_each_pinned_source_carries_its_opening(row):
    analyser, _relative_path, variable, opening = row

    assert (
        server._check_skillspector_analyser_opening(
            PINNED_SOURCES[analyser], variable, opening
        )
        is None
    )


@pytest.mark.parametrize("row", EXPECTED_PROMPTS, ids=[row[0] for row in EXPECTED_PROMPTS])
def test_an_opening_that_differs_fails(row):
    analyser, _relative_path, variable, opening = row
    source = PINNED_SOURCES[analyser].replace(opening, opening[:-1] + "!", 1)

    with pytest.raises(server.SkillspectorPatchError):
        server._check_skillspector_analyser_opening(source, variable, opening)


@pytest.mark.parametrize("row", EXPECTED_PROMPTS, ids=[row[0] for row in EXPECTED_PROMPTS])
def test_a_source_without_the_opening_fails(row):
    _analyser, _relative_path, variable, opening = row
    source = "ANALYZER_PROMPT = '''no prompt here'''\n"

    with pytest.raises(server.SkillspectorPatchError):
        server._check_skillspector_analyser_opening(source, variable, opening)


@pytest.mark.parametrize("row", EXPECTED_PROMPTS, ids=[row[0] for row in EXPECTED_PROMPTS])
def test_an_opening_that_appears_twice_fails(row):
    analyser, _relative_path, variable, opening = row
    source = PINNED_SOURCES[analyser] + "\n" + PINNED_SOURCES[analyser]

    with pytest.raises(server.SkillspectorPatchError):
        server._check_skillspector_analyser_opening(source, variable, opening)


def test_the_image_build_checks_every_analyser_opening():
    builder = DOCKERFILE.read_text(encoding="utf-8").split("# ---- runtime", 1)[0]

    assert "_ANALYSER_PROMPTS" in builder
    assert "_check_skillspector_analyser_opening" in builder
