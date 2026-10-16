"""A model call may take far longer than skillspector's 120 s client cut.

Measured on 16 October 2026: three skills of 4,500, 2,306 and 1,158 bytes each
spent 163-811 s inside a single model call, almost all of it reasoning tokens.
skillspector cuts every OpenAI client call at 120 s (two literals in the pinned
commit: ``llm_utils.get_chat_model`` and the OpenAI provider's default) and
retries twice, so each call was cut before the model answered, the LLM step was
stopped at the engine's old 300 s, and the scan returned a static verdict the
control-plane discarded. With the client timeout raised to 600 s the same model
returned full verdicts: a credential-exfiltrating skill scored CRITICAL /
DO_NOT_INSTALL with four findings and ``mode=llm``.

The timeout is not a setting skillspector reads, so the image build rewrites the
two literals to read ``SKILLCHECK_LLM_CALL_TIMEOUT`` (default 900). The patch
fails the build if either line is gone, so a skillspector bump cannot silently
restore the cut. Both halves are tested here: the engine's default and ordering,
the value it hands the scanner subprocess, and the build patch itself.

Run from the package root::

    python -m pytest tests/test_llm_call_timeout.py -v
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server  # noqa: E402

DOCKERFILE = Path(__file__).resolve().parent.parent / "Dockerfile"


# ---------------------------------------------------------------------------
# Defaults and ordering: call < model step < overall deadline
# ---------------------------------------------------------------------------


def test_the_call_timeout_defaults_to_900(monkeypatch):
    monkeypatch.delenv("SKILLCHECK_LLM_CALL_TIMEOUT", raising=False)
    assert server._llm_call_timeout() == 900


def test_the_call_timeout_is_configurable(monkeypatch):
    monkeypatch.setenv("SKILLCHECK_LLM_CALL_TIMEOUT", "1234")
    assert server._llm_call_timeout() == 1234


def test_the_engine_defaults_are_raised_to_fit(monkeypatch):
    monkeypatch.delenv("SKILLCHECK_LLM_CALL_TIMEOUT", raising=False)
    assert server._LLM_SCAN_TIMEOUT == 1800, "the model step must outlast a 900 s call"
    assert server._SCAN_DEADLINE == 2100, "the request deadline must outlast the model step"


def test_the_timeouts_are_ordered_call_below_step_below_deadline(monkeypatch):
    """A call ceiling below the model step, which is below the request deadline.

    Anything else re-creates the defect at the next layer up: a call cut by the
    step, or a step cut by the deadline before the model can answer.
    """
    monkeypatch.delenv("SKILLCHECK_LLM_CALL_TIMEOUT", raising=False)
    assert server._llm_call_timeout() < server._LLM_SCAN_TIMEOUT
    assert server._LLM_SCAN_TIMEOUT < server._SCAN_DEADLINE


def test_the_proxy_upstream_timeout_is_at_least_a_model_call(monkeypatch):
    """The forwarder must not be the next thing that cuts a long call."""
    monkeypatch.setenv("SKILLCHECK_LLM_CALL_TIMEOUT", "900")
    proxy = server._CompletionProxy("http://litellm.invalid", server.Budget(server._SCAN_DEADLINE))
    assert proxy._timeout() >= server._llm_call_timeout()


# ---------------------------------------------------------------------------
# The value the scanner subprocess actually receives
# ---------------------------------------------------------------------------

FAKE_SCANNER = '''#!/usr/bin/env python3
"""A stand-in skillspector: records the call-timeout env it was handed."""
import json
import os
import sys

argv = sys.argv[1:]
out = argv[argv.index("--output") + 1]
with open(out, "w", encoding="utf-8") as fh:
    json.dump({"call_timeout": os.environ.get("SKILLCHECK_LLM_CALL_TIMEOUT")}, fh)
sys.exit(0)
'''


@pytest.fixture
def fake_scanner(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    script = bindir / "skillspector"
    script.write_text(FAKE_SCANNER, encoding="utf-8")
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    return script


def _subprocess_call_timeout(fake_scanner, tmp_path) -> str | None:
    """Run the stand-in scanner through the engine and read back its env."""
    target = tmp_path / "SKILL.md"
    target.write_text("---\nname: probe\ndescription: fixture.\n---\n", encoding="utf-8")
    data = server._run_skillspector(
        target,
        use_llm=True,
        budget=server.Budget(server._SCAN_DEADLINE),
        llm_base_url="http://127.0.0.1:1/v1",
    )
    return data["call_timeout"]


@pytest.fixture
def llm_configured(monkeypatch):
    monkeypatch.setenv("LITELLM_BASE_URL", "http://cerase-litellm.invalid")
    monkeypatch.setenv("SKILLCHECK_LLM_API_KEY", "sk-cerase-svc-skillcheck")


def test_the_scanner_subprocess_gets_the_engine_default_call_timeout(
    fake_scanner, llm_configured, monkeypatch, tmp_path
):
    """With nothing set, the subprocess still gets the engine's 900, not 120.

    The service must state the value itself rather than inherit whatever the
    container happens to carry, so the timeout cannot silently differ between
    the proxy, the scanner and the engine.
    """
    monkeypatch.delenv("SKILLCHECK_LLM_CALL_TIMEOUT", raising=False)
    assert _subprocess_call_timeout(fake_scanner, tmp_path) == "900"


def test_the_scanner_subprocess_gets_the_configured_call_timeout(
    fake_scanner, llm_configured, monkeypatch, tmp_path
):
    monkeypatch.setenv("SKILLCHECK_LLM_CALL_TIMEOUT", "1234")
    assert _subprocess_call_timeout(fake_scanner, tmp_path) == "1234"


# ---------------------------------------------------------------------------
# The build patch: skillspector's literals now read our setting
# ---------------------------------------------------------------------------

PATCHABLE_SOURCE = """\
from __future__ import annotations

import json


def build():
    return make(
        timeout=120,
    )
"""


def test_the_patch_list_names_the_two_pinned_literals():
    """The exact lines the pinned commit ships, so a bump that moves one fails."""
    assert server._SKILLSPECTOR_TIMEOUT_PATCHES == (
        ("llm_utils.py", "        timeout=120,"),
        ("providers/openai/provider.py", "        timeout: float | None = 120,"),
    )


def test_the_patch_replaces_the_hardcoded_timeout(monkeypatch):
    patched = server._patch_skillspector_llm_call_timeout(
        PATCHABLE_SOURCE, "        timeout=120,"
    )
    assert "120" not in patched, "a hardcoded cut survived the patch"
    assert "_cerase_llm_call_timeout()" in patched

    monkeypatch.setenv("SKILLCHECK_LLM_CALL_TIMEOUT", "777")
    namespace: dict = {}
    exec(compile(patched, "<patched>", "exec"), namespace)
    assert namespace["_cerase_llm_call_timeout"]() == 777.0


def test_the_patch_helper_defaults_to_900(monkeypatch):
    patched = server._patch_skillspector_llm_call_timeout(
        PATCHABLE_SOURCE, "        timeout=120,"
    )
    monkeypatch.delenv("SKILLCHECK_LLM_CALL_TIMEOUT", raising=False)
    namespace: dict = {}
    exec(compile(patched, "<patched>", "exec"), namespace)
    assert namespace["_cerase_llm_call_timeout"]() == 900.0


def test_the_patch_fails_when_the_line_is_not_found():
    """A skillspector bump that moves the literal must fail the build."""
    with pytest.raises(server.SkillspectorPatchError):
        server._patch_skillspector_llm_call_timeout(
            "from __future__ import annotations\n", "        timeout=120,"
        )


def test_the_image_build_applies_the_patch():
    """The Dockerfile must run the patcher against the installed package."""
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "_patch_skillspector_llm_call_timeout" in text
    assert "server.py" in text
