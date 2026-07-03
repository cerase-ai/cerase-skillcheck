"""Unit tests for cerase-skillcheck's LLM-routing + degrade helpers.

These import the ``server`` module directly and exercise the pure decision
functions that decide analysis mode, degradation, model knob, and LiteLLM
routing — no running service and no skillspector install required (skillspector
is only ever shelled out). Run from the package root:

    python -m pytest tests/test_helpers.py -v

They cover M-SKILLSCAN-2's contract: mode-flag propagation, the degrade-to-
static path (LLM requested but not effectively applied / LiteLLM unreachable),
and the model-alias knob default.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Import the service module (server.py sits at the package root).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server  # noqa: E402


# ---------------------------------------------------------------------------
# Model-alias knob (default core, switchable to a cheaper alias)
# ---------------------------------------------------------------------------


def test_llm_model_defaults_to_core(monkeypatch):
    monkeypatch.delenv("SKILLCHECK_LLM_MODEL", raising=False)
    assert server._llm_model() == "core"


def test_llm_model_knob_overrides_to_cheaper_alias(monkeypatch):
    monkeypatch.setenv("SKILLCHECK_LLM_MODEL", "spark")
    assert server._llm_model() == "spark"


def test_llm_model_blank_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("SKILLCHECK_LLM_MODEL", "   ")
    assert server._llm_model() == "core"


# ---------------------------------------------------------------------------
# LLM-configured predicate (needs BOTH a base URL and an explicit svc key)
# ---------------------------------------------------------------------------


def test_llm_configured_requires_base_and_key(monkeypatch):
    monkeypatch.setenv("LITELLM_BASE_URL", "http://cerase-litellm:4000")
    monkeypatch.setenv("SKILLCHECK_LLM_API_KEY", "sk-cerase-svc-skillcheck")
    assert server._llm_configured() is True


def test_llm_not_configured_without_key(monkeypatch):
    monkeypatch.setenv("LITELLM_BASE_URL", "http://cerase-litellm:4000")
    monkeypatch.delenv("SKILLCHECK_LLM_API_KEY", raising=False)
    assert server._llm_configured() is False


def test_llm_not_configured_without_base(monkeypatch):
    monkeypatch.delenv("LITELLM_BASE_URL", raising=False)
    monkeypatch.setenv("SKILLCHECK_LLM_API_KEY", "sk-cerase-svc-skillcheck")
    assert server._llm_configured() is False


# ---------------------------------------------------------------------------
# OpenAI-compatible base URL normalisation (skillspector expects a /v1 suffix)
# ---------------------------------------------------------------------------


def test_openai_base_url_appends_v1(monkeypatch):
    monkeypatch.setenv("LITELLM_BASE_URL", "http://cerase-litellm:4000")
    assert server._openai_base_url() == "http://cerase-litellm:4000/v1"


def test_openai_base_url_keeps_existing_v1(monkeypatch):
    monkeypatch.setenv("LITELLM_BASE_URL", "http://cerase-litellm:4000/v1")
    assert server._openai_base_url() == "http://cerase-litellm:4000/v1"


def test_openai_base_url_strips_trailing_slash(monkeypatch):
    monkeypatch.setenv("LITELLM_BASE_URL", "http://cerase-litellm:4000/")
    assert server._openai_base_url() == "http://cerase-litellm:4000/v1"


def test_litellm_health_url_is_liveliness_not_under_v1(monkeypatch):
    monkeypatch.setenv("LITELLM_BASE_URL", "http://cerase-litellm:4000/v1")
    assert server._litellm_health_url() == "http://cerase-litellm:4000/health/liveliness"


# ---------------------------------------------------------------------------
# LLM scan environment (routes skillspector's OpenAI provider at our LiteLLM,
# NOT the master key, NOT CERASE_LLM_API_BASE)
# ---------------------------------------------------------------------------


def test_llm_scan_env_points_openai_provider_at_litellm(monkeypatch):
    monkeypatch.setenv("LITELLM_BASE_URL", "http://cerase-litellm:4000")
    monkeypatch.setenv("SKILLCHECK_LLM_API_KEY", "sk-cerase-svc-skillcheck")
    monkeypatch.setenv("SKILLCHECK_LLM_MODEL", "core")
    env = server._llm_scan_env()
    assert env["SKILLSPECTOR_PROVIDER"] == "openai"
    assert env["OPENAI_API_KEY"] == "sk-cerase-svc-skillcheck"
    assert env["OPENAI_BASE_URL"] == "http://cerase-litellm:4000/v1"
    assert env["SKILLSPECTOR_MODEL"] == "core"
    # Tracing must stay off so a scan never phones home.
    assert env["LANGCHAIN_TRACING_V2"] == "false"


def test_base_scan_env_strips_ambient_openai_creds(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "leaked")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://evil.example/v1")
    monkeypatch.setenv("SKILLSPECTOR_MODEL", "gpt-x")
    env = server._base_scan_env()
    assert "OPENAI_API_KEY" not in env
    assert "OPENAI_BASE_URL" not in env
    assert "SKILLSPECTOR_MODEL" not in env
    assert env["LANGCHAIN_TRACING_V2"] == "false"


# ---------------------------------------------------------------------------
# Mode / degraded mapping from a skillspector report's metadata
# (the crux of M-SKILLSCAN-2: mode flag + degrade)
# ---------------------------------------------------------------------------


def test_llm_outcome_applied_is_llm_not_degraded():
    data = {"metadata": {"llm_requested": True, "meta_analysis_applied": True}}
    assert server._llm_outcome(data) == (server.MODE_LLM, False)


def test_llm_outcome_requested_but_not_applied_is_static_degraded():
    # LLM was asked for but did not effectively run (unreachable / bad key /
    # every call failed) — the report reflects static analysis only.
    data = {"metadata": {"llm_requested": True, "meta_analysis_applied": False, "llm_degraded": True}}
    assert server._llm_outcome(data) == (server.MODE_STATIC, True)


def test_llm_outcome_not_requested_is_static_not_degraded():
    data = {"metadata": {"llm_requested": False, "meta_analysis_applied": False}}
    assert server._llm_outcome(data) == (server.MODE_STATIC, False)


def test_llm_outcome_missing_metadata_defaults_to_static():
    assert server._llm_outcome({}) == (server.MODE_STATIC, False)


# ---------------------------------------------------------------------------
# Reachability probe — a transport failure degrades (never hangs the scan)
# ---------------------------------------------------------------------------


def test_litellm_unreachable_host_returns_false(monkeypatch):
    # RFC 2606 .invalid TLD never resolves — a deterministic offline check.
    monkeypatch.setenv("LITELLM_BASE_URL", "http://cerase-litellm.invalid:4000")
    monkeypatch.setenv("SKILLCHECK_LLM_PROBE_TIMEOUT", "2")
    monkeypatch.setattr(server, "_PROBE_TIMEOUT", 2.0)
    assert server._litellm_reachable() is False


# ---------------------------------------------------------------------------
# Verdict mapping is defensive (schema drift → well-formed verdict, not a 500)
# ---------------------------------------------------------------------------


def test_to_verdict_clamps_and_normalises():
    data = {
        "risk_assessment": {"score": 250, "severity": "bogus", "recommendation": "weird"},
        "issues": "not-a-list",
        "metadata": {"skillspector_version": "9.9.9"},
        "skill": {"name": "x"},
        "components": [1, 2, 3],
    }
    v = server._to_verdict(data, partial=True, mode=server.MODE_LLM, degraded=False)
    assert v.score == 100  # clamped
    assert v.severity == "LOW"  # invalid → LOW
    assert v.recommendation == "CAUTION"  # invalid → CAUTION
    assert v.findings == []  # non-list → []
    assert v.mode == server.MODE_LLM
    assert v.degraded is False
    assert v.partial is True
    assert v.components_scanned == 3
    assert v.scanner_version == "9.9.9"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
