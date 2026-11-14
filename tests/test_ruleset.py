"""The service must report a fingerprint of the rules it is actually running.

skillspector's version string does not change when the image build patches its
rule text, and it need not change when ``requirements.txt`` moves its pinned
commit. Two scanners that run different rules can therefore report the same
version, and the control-plane cannot tell a verdict given under the old rules
from one given under the new ones.

The service reports a fingerprint of the installed rule text instead. It is
derived from the package tree, not from the version string, and it is resolved
once and then held in memory so ``/healthz`` never touches the disk. The
control-plane stores it with each verdict and scans a held skill again when the
fingerprint changes.

Run from the package root::

    python -m pytest tests/test_ruleset.py -v
"""
from __future__ import annotations

import asyncio
import re
import shutil
import sys
import types
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server  # noqa: E402

HEX16 = re.compile(r"[0-9a-f]{16}\Z")


def _write_tree(root: Path) -> None:
    """A small stand-in for an installed skillspector package tree."""
    (root / "rules").mkdir(parents=True, exist_ok=True)
    (root / "rules" / "sqp.py").write_text("RULE = 'SQP-2'\n", encoding="utf-8")
    (root / "rules" / "sdi.py").write_text("RULE = 'SDI-2'\n", encoding="utf-8")
    (root / "nested" / "deeper").mkdir(parents=True, exist_ok=True)
    (root / "nested" / "deeper" / "text.txt").write_text("pinned rule text\n", encoding="utf-8")
    (root / "manifest.txt").write_text("ruleset fixture\n", encoding="utf-8")


def test_the_fingerprint_is_stable_and_path_independent(tmp_path):
    root = tmp_path / "installed"
    _write_tree(root)

    first = server._ruleset_fingerprint(root)
    assert isinstance(first, str)
    assert HEX16.fullmatch(first), f"not 16 lowercase hex characters: {first!r}"

    assert server._ruleset_fingerprint(root) == first

    copy = tmp_path / "elsewhere" / "copy"
    shutil.copytree(root, copy)
    assert server._ruleset_fingerprint(copy) == first


def test_the_fingerprint_tracks_content_names_and_membership(tmp_path):
    root = tmp_path / "tree"
    _write_tree(root)
    baseline = server._ruleset_fingerprint(root)

    changed = tmp_path / "changed"
    shutil.copytree(root, changed)
    target = changed / "rules" / "sqp.py"
    data = target.read_bytes()
    assert b"2" in data
    target.write_bytes(data.replace(b"2", b"3", 1))
    assert server._ruleset_fingerprint(changed) != baseline

    added = tmp_path / "added"
    shutil.copytree(root, added)
    (added / "rules" / "extra.py").write_text("RULE = 'NEW'\n", encoding="utf-8")
    assert server._ruleset_fingerprint(added) != baseline

    renamed = tmp_path / "renamed"
    shutil.copytree(root, renamed)
    (renamed / "rules" / "sqp.py").rename(renamed / "rules" / "sqp_renamed.py")
    assert server._ruleset_fingerprint(renamed) != baseline


def test_caches_and_bytecode_are_ignored(tmp_path):
    root = tmp_path / "tree"
    _write_tree(root)
    baseline = server._ruleset_fingerprint(root)

    (root / "__pycache__").mkdir()
    (root / "__pycache__" / "sqp.cpython-313.pyc").write_bytes(b"\x00compiled")
    nested = root / "nested" / "__pycache__"
    nested.mkdir()
    (nested / "deeper.cpython-313.pyc").write_bytes(b"\x00more")
    (root / "loose.pyc").write_bytes(b"\x00loose")
    (root / "nested" / "deeper" / "another.pyc").write_bytes(b"\x00deep")

    assert server._ruleset_fingerprint(root) == baseline


def test_ruleset_is_unknown_without_skillspector(monkeypatch):
    monkeypatch.setattr(server.importlib.util, "find_spec", lambda name: None)
    monkeypatch.setattr(server, "_RULESET", None)

    assert server._ruleset() == "unknown"


def test_ruleset_uses_the_installed_package_tree_once(tmp_path, monkeypatch):
    root = tmp_path / "skillspector"
    _write_tree(root)

    real_fingerprint = server._ruleset_fingerprint
    expected = server._combine_ruleset(real_fingerprint(root), server._cerase_rules_fingerprint())
    calls = []

    def counting_fingerprint(path):  # noqa: ANN001
        calls.append(Path(path))
        return real_fingerprint(path)

    monkeypatch.setattr(
        server.importlib.util,
        "find_spec",
        lambda name: types.SimpleNamespace(submodule_search_locations=[str(root)]),
    )
    monkeypatch.setattr(server, "_ruleset_fingerprint", counting_fingerprint)
    monkeypatch.setattr(server, "_RULESET", None)

    assert server._ruleset() == expected
    assert server._ruleset() == expected
    assert len(calls) == 1, "the tree must be read once and then held in memory"


def test_healthz_reports_the_ruleset():
    expected = server._ruleset()

    async def scenario() -> dict:
        transport = httpx.ASGITransport(app=server.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            response = await client.get("/healthz")
        assert response.status_code == 200
        return response.json()

    body = asyncio.run(scenario())
    assert "ruleset" in body, "the health probe does not report the ruleset"
    assert body["ruleset"] == expected


def test_the_verdict_carries_the_ruleset_and_stays_backwards_compatible():
    verdict = server._to_verdict({}, partial=True, mode=server.MODE_STATIC, degraded=False)
    assert verdict.ruleset == server._ruleset()

    # Existing callers build a Verdict without a ruleset; that must keep working.
    old = server.Verdict(
        score=0,
        severity="LOW",
        recommendation="SAFE",
        findings=[],
        scanner_version="test",
    )
    assert isinstance(old, server.Verdict)
