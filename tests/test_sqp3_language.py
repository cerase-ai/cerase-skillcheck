"""SQP-3 must not report a skill merely for being written in another language.

skillspector's pinned SQP-3 prompt asks whether the skill forces the user into a
language. Its ``Do NOT flag if`` list covers an explicit language choice and a
justified locale constraint, but not the plain fact that a skill is written in
Italian: live scans produced SQP-3 findings whose explanations said the skill
"is written entirely in Italian", "requires the final message to be in Italian"
or "uses an Italian-language placeholder". A skill written in the language of
the people who use it leaves them the language they write in.

The pinned prompt cannot be edited at runtime, so the image build rewrites it
the same way it raises the per-call timeout: ``_SKILLSPECTOR_SQP3_PATCH`` names
the file and the exact block, and ``_patch_skillspector_sqp3`` inserts the
missing item into the ``Do NOT flag if`` list. A skillspector bump that moves
the block must fail the build instead of silently restoring the false positives.

Run from the package root::

    python -m pytest tests/test_sqp3_language.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server  # noqa: E402

DOCKERFILE = Path(__file__).resolve().parent.parent / "Dockerfile"


# A small stand-in for the pinned file. It has the exact block the real
# ``ANALYZER_PROMPT`` carries, wrapped in a triple-quoted prompt so a patch that
# breaks the string literal shows up in the compile check.
PINNED_SOURCE = '''\
from __future__ import annotations

ANALYZER_PROMPT = """
You are reviewing a skill for policy violations.

Do NOT flag if:
- The skill explicitly offers the user a language/locale choice or opt-in
- The locale constraint is clearly documented and justified (e.g. a
  region-specific compliance tool)

Use rule ID **SQP-3** for all policy-violation findings.

Return a JSON object.
"""
'''


def test_the_patch_names_the_pinned_sqp3_file_and_block():
    patch = server._SKILLSPECTOR_SQP3_PATCH

    assert isinstance(patch, tuple)
    assert len(patch) == 2
    relative_path, anchor = patch
    assert relative_path == "nodes/analyzers/semantic_quality_policy.py"
    assert isinstance(anchor, str) and anchor
    assert anchor in PINNED_SOURCE, "the anchor is not a substring of the pinned block"


def test_the_patch_adds_a_language_item_to_the_do_not_flag_list():
    patched = server._patch_skillspector_sqp3(PINNED_SOURCE)

    start = patched.index("Do NOT flag if:")
    end = patched.index("Use rule ID **SQP-3**", start)
    do_not_flag = patched[start:end]

    assert "written in" in do_not_flag
    assert "language the user writes in" in do_not_flag
    assert (
        "- The skill explicitly offers the user a language/locale choice or opt-in" in do_not_flag
    )
    assert (
        "- The locale constraint is clearly documented and justified (e.g. a\n"
        "  region-specific compliance tool)" in do_not_flag
    )
    compile(patched, "x", "exec")


def test_the_patch_fails_when_the_anchor_is_absent():
    _, anchor = server._SKILLSPECTOR_SQP3_PATCH
    source = "from __future__ import annotations\n\nANALYZER_PROMPT = '''no rule here'''\n"
    assert anchor not in source

    with pytest.raises(server.SkillspectorPatchError):
        server._patch_skillspector_sqp3(source)


def test_the_patch_fails_when_the_anchor_occurs_twice():
    _, anchor = server._SKILLSPECTOR_SQP3_PATCH
    source = PINNED_SOURCE + "\n" + PINNED_SOURCE
    assert source.count(anchor) == 2

    with pytest.raises(server.SkillspectorPatchError):
        server._patch_skillspector_sqp3(source)


def test_the_patch_is_idempotent_safe():
    """Re-applying it finds the anchor it replaced gone, so it fails loudly."""
    patched = server._patch_skillspector_sqp3(PINNED_SOURCE)

    with pytest.raises(server.SkillspectorPatchError):
        server._patch_skillspector_sqp3(patched)


def test_the_image_build_applies_the_patch():
    """The builder stage must run the patcher against the installed package."""
    builder = DOCKERFILE.read_text(encoding="utf-8").split("# ---- runtime", 1)[0]
    assert "_SKILLSPECTOR_SQP3_PATCH" in builder
    assert "_patch_skillspector_sqp3" in builder
