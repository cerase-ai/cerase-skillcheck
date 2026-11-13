"""SQP-2 and SDI-2 must not report a skill for using Cerase's connectors.

A skill on Cerase reaches mail, sheets, CRMs and calendars only through
connector tools. Cerase's gateway decides at the autonomy level the
organisation's administrator set whether a call runs: writes wait for the
person's approval unless the administrator chose otherwise, and personal data
reaches the model masked. skillspector's pinned SQP-2 and SDI-2 prompts instead
ask a skill to repeat those controls itself. SQP-2 flags a connector write for
having no confirmation prompt or log of its own, and SDI-2 flags a connector
call as a capability the manifest did not justify.

The pinned prompts cannot be edited at runtime, so the image build rewrites
them the same way it adds the SQP-3 language item: ``_SKILLSPECTOR_SQP2_PATCH``
and ``_SKILLSPECTOR_SDI2_PATCH`` name the file and the exact block, and
``_patch_skillspector_sqp2`` / ``_patch_skillspector_sdi2`` insert the missing
item into each rule's ``Do NOT flag`` list. A skillspector bump that moves a
block must fail the build instead of silently restoring the false positives.

Run from the package root::

    python -m pytest tests/test_connector_rules.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server  # noqa: E402

DOCKERFILE = Path(__file__).resolve().parent.parent / "Dockerfile"


# A small stand-in for the pinned file. It has the exact SQP-2 block the real
# ``ANALYZER_PROMPT`` carries, followed by the SQP-3 block that already gets a
# language item, wrapped in a triple-quoted prompt so a patch that breaks the
# string literal shows up in the compile check.
SQP2_BLOCK = '''\
### SQP-2  Missing User Warnings
**Applies to: code files (.py, .sh, .js, .ts, .go, .rs, .rb, .pl, etc.) AND markdown files (.md), but with different criteria per type.**

**For code files:** flag safety-critical operations that lack ANY form of user
disclosure — no confirmation prompt, no logging/print statement, no docstring
or comment explaining the action, and no mention in the skill's README/SKILL.md.
Operations to check:
- File writes or deletions
- Network / HTTP calls that transmit user or system data
- Access to sensitive environment variables or credentials
- Subprocess or shell execution
- Destructive or irreversible operations

Do NOT flag an operation if:
- The code includes a visible confirmation prompt, user-facing log, or print
- The skill's markdown description explicitly warns about the operation
- The operation is clearly part of the skill's stated purpose (e.g. a "deploy"
  skill running shell commands is expected, not a missing warning)

**For markdown files:** flag when the skill description omits warnings about
behaviours that could affect user data, privacy, or system integrity.

Use rule ID **SQP-2** for all missing-warning findings.
'''

SQP3_BODY = '''\
You are reviewing a skill for policy violations.

Do NOT flag if:
- The skill explicitly offers the user a language/locale choice or opt-in
- The locale constraint is clearly documented and justified (e.g. a
  region-specific compliance tool)

Use rule ID **SQP-3** for all policy-violation findings.

Return a JSON object.
'''

SQP_PINNED_SOURCE = (
    "from __future__ import annotations\n"
    "\n"
    'ANALYZER_PROMPT = """\n'
    + SQP2_BLOCK
    + "\n"
    + SQP3_BODY
    + '"""\n'
)

# The SDI-2 prompt is later rendered with ``format(manifest_section=...)``, so
# its stand-in carries that placeholder and no other braces.
SDI2_BLOCK = '''\
### SDI-2  Context-Inappropriate Capability
The code implements a capability that is not justified by the skill's stated
purpose in the manifest.

Examples:
- A "text formatter" skill that spawns subprocesses or executes shell commands
- A "calendar reminder" skill that reads environment variables for credentials
- A "document converter" skill that accesses the network

Do NOT flag if:
- The capability is a direct and obvious requirement of the stated purpose
- The manifest explicitly declares the capability as part of the skill's scope

Use rule ID **SDI-2** for all context-inappropriate-capability findings.
'''

SDI_PINNED_SOURCE = (
    "from __future__ import annotations\n"
    "\n"
    'ANALYZER_PROMPT = """\n'
    "Skill manifest context:\n"
    "{manifest_section}\n"
    "\n"
    + SDI2_BLOCK
    + '"""\n'
)

SQP2_THIRD_ITEM = (
    '- The operation is clearly part of the skill\'s stated purpose (e.g. a "deploy"\n'
    "  skill running shell commands is expected, not a missing warning)\n"
)

SDI2_FIRST_ITEM = (
    "- The capability is a direct and obvious requirement of the stated purpose\n"
)
SDI2_SECOND_ITEM = (
    "- The manifest explicitly declares the capability as part of the skill's scope\n"
)

PATCH_CASES = (
    ("_SKILLSPECTOR_SQP2_PATCH", "_patch_skillspector_sqp2", "sqp"),
    ("_SKILLSPECTOR_SDI2_PATCH", "_patch_skillspector_sdi2", "sdi"),
)


def _pinned_source(kind: str) -> str:
    return SQP_PINNED_SOURCE if kind == "sqp" else SDI_PINNED_SOURCE


def test_the_sqp2_patch_names_the_pinned_file_and_block():
    patch = server._SKILLSPECTOR_SQP2_PATCH

    assert isinstance(patch, tuple)
    assert len(patch) == 2
    relative_path, anchor = patch
    assert relative_path == "nodes/analyzers/semantic_quality_policy.py"
    assert isinstance(anchor, str) and anchor
    assert SQP_PINNED_SOURCE.count(anchor) == 1, "the anchor is not unique in the pinned block"


def test_the_sdi2_patch_names_the_pinned_file_and_block():
    patch = server._SKILLSPECTOR_SDI2_PATCH

    assert isinstance(patch, tuple)
    assert len(patch) == 2
    relative_path, anchor = patch
    assert relative_path == "nodes/analyzers/semantic_developer_intent.py"
    assert isinstance(anchor, str) and anchor
    assert SDI_PINNED_SOURCE.count(anchor) == 1, "the anchor is not unique in the pinned block"


def test_the_sqp2_patch_adds_a_connector_item_to_the_do_not_flag_list():
    item = server._SKILLSPECTOR_SQP2_CONNECTOR_ITEM
    patched = server._patch_skillspector_sqp2(SQP_PINNED_SOURCE)

    start = patched.index("Do NOT flag an operation if:")
    end = patched.index("**For markdown files:**", start)
    region = patched[start:end]

    assert item in region
    assert (
        "- The code includes a visible confirmation prompt, user-facing log, or print\n"
        in region
    )
    assert "- The skill's markdown description explicitly warns about the operation\n" in region
    assert SQP2_THIRD_ITEM in region
    assert region.index(SQP2_THIRD_ITEM) < region.index(item), (
        "the connector item must come after the three existing items"
    )
    compile(patched, "x", "exec")
    assert SQP3_BODY in patched, "the SQP-3 block must be unchanged"


def test_the_sdi2_patch_adds_a_connector_item_to_the_do_not_flag_list():
    item = server._SKILLSPECTOR_SDI2_CONNECTOR_ITEM
    patched = server._patch_skillspector_sdi2(SDI_PINNED_SOURCE)

    start = patched.index("Do NOT flag if:")
    end = patched.index("Use rule ID **SDI-2**", start)
    region = patched[start:end]

    assert item in region
    assert SDI2_FIRST_ITEM in region
    assert SDI2_SECOND_ITEM in region
    assert region.index(SDI2_SECOND_ITEM) < region.index(item), (
        "the connector item must come after the two existing items"
    )

    namespace: dict = {}
    exec(patched, namespace)
    rendered = namespace["ANALYZER_PROMPT"].format(manifest_section="Name: x")
    assert item in rendered


@pytest.mark.parametrize(
    "item_attr",
    ["_SKILLSPECTOR_SQP2_CONNECTOR_ITEM", "_SKILLSPECTOR_SDI2_CONNECTOR_ITEM"],
)
def test_each_item_is_a_wrapped_ascii_markdown_list_item(item_attr):
    item = getattr(server, item_attr)

    assert isinstance(item, str)
    assert item.startswith("- ")
    assert item.endswith("\n")

    lines = item.splitlines()
    assert lines
    for continuation in lines[1:]:
        assert continuation.startswith("  "), (
            f"continuation line is not indented by two spaces: {continuation!r}"
        )
    for line in lines:
        assert len(line) <= 80, f"line is longer than 80 characters: {line!r}"
        assert line.isascii(), f"non-ASCII character in the item: {line!r}"
    assert "{" not in item and "}" not in item


def test_the_sqp2_item_names_the_runtime_that_handles_the_controls():
    flat = " ".join(server._SKILLSPECTOR_SQP2_CONNECTOR_ITEM.split())
    for word in (
        "Cerase",
        "connector",
        "gateway",
        "administrator",
        "approval",
        "masked",
        "markdown",
    ):
        assert word in flat, f"the SQP-2 item does not mention {word!r}"


def test_the_sdi2_item_names_the_runtime_that_handles_the_controls():
    flat = " ".join(server._SKILLSPECTOR_SDI2_CONNECTOR_ITEM.split())
    for phrase in ("Cerase", "connector", "bound to it", "administrator"):
        assert phrase in flat, f"the SDI-2 item does not mention {phrase!r}"


def test_the_sqp2_item_still_flags_operations_outside_a_connector():
    flat = " ".join(server._SKILLSPECTOR_SQP2_CONNECTOR_ITEM.split())
    for phrase in (
        "Still flag",
        "shell commands",
        "deletes or overwrites",
        "network calls made outside a connector",
        "code the skill ships",
    ):
        assert phrase in flat, f"the SQP-2 item does not say {phrase!r}"


def test_the_sdi2_item_still_flags_capabilities_outside_connectors():
    flat = " ".join(server._SKILLSPECTOR_SDI2_CONNECTOR_ITEM.split())
    for phrase in ("Still flag", "outside connectors", "unrelated to the stated purpose"):
        assert phrase in flat, f"the SDI-2 item does not say {phrase!r}"


@pytest.mark.parametrize("patch_attr,patcher_name,kind", PATCH_CASES)
def test_the_patch_fails_when_the_anchor_is_absent(patch_attr, patcher_name, kind):
    _, anchor = getattr(server, patch_attr)
    patcher = getattr(server, patcher_name)
    source = "from __future__ import annotations\n\nANALYZER_PROMPT = '''no rule here'''\n"
    assert anchor not in source

    with pytest.raises(server.SkillspectorPatchError):
        patcher(source)


@pytest.mark.parametrize("patch_attr,patcher_name,kind", PATCH_CASES)
def test_the_patch_fails_when_the_anchor_occurs_twice(patch_attr, patcher_name, kind):
    _, anchor = getattr(server, patch_attr)
    patcher = getattr(server, patcher_name)
    source = _pinned_source(kind)
    doubled = source + "\n" + source
    assert doubled.count(anchor) == 2

    with pytest.raises(server.SkillspectorPatchError):
        patcher(doubled)


@pytest.mark.parametrize("patch_attr,patcher_name,kind", PATCH_CASES)
def test_the_patch_is_idempotent_safe(patch_attr, patcher_name, kind):
    """Re-applying it finds the anchor it replaced gone, so it fails loudly."""
    patcher = getattr(server, patcher_name)
    patched = patcher(_pinned_source(kind))

    with pytest.raises(server.SkillspectorPatchError):
        patcher(patched)


def test_the_sqp3_and_sqp2_patches_compose_on_the_one_file():
    patched = server._patch_skillspector_sqp3(SQP_PINNED_SOURCE)
    patched = server._patch_skillspector_sqp2(patched)

    assert server._SKILLSPECTOR_SQP3_LANGUAGE_ITEM in patched
    assert server._SKILLSPECTOR_SQP2_CONNECTOR_ITEM in patched
    compile(patched, "x", "exec")


def test_the_image_build_applies_the_two_patches():
    """The builder stage must run the patchers against the installed package."""
    builder = DOCKERFILE.read_text(encoding="utf-8").split("# ---- runtime", 1)[0]
    for name in (
        "_SKILLSPECTOR_SQP2_PATCH",
        "_patch_skillspector_sqp2",
        "_SKILLSPECTOR_SDI2_PATCH",
        "_patch_skillspector_sdi2",
    ):
        assert name in builder
