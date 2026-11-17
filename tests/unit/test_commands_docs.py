"""docs/commands.md lists every plan warning code and every ``mesh status`` option."""

from __future__ import annotations

import re
from pathlib import Path

import click
import pytest

from meshprovision.cli.main import cli
from meshprovision.lora_regions import REGION_BANDS
from meshprovision.provisioning.plan import PlanWarningCode
from meshprovision.remote import render
from meshprovision.remote.budget import TYPICAL_CW, relay_budget_seconds
from meshprovision.remote.plan import (
    BUSY_EVIDENCE_MAX_AGE_SECONDS,
    BUSY_SHARE_OF_DUTY,
    MAX_REPLY_BYTES,
    SECURITY_REPLY_BYTES,
    plan_dry_run,
)
from meshprovision.remote.plan_types import (
    Destination,
    DryRunInputs,
    Gateway,
    NoteCode,
    RefusalCode,
    ReplySize,
)
from tests.unit.test_followup_constants import _standalone

pytestmark = pytest.mark.unit

_DOCS = (Path(__file__).resolve().parents[2] / "docs" / "commands.md").read_text(encoding="utf-8")


def _after(marker: str) -> str:
    """Return the text from ``marker`` to the next ``##`` heading."""
    start = _DOCS.index(marker) + len(marker)
    following = re.search(r"^## ", _DOCS[start:], flags=re.MULTILINE)
    return _DOCS[start : None if following is None else start + following.start()]


def test_every_plan_warning_code_has_a_row() -> None:
    table = _after("**Plan warnings.**")
    rows = re.findall(r"^\| `(\w+)` \|", table, flags=re.MULTILINE)

    assert sorted(rows) == sorted(code.value for code in PlanWarningCode)


def test_every_status_option_has_a_row() -> None:
    status = cli.commands["status"]
    section = _after("## `mesh status`")
    rows = {
        name
        for cell in re.findall(r"^\| (`--[^|]*) \|", section, flags=re.MULTILINE)
        for name in re.findall(r"`(--[\w-]+)`", cell)
    }

    options = {
        name
        for param in status.params
        if isinstance(param, click.Option)
        for name in param.opts + param.secondary_opts
        if name.startswith("--") and name != "--help"
    }
    assert rows == options


def _remote_section() -> str:
    return _after("## `mesh remote`")


def _between(text: str, start: str, end: str) -> str:
    begin = text.index(start) + len(start)
    return text[begin : text.index(end, begin)]


def test_every_remote_diff_option_has_a_row() -> None:
    diff = cli.commands["remote"].commands["diff"]  # type: ignore[attr-defined]
    rows = {
        name
        for cell in re.findall(r"^\| (`--[^|]*) \|", _remote_section(), flags=re.MULTILINE)
        for name in re.findall(r"`(--[\w-]+)`", cell)
    }

    options = {
        name
        for param in diff.params
        if isinstance(param, click.Option)
        for name in param.opts + param.secondary_opts
        if name.startswith("--") and name != "--help"
    }
    assert rows == options


def test_every_remote_refusal_code_has_a_row() -> None:
    table = _between(_remote_section(), "**Refusals.**", "**Notes.**")
    rows = re.findall(r"^\| `(\w+)` \|", table, flags=re.MULTILINE)

    assert rows == [code.value for code in RefusalCode]


def test_every_remote_note_code_has_a_row() -> None:
    table = _between(_remote_section(), "**Notes.**", "**JSON.**")
    rows = re.findall(r"^\| `(\w+)` \|", table, flags=re.MULTILINE)

    assert rows == [code.value for code in NoteCode]


def test_the_remote_json_keys_are_documented() -> None:
    plan = plan_dry_run(
        DryRunInputs(
            destination=Destination("!deadbe01", True, template_managed=True, firmware="2.8.3"),
            gateway=Gateway("!deadbe0a", True, firmware="2.8.3"),
            region="EU_868",
            preset="LONG_FAST",
            hop_limit=3,
            override_duty_cycle=False,
            template_sections=frozenset({"owner", "lora"}),
            requested_sections=frozenset({"lora"}),
        )
    )
    document: dict[str, object] = render.plan_to_json(plan)
    estimate = document["estimate"]
    assert isinstance(estimate, dict)
    keys = set(document) | set(estimate) | set(estimate["ledger"]) | set(estimate["timings"][0])
    section = _remote_section()

    missing = sorted(key for key in keys if f"`{key}`" not in section)

    assert missing == []


def test_every_remote_reply_size_is_documented() -> None:
    listed = re.search(r"`reply_size`: ([^)]*)\)", _remote_section())

    assert listed is not None
    assert re.findall(r"`([a-z]+)`", listed.group(1)) == [size.value for size in ReplySize]


@pytest.mark.parametrize(
    "phrase",
    [
        f"a polite share of {relay_budget_seconds('EU_868'):g} s per rolling hour",
        f"largest possible packet ({MAX_REPLY_BYTES} B)",
        f"signature policy, {SECURITY_REPLY_BYTES} B.",
        f"above {REGION_BANDS['EU_868'].duty_cycle * BUSY_SHARE_OF_DUTY:g} %",
        f"in the last {BUSY_EVIDENCE_MAX_AGE_SECONDS / 3600:g} hours",
        f"contention window {TYPICAL_CW}",
        render.ESTIMATE_LINE,
    ],
)
def test_the_remote_section_states_each_value(phrase: str) -> None:
    assert _standalone(phrase, _remote_section()) == 1
