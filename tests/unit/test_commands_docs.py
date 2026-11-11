"""docs/commands.md lists every plan warning code and every ``mesh status`` option."""

from __future__ import annotations

import re
from pathlib import Path

import click
import pytest

from meshprovision.cli.main import cli
from meshprovision.provisioning.plan import PlanWarningCode

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
