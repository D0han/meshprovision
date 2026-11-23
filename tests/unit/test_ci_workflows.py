"""The GitHub workflows pin every action to a commit and keep no checkout token."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

WORKFLOWS = sorted((Path(__file__).resolve().parents[2] / ".github" / "workflows").glob("*.yml"))

_SHA_PIN_RE = re.compile(r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")


def _steps(path: Path) -> list[dict[str, object]]:
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    return [step for job in workflow["jobs"].values() for step in job["steps"]]


def test_there_are_workflows() -> None:
    assert [path.name for path in WORKFLOWS] == ["ci.yml", "release.yml"]


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_every_action_is_pinned_to_a_full_commit_sha(path: Path) -> None:
    uses = [str(step["uses"]) for step in _steps(path) if "uses" in step]

    assert uses
    assert [use for use in uses if not _SHA_PIN_RE.match(use)] == []


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_no_checkout_keeps_its_token(path: Path) -> None:
    checkouts = [
        step for step in _steps(path) if str(step.get("uses", "")).startswith("actions/checkout@")
    ]

    assert checkouts
    assert all(step.get("with", {}).get("persist-credentials") is False for step in checkouts)
