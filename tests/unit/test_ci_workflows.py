"""The GitHub workflows pin every action to a commit and keep no checkout token."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
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


def _release_step(name: str) -> dict[str, object]:
    (step,) = [step for step in _steps(_WORKFLOW_DIR / "release.yml") if step.get("name") == name]
    return step


_WORKFLOW_DIR = Path(__file__).resolve().parents[2] / ".github" / "workflows"


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
@pytest.mark.parametrize(
    ("tag", "prerelease"),
    [
        ("v1.2.3", "false"),
        ("v1.2.3rc1", "true"),
        ("v1.2.3a1", "true"),
        ("v1.2.3b2", "true"),
        ("v1.2.3.dev1", "true"),
        ("v1.2.3a1.dev2", "true"),
        ("v1.2.3rc1.post1.dev3", "true"),
        ("v1.2.3.post1", "false"),
    ],
)
def test_a_pre_or_development_release_tag_is_marked_a_prerelease(
    tmp_path: Path, tag: str, prerelease: str
) -> None:
    output = tmp_path / "output"
    script = str(_release_step("Tell whether the tag is a pre-release")["run"])

    bash = shutil.which("bash")
    assert bash is not None

    subprocess.run(
        [bash, "-c", script],
        env={"TAG": tag, "GITHUB_OUTPUT": str(output), "PATH": os.environ["PATH"]},
        check=True,
    )

    assert output.read_text(encoding="utf-8") == f"prerelease={prerelease}\n"


def test_dependabot_leaves_ruff_to_the_hand_bump_with_its_pre_commit_rev() -> None:
    config = yaml.safe_load((_WORKFLOW_DIR.parent / "dependabot.yml").read_text(encoding="utf-8"))
    (pip,) = [update for update in config["updates"] if update["package-ecosystem"] == "pip"]

    assert {"dependency-name": "ruff"} in pip["ignore"]
    assert "ruff" not in pip["groups"]["dev-tooling"]["patterns"]
