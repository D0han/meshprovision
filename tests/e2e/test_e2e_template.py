"""``mesh template validate`` -- device-free, database-free template checking."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from tests.e2e.conftest import invoke

if TYPE_CHECKING:
    from collections.abc import Callable

    from click.testing import CliRunner

pytestmark = pytest.mark.e2e


def test_template_validate_ok(
    runner: CliRunner, env: dict[str, str], write_template: Callable[..., Path]
) -> None:
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template())

    result = invoke(runner, ["template", "validate"], env)

    assert result.exit_code == 0
    assert "Template OK" in result.stderr


def test_template_validate_json_reports_the_resolved_template(
    runner: CliRunner, env: dict[str, str], write_template: Callable[..., Path]
) -> None:
    template_path = write_template(admin_nodes=["ADMIN1"])
    env["MESHPROVISION_TEMPLATE_PATH"] = str(template_path)

    result = invoke(runner, ["template", "validate", "--json"], env)

    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["template_path"] == str(template_path)
    assert document["admin_nodes"] == ["ADMIN1"]
    assert document["warnings"] == []


def test_template_validate_missing_file_exits_two(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    env["MESHPROVISION_TEMPLATE_PATH"] = str(tmp_path / "does-not-exist.yaml")

    result = invoke(runner, ["template", "validate"], env)

    assert result.exit_code == 2
    assert "Template file not found" in result.stderr


def test_template_validate_malformed_yaml_exits_two(
    runner: CliRunner, env: dict[str, str], tmp_path: Path
) -> None:
    broken = tmp_path / "broken.yaml"
    broken.write_text("not: [valid yaml", encoding="utf-8")
    env["MESHPROVISION_TEMPLATE_PATH"] = str(broken)

    result = invoke(runner, ["template", "validate"], env)

    assert result.exit_code == 2
    assert "not valid YAML" in result.stderr


def test_template_validate_reports_a_capacity_warning(
    runner: CliRunner, env: dict[str, str], write_template: Callable[..., Path]
) -> None:
    """A non-fatal TemplateWarning (not a raised error) must still surface, in both modes."""
    template_path = write_template(
        short_name_pattern="MT{n}", name_min_capacity=100, name_capacity_strict=False
    )
    env["MESHPROVISION_TEMPLATE_PATH"] = str(template_path)

    result = invoke(runner, ["template", "validate"], env)
    assert result.exit_code == 0
    assert "warning:" in result.stderr.lower()

    json_result = invoke(runner, ["template", "validate", "--json"], env)
    assert json_result.exit_code == 0
    document = json.loads(json_result.stdout)
    assert document["warnings"]
    assert document["warnings"][0]["code"]


def test_template_validate_uses_the_global_template_path_flag(
    runner: CliRunner, env: dict[str, str], write_template: Callable[..., Path]
) -> None:
    """--template-path is a global `mesh` option, not a per-command one -- confirm it's honored."""
    template_path = write_template()
    del env["MESHPROVISION_TEMPLATE_PATH"]

    result = invoke(runner, ["--template-path", str(template_path), "template", "validate"], env)

    assert result.exit_code == 0
    assert "Template OK" in result.stderr
