"""Which lorastats regions ``mesh status`` asks: ``--region`` > the setting > the defaults."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from click.testing import CliRunner

from meshprovision.cli import status as status_cli
from meshprovision.cli.main import cli
from meshprovision.datasources.lorastats import DEFAULT_REGIONS
from meshprovision.status.merge import Thresholds
from meshprovision.status.report import StatusOptions, StatusReport

pytestmark = pytest.mark.unit


def _regions_asked(
    monkeypatch: pytest.MonkeyPatch, env: dict[str, str], *args: str
) -> tuple[str, ...]:
    """Run ``mesh status`` with ``args`` and return the regions its one run used."""
    seen: list[tuple[str, ...]] = []

    def fake_run_once(ctx: object, options: StatusOptions, client: object) -> StatusReport:
        del ctx, client
        seen.append(options.regions)
        return StatusReport(generated_at=datetime.now(UTC), nodes=(), thresholds=Thresholds())

    monkeypatch.setattr(status_cli, "_run_once", fake_run_once)
    result = CliRunner().invoke(cli, ["status", "--json", *args], env=env)
    assert result.exit_code == 0, result.output
    (regions,) = seen
    return regions


def test_status_asks_the_default_regions_without_a_setting_or_flag(
    monkeypatch: pytest.MonkeyPatch, cli_env: dict[str, str]
) -> None:
    assert _regions_asked(monkeypatch, cli_env) == DEFAULT_REGIONS


def test_status_asks_the_configured_regions(
    monkeypatch: pytest.MonkeyPatch, cli_env: dict[str, str]
) -> None:
    env = {**cli_env, "MESHPROVISION_LORASTATS_REGIONS": "PL,Wschód"}
    assert _regions_asked(monkeypatch, env) == ("PL", "Wschód")


def test_region_flags_override_the_configured_regions(
    monkeypatch: pytest.MonkeyPatch, cli_env: dict[str, str]
) -> None:
    env = {**cli_env, "MESHPROVISION_LORASTATS_REGIONS": "PL,Wschód"}
    assert _regions_asked(monkeypatch, env, "--region", "XX", "--region", "YY") == ("XX", "YY")
