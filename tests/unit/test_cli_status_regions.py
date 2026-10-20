"""Which lorastats regions `mesh status` asks: --region > the setting > lorastats.pl's list."""

from __future__ import annotations

import time
from datetime import UTC, datetime

import pytest
from click.testing import CliRunner

from meshprovision.cli import status as status_cli
from meshprovision.cli.main import cli
from meshprovision.errors import ExitCode
from meshprovision.status.merge import Thresholds
from meshprovision.status.report import StatusOptions, StatusReport

pytestmark = pytest.mark.unit


def _options_seen(
    monkeypatch: pytest.MonkeyPatch, env: dict[str, str], *args: str, polls: int = 1
) -> list[StatusOptions]:
    """Run ``mesh status`` with ``args`` and return the options of each run (poll)."""
    seen: list[StatusOptions] = []

    def fake_run_once(ctx: object, options: StatusOptions, client: object) -> StatusReport:
        del ctx, client
        seen.append(options)
        return StatusReport(generated_at=datetime.now(UTC), nodes=(), thresholds=Thresholds())

    def fake_sleep(_seconds: float) -> None:
        if len(seen) >= polls:
            raise KeyboardInterrupt

    monkeypatch.setattr(status_cli, "_run_once", fake_run_once)
    monkeypatch.setattr(time, "sleep", fake_sleep)
    result = CliRunner().invoke(cli, ["status", "--json", *args], env=env)
    assert result.exit_code == 0, result.output
    assert len(seen) == polls
    return seen


def test_without_a_setting_or_flag_status_uses_lorastats_pls_region_list(
    monkeypatch: pytest.MonkeyPatch, cli_env: dict[str, str]
) -> None:
    (options,) = _options_seen(monkeypatch, cli_env)
    assert options.regions == ()
    assert options.region_list is not None


def test_status_asks_the_configured_regions(
    monkeypatch: pytest.MonkeyPatch, cli_env: dict[str, str]
) -> None:
    env = {**cli_env, "MESHPROVISION_LORASTATS_REGIONS": "Zachód,Wschód"}
    (options,) = _options_seen(monkeypatch, env)
    assert options.regions == ("Zachód", "Wschód")
    assert options.region_list is None


def test_region_flags_override_the_configured_regions(
    monkeypatch: pytest.MonkeyPatch, cli_env: dict[str, str]
) -> None:
    env = {**cli_env, "MESHPROVISION_LORASTATS_REGIONS": "Zachód,Wschód"}
    (options,) = _options_seen(monkeypatch, env, "--region", "Gdańsk", "--region", "Rzeszów")
    assert options.regions == ("Gdańsk", "Rzeszów")


def test_every_watch_poll_shares_one_region_list(
    monkeypatch: pytest.MonkeyPatch, cli_env: dict[str, str]
) -> None:
    seen = _options_seen(monkeypatch, cli_env, "--watch", "--interval", "1", polls=3)
    assert {id(options.region_list) for options in seen} == {id(seen[0].region_list)}
    assert seen[0].region_list is not None


@pytest.mark.parametrize(
    ("env_regions", "args"),
    [("Zachód", ()), (None, ("--region", "Zachód"))],
    ids=["setting", "flag"],
)
def test_refresh_regions_is_refused_when_regions_are_configured(
    monkeypatch: pytest.MonkeyPatch,
    cli_env: dict[str, str],
    env_regions: str | None,
    args: tuple[str, ...],
) -> None:
    env = dict(cli_env)
    if env_regions is not None:
        env["MESHPROVISION_LORASTATS_REGIONS"] = env_regions
    monkeypatch.setattr(status_cli, "_run_once", lambda *_args: pytest.fail("ran"))

    result = CliRunner().invoke(cli, ["status", "--refresh-regions", *args], env=env)

    assert result.exit_code == ExitCode.CONFIG
    assert "--refresh-regions has no effect" in result.output
