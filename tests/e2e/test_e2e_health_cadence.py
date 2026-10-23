"""``mesh health`` judges each node against its expected interval (override, template)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.cache.http import CachedHTTPClient
from meshprovision.config.settings import Settings
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import ManagementMode
from meshprovision.health import report as health_report
from meshprovision.health.report import HealthOptions, run_health
from meshprovision.status.merge import Thresholds
from meshprovision.status.report import StatusOptions, StatusReport
from tests.e2e.conftest import invoke

if TYPE_CHECKING:
    from collections.abc import Callable

    from click.testing import CliRunner

pytestmark = pytest.mark.e2e


def _seed(seed_db: Callable[..., Path]) -> None:
    seed_db(
        nodes=[
            NodeRecord(node_id="deadbe01", role="CLIENT", management=ManagementMode.TEMPLATE),
            NodeRecord(node_id="deadbe02", role="TAK", management=ManagementMode.OBSERVED),
        ]
    )


def _cadences(stdout: str) -> list[tuple[object, object]]:
    return [
        (node["expected_interval_source"], node["expected_interval_seconds"])
        for node in json.loads(stdout)["nodes"]
    ]


def test_no_fetch_uses_the_template_and_the_role(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    write_template: Callable[..., Path],
) -> None:
    _seed(seed_db)
    template = write_template(device={"role": "CLIENT", "node_info_broadcast_secs": 7200})
    env = {**env, "MESHPROVISION_TEMPLATE_PATH": str(template)}

    result = invoke(runner, ["health", "--no-fetch", "--json"], env)

    assert result.exit_code == 0, result.output
    assert _cadences(result.stdout) == [("template", 7200), ("role", 86400)]


def test_expected_interval_overrides_every_node(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], tmp_path: Path
) -> None:
    _seed(seed_db)
    broken = tmp_path / "broken.yaml"
    broken.write_text("device: [unclosed\n", encoding="utf-8")
    env = {**env, "MESHPROVISION_TEMPLATE_PATH": str(broken)}

    result = invoke(runner, ["health", "--no-fetch", "--json", "--expected-interval", "6"], env)

    assert result.exit_code == 0, result.output
    assert _cadences(result.stdout) == [("override", 21600), ("override", 21600)]
    assert "template" not in result.stderr


def test_an_unloadable_template_is_skipped_with_a_warning(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], tmp_path: Path
) -> None:
    _seed(seed_db)
    broken = tmp_path / "broken.yaml"
    broken.write_text("device: [unclosed\n", encoding="utf-8")
    env = {**env, "MESHPROVISION_TEMPLATE_PATH": str(broken)}

    result = invoke(runner, ["health", "--no-fetch", "--json"], env)

    assert result.exit_code == 0, result.output
    assert _cadences(result.stdout) == [("role", 10800), ("role", 86400)]
    assert result.stderr.count("Not using the template") == 1


@pytest.mark.parametrize("value", ["0", "48.5", "nan"])
def test_expected_interval_outside_its_range_is_a_usage_error(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], value: str
) -> None:
    _seed(seed_db)
    result = invoke(runner, ["health", "--no-fetch", "--expected-interval", value], env)
    assert result.exit_code == 2


def test_fetching_passes_the_interval_to_mesh_status(
    env: dict[str, str], seed_db: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed(seed_db)
    settings = Settings(
        db_path=Path(env["MESHPROVISION_DB_PATH"]),
        cache_dir=Path(env["MESHPROVISION_CACHE_DIR"]),
        contact="t@example.invalid",
    )
    seen: list[StatusOptions] = []

    def _run_status(_settings: Settings, options: StatusOptions, **_kw: object) -> StatusReport:
        seen.append(options)
        return StatusReport(generated_at=datetime.now(tz=UTC), nodes=(), thresholds=Thresholds())

    monkeypatch.setattr(health_report, "run_status", _run_status)
    options = HealthOptions(
        expected_interval=timedelta(hours=5), template_interval=timedelta(hours=4)
    )
    client = CachedHTTPClient(cache_dir=settings.cache_dir, user_agent="mp/1 (+t@example.invalid)")
    try:
        run_health(settings, options, client=client)
    finally:
        client.close()

    (status_options,) = seen
    assert status_options.expected_interval == timedelta(hours=5)
    assert status_options.template_interval == timedelta(hours=4)
