"""Each node's expected interval: learned by `run_status`, the template, `--expected-interval`."""

from __future__ import annotations

import dataclasses
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.config.settings import Settings
from meshprovision.datasources.models import NodeObservation
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import ManagementMode
from meshprovision.health.history import HourBucket
from meshprovision.health.store import HISTORY_DIRNAME, HistoryStore
from meshprovision.nodeid import NodeId
from meshprovision.status import report as report_module
from meshprovision.status.cadence import CadenceSource
from meshprovision.status.merge import Availability
from meshprovision.status.report import StatusOptions, run_status
from tests.e2e.conftest import invoke

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    import respx
    from click.testing import CliRunner, Result

pytestmark = pytest.mark.e2e

_NODE = NodeId.from_hex("deadbe01")
_SILENT_FOR = timedelta(hours=10)


class _HeardTenHoursAgo:
    """A loranet stand-in that last heard every node ten hours ago."""

    name = "loranet"
    last_fetch_skipped = 0
    last_fetch_field_coercions = 0
    last_fetch_data_as_of = None

    def __init__(self, _client: object) -> None:
        pass

    def fetch_nodes(
        self, ids: Sequence[NodeId], **_options: object
    ) -> dict[NodeId, NodeObservation]:
        now = datetime.now(tz=UTC)
        return {
            node_id: NodeObservation(
                node_id=node_id, source="loranet", observed_at=now, last_seen=now - _SILENT_FOR
            )
            for node_id in ids
        }


def _settings(env: dict[str, str], seed_db: Callable[..., Path]) -> Settings:
    seed_db(nodes=[NodeRecord(node_id="deadbe01", role="CLIENT")])
    return Settings(
        db_path=Path(env["MESHPROVISION_DB_PATH"]), cache_dir=Path(env["MESHPROVISION_CACHE_DIR"])
    )


def _store_six_hourly_history(cache_dir: Path) -> Path:
    newest = int(time.time()) // 3600 * 3600 - 10 * 3600
    buckets = tuple(
        HourBucket(hour=newest - offset * 3600, receptions=0 if offset % 6 else 3)
        for offset in reversed(range(48))
    )
    store = HistoryStore(cache_dir / HISTORY_DIRNAME)
    store.update(_NODE, lambda history: dataclasses.replace(history, hours=buckets))
    return store.path_for(_NODE)


def test_a_six_hourly_node_heard_ten_hours_ago_is_online(
    env: dict[str, str], seed_db: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(env, seed_db)
    path = _store_six_hourly_history(settings.cache_dir)
    before = path.stat().st_mtime_ns
    monkeypatch.setattr(report_module, "LoranetSource", _HeardTenHoursAgo)

    node = run_status(settings, StatusOptions(sources=("loranet",))).nodes[0]

    assert node.cadence.source is CadenceSource.HISTORY
    assert node.cadence.interval == timedelta(hours=6)
    assert node.availability is Availability.ONLINE
    assert path.stat().st_mtime_ns == before


def test_without_a_history_the_same_node_is_stale(
    env: dict[str, str], seed_db: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(env, seed_db)
    monkeypatch.setattr(report_module, "LoranetSource", _HeardTenHoursAgo)

    node = run_status(settings, StatusOptions(sources=("loranet",))).nodes[0]

    assert node.cadence.source is CadenceSource.ROLE
    assert node.availability is Availability.STALE


def test_an_override_reads_no_history(
    env: dict[str, str], seed_db: Callable[..., Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(env, seed_db)
    _store_six_hourly_history(settings.cache_dir)
    monkeypatch.setattr(report_module, "LoranetSource", _HeardTenHoursAgo)

    def _no_reading(*_args: object, **_kwargs: object) -> dict[NodeId, timedelta]:
        raise AssertionError("the histories were read")

    monkeypatch.setattr(report_module, "learned_intervals", _no_reading)
    options = StatusOptions(sources=("loranet",), expected_interval=timedelta(hours=4))

    node = run_status(settings, options).nodes[0]

    assert node.cadence.source is CadenceSource.OVERRIDE
    assert node.availability is Availability.STALE


# ---------------------------------------------------------------------------
# The CLI: --expected-interval and the template.
# ---------------------------------------------------------------------------


def _seed_managed(seed_db: Callable[..., Path]) -> None:
    seed_db(
        nodes=[
            NodeRecord(node_id="deadbe01", role="CLIENT", management=ManagementMode.TEMPLATE),
            NodeRecord(node_id="deadbe02", role="CLIENT", management=ManagementMode.OBSERVED),
        ]
    )


def _status_json(
    runner: CliRunner,
    env: dict[str, str],
    mock_sources: Callable[..., respx.MockRouter],
    *args: str,
) -> tuple[Result, list[dict[str, object]]]:
    recent = int(time.time()) - 60
    nodes = {hex_id: {"seenBy": {"gw1": recent}} for hex_id in ("deadbe01", "deadbe02")}
    with mock_sources(nodes=nodes):
        result = invoke(runner, ["status", "--json", "--source", "loranet", *args], env)
    documents = json.loads(result.stdout)["nodes"] if result.exit_code == 0 else []
    return result, documents


def _cadences(documents: list[dict[str, object]]) -> list[tuple[object, object]]:
    return [
        (doc["expected_interval_source"], doc["expected_interval_seconds"]) for doc in documents
    ]


def test_a_template_managed_node_gets_the_template_interval(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
    write_template: Callable[..., Path],
) -> None:
    _seed_managed(seed_db)
    template = write_template(device={"role": "CLIENT", "node_info_broadcast_secs": 21600})
    env = {**env, "MESHPROVISION_TEMPLATE_PATH": str(template)}

    result, documents = _status_json(runner, env, mock_sources)

    assert result.exit_code == 0
    assert _cadences(documents) == [("template", 21600), ("role", 10800)]
    assert documents[0]["stale_after_seconds"] == 13.5 * 3600
    assert "template" not in result.stderr


def test_an_unloadable_template_is_skipped_with_a_warning(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
    tmp_path: Path,
) -> None:
    _seed_managed(seed_db)
    broken = tmp_path / "broken.yaml"
    broken.write_text("device: [unclosed\n", encoding="utf-8")
    env = {**env, "MESHPROVISION_TEMPLATE_PATH": str(broken)}

    result, documents = _status_json(runner, env, mock_sources)

    assert result.exit_code == 0
    assert _cadences(documents) == [("role", 10800), ("role", 10800)]
    assert result.stderr.count("Not using the template") == 1


def test_a_missing_template_is_skipped_silently(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
    tmp_path: Path,
) -> None:
    _seed_managed(seed_db)
    env = {**env, "MESHPROVISION_TEMPLATE_PATH": str(tmp_path / "absent.yaml")}

    result, documents = _status_json(runner, env, mock_sources)

    assert result.exit_code == 0
    assert _cadences(documents) == [("role", 10800), ("role", 10800)]
    assert "template" not in result.stderr


def test_expected_interval_beats_the_template_interval(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
    write_template: Callable[..., Path],
) -> None:
    _seed_managed(seed_db)
    template = write_template(device={"role": "CLIENT", "node_info_broadcast_secs": 21600})
    env = {**env, "MESHPROVISION_TEMPLATE_PATH": str(template)}

    result, documents = _status_json(runner, env, mock_sources, "--expected-interval", "0.5")

    assert result.exit_code == 0
    assert _cadences(documents) == [("override", 1800), ("override", 1800)]
    assert {(doc["stale_after_seconds"], doc["offline_after_seconds"]) for doc in documents} == {
        (7200, 86400)
    }


def test_the_template_preset_is_shown_for_template_managed_nodes_only(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
    write_template: Callable[..., Path],
) -> None:
    _seed_managed(seed_db)
    template = write_template(lora={"use_preset": True, "modem_preset": "MEDIUM_FAST"})
    env = {**env, "MESHPROVISION_TEMPLATE_PATH": str(template)}

    result, documents = _status_json(runner, env, mock_sources, "--expected-interval", "2")

    assert result.exit_code == 0
    assert [doc["modem_preset"] for doc in documents] == ["MEDIUM_FAST", None]


def test_a_template_without_use_preset_gives_no_preset(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
    write_template: Callable[..., Path],
) -> None:
    _seed_managed(seed_db)
    template = write_template(lora={"use_preset": False, "modem_preset": "MEDIUM_FAST"})
    env = {**env, "MESHPROVISION_TEMPLATE_PATH": str(template)}

    result, documents = _status_json(runner, env, mock_sources)

    assert result.exit_code == 0, result.output
    assert [doc["modem_preset"] for doc in documents] == [None, None]


@pytest.mark.parametrize("value", ["0", "-1", "48.01", "nan", "inf"])
def test_expected_interval_outside_its_range_is_a_usage_error(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
    value: str,
) -> None:
    _seed_managed(seed_db)
    result, _ = _status_json(runner, env, mock_sources, "--expected-interval", value)
    assert result.exit_code == 2


def test_expected_interval_accepts_its_upper_bound(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    _seed_managed(seed_db)
    result, documents = _status_json(runner, env, mock_sources, "--expected-interval", "48")
    assert result.exit_code == 0
    assert _cadences(documents)[0] == ("override", 48 * 3600)
