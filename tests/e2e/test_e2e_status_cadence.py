"""`run_status` learns each node's interval from its health history (read only)."""

from __future__ import annotations

import dataclasses
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.config.settings import Settings
from meshprovision.datasources.models import NodeObservation
from meshprovision.db.nodes import NodeRecord
from meshprovision.health.history import HourBucket
from meshprovision.health.store import HISTORY_DIRNAME, HistoryStore
from meshprovision.nodeid import NodeId
from meshprovision.status import report as report_module
from meshprovision.status.cadence import CadenceSource
from meshprovision.status.merge import Availability
from meshprovision.status.report import StatusOptions, run_status

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

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
