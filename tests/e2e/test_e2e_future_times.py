"""``--no-fetch`` over a cached time past every datetime (a corrupt value) still renders."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.datasources.region_memo import REGION_MEMO_FILENAME, REGION_MEMO_VERSION
from meshprovision.health.history import NodeHistory
from meshprovision.health.store import HISTORY_DIRNAME, history_to_json
from meshprovision.network.store import NETWORK_DIRNAME, region_dirname
from meshprovision.nodeid import NodeId
from tests.e2e import test_e2e_health as health
from tests.e2e import test_e2e_network as network
from tests.e2e.conftest import invoke

if TYPE_CHECKING:
    import respx
    from click.testing import CliRunner

pytestmark = pytest.mark.e2e

_FAR = 1e12
"""Year 33658: :meth:`datetime.fromtimestamp` raises for it."""


def test_health_no_fetch_reads_a_far_future_history_time_as_unknown(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    health._seed(seed_db)
    directory = Path(env["MESHPROVISION_CACHE_DIR"]) / HISTORY_DIRNAME
    directory.mkdir(parents=True)
    history = NodeHistory(node=NodeId.from_hex(health._A), fetched_at=_FAR, last_heard=_FAR)
    (directory / f"{health._A}.json").write_text(json.dumps(history_to_json(history)))

    text = invoke(runner, ["health", "--no-fetch"], env)
    detail = invoke(runner, ["health", health._A, "--no-fetch"], env)
    as_json = invoke(runner, ["health", "--no-fetch", "--json"], env)

    assert (text.exit_code, detail.exit_code, as_json.exit_code) == (0, 0, 0)
    (node,) = (n for n in json.loads(as_json.stdout)["nodes"] if n["node_id"] == health._A)
    assert (node["history_fetched_at"], node["metrics"]["last_heard"]) == (None, None)


@pytest.mark.parametrize("view", ["keys", "relays"])
def test_network_no_fetch_reads_a_far_future_fetch_time_as_no_data(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], view: str
) -> None:
    network._seed(seed_db)
    network._run(runner, env, [view, "--region", "PL"])
    state_file = (
        Path(env["MESHPROVISION_CACHE_DIR"]) / NETWORK_DIRNAME / region_dirname("PL") / "state.json"
    )
    state = json.loads(state_file.read_text(encoding="utf-8"))
    state_file.write_text(json.dumps({**state, "fetched_at": _FAR}), encoding="utf-8")

    text, _ = network._run(runner, env, [view, "--region", "PL", "--no-fetch"])
    as_json, _ = network._run(runner, env, [view, "--region", "PL", "--no-fetch", "--json"])

    assert "no data yet" in text.stdout
    assert (text.exit_code, as_json.exit_code) == (3, 3)
    (region,) = json.loads(as_json.stdout)["regions"]
    assert region["data_as_of"] is None


def test_health_judges_a_fresh_low_battery_over_a_level_dated_in_the_future(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    """An old loranet 95% dated a day ahead hid the 4% lorastats heard 10 minutes ago."""
    health._seed(seed_db)
    now = time.time()
    ahead = {"batteryLevel": 95, "lastDeviceMetrics": int(now) + 86400}
    nodes = {
        hex_id: {**fields, **ahead} if hex_id == health._A else fields
        for hex_id, fields in health._nodes(now).items()
    }
    router = mock_sources(nodes=nodes)
    rows = {health._A: health._reports(health._A, now, battery=4)}
    health._Lorastats(router, {**rows, health._B: health._reports(health._B, now)})

    with router:
        result = invoke(runner, ["health", "--json"], env)

    (node,) = (n for n in json.loads(result.stdout)["nodes"] if n["node_id"] == health._A)
    assert result.exit_code == 7
    assert node["verdict"] == "crit"
    assert [f["text"] for f in node["findings"] if f["code"] == "battery_low"] == ["battery at 4%"]


def test_a_remembered_region_time_too_large_for_a_float_is_never_current(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    health._seed(seed_db)
    memo = Path(env["MESHPROVISION_CACHE_DIR"]) / REGION_MEMO_FILENAME
    memo.parent.mkdir(parents=True, exist_ok=True)
    node = f'"{health._A}": {{"region": "PL", "stored_at": 1{"0" * 400}}}'
    memo.write_text(f'{{"version": {REGION_MEMO_VERSION}, "nodes": {{{node}}}}}', encoding="utf-8")

    result = invoke(runner, ["network", "relays", "--no-fetch"], env)

    assert result.exit_code == 2, result.exception
    assert "No lorastats region is known for any of our nodes" in result.output


def test_health_no_fetch_ignores_a_last_heard_a_year_ahead(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    """A last_heard a year ahead judged the node OK, "Last heard: in the future"."""
    health._seed(seed_db)
    directory = Path(env["MESHPROVISION_CACHE_DIR"]) / HISTORY_DIRNAME
    directory.mkdir(parents=True)
    now = time.time()
    history = NodeHistory(
        node=NodeId.from_hex(health._A), fetched_at=now - 600, last_heard=now + 365 * 86400
    )
    (directory / f"{health._A}.json").write_text(json.dumps(history_to_json(history)))

    as_json = invoke(runner, ["health", "--no-fetch", "--json"], env)
    detail = invoke(runner, ["health", health._A, "--no-fetch"], env)

    (node,) = (n for n in json.loads(as_json.stdout)["nodes"] if n["node_id"] == health._A)
    assert (node["verdict"], node["metrics"]["last_heard"]) == ("unknown", None)
    assert "Last heard: -" in detail.stdout
