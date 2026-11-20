"""``--no-fetch`` over a cached time past every datetime (a corrupt value) still renders."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.health.history import NodeHistory
from meshprovision.health.store import HISTORY_DIRNAME, history_to_json
from meshprovision.network.store import NETWORK_DIRNAME, region_dirname
from meshprovision.nodeid import NodeId
from tests.e2e import test_e2e_health as health
from tests.e2e import test_e2e_network as network
from tests.e2e.conftest import invoke

if TYPE_CHECKING:
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
