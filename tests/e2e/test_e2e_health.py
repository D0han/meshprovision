"""``mesh health`` against respx-mocked loranet.pl and lorastats.pl (synthetic packet rows)."""

from __future__ import annotations

import json
import stat
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
import pytest
import respx

from meshprovision.datasources.loranet import LORANET_NODES_URL
from meshprovision.datasources.lorastats import LORASTATS_BASE_URL, LORASTATS_NODES_PATH
from meshprovision.datasources.lorastats_packets import (
    LORASTATS_PACKET_REPORTS_PATH,
    LORASTATS_PACKETS_PARSED_PATH,
    since_param,
)
from meshprovision.db.nodes import NodeRecord
from meshprovision.nodeid import NodeId
from tests.e2e.conftest import db_fingerprint, invoke

if TYPE_CHECKING:
    from click.testing import CliRunner

pytestmark = pytest.mark.e2e

_A = "ab446357"
_B = "979ed146"
_GATEWAYS = ("32aca541", "db58ae50", "4000722a")


def _seed(seed_db: Callable[..., Path]) -> None:
    seed_db(
        nodes=[
            NodeRecord(node_id=_A, short_name="D0h5", long_name="Alpha D0h5", role="CLIENT_MUTE"),
            NodeRecord(node_id=_B, short_name="Bravo", long_name="Bravo node", role="ROUTER"),
        ]
    )


def _reports(
    node: str, now: float, *, battery: int = 80
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Twelve packets over the last 6 hours, each heard by every gateway; 9 of them decoded."""
    reports: list[dict[str, Any]] = []
    parsed: list[dict[str, Any]] = []
    for index in range(12):
        when = since_param(now - 600 - index * 1800)
        packet = f"{index + 1:08x}"
        for hop_limit, gateway in enumerate(_GATEWAYS, start=4):
            reports.append(
                {
                    "Time": when,
                    "Gateway": gateway,
                    "FromNode": node,
                    "ToNode": None,
                    "PacketId": packet,
                    "SNR": 6.5,
                    "RSSI": 170,
                    "HopLimit": hop_limit,
                    "RelayNode": 0x61,
                    "NextHop": 0,
                }
            )
        if index % 4 != 3:
            parsed.append(
                {
                    "Time": when,
                    "FromNode": node,
                    "ToNode": None,
                    "PacketId": packet,
                    "HopStart": 7,
                    "WantAck": False,
                    "WantResponse": False,
                    "PortNum": 67,
                    "BitField": 1,
                    "Channel": 1003,
                    "Payload": f"3.5% ChUtil, 0.02% AirUtilTx, {battery}% Bat",
                }
            )
    return reports, parsed


class _Lorastats:
    """respx routes for PacketReports (by node and by gateway) and PacketsParsed."""

    def __init__(
        self, router: respx.MockRouter, rows: Mapping[str, Any], *, status: int = 200
    ) -> None:
        self.reports: list[httpx.Request] = []
        self.parsed: list[httpx.Request] = []
        self.uplinked: list[httpx.Request] = []

        def reports(request: httpx.Request) -> httpx.Response:
            if status != 200:
                return httpx.Response(status)
            gateway = request.url.params.get("gateway")
            if gateway is not None:
                self.uplinked.append(request)
                return httpx.Response(200, json=rows.get("uplinked", []))
            self.reports.append(request)
            return httpx.Response(200, json=rows.get(request.url.params["fromNode"], ([], []))[0])

        def parsed(request: httpx.Request) -> httpx.Response:
            self.parsed.append(request)
            return httpx.Response(200, json=rows.get(request.url.params["fromNode"], ([], []))[1])

        base = LORASTATS_BASE_URL
        router.get(url__startswith=base + LORASTATS_PACKET_REPORTS_PATH.format(region="PL")).mock(
            side_effect=reports
        )
        router.get(url__startswith=base + LORASTATS_PACKETS_PARSED_PATH.format(region="PL")).mock(
            side_effect=parsed
        )


def _nodes(now: float, *, known: Sequence[str] = (_A, _B)) -> dict[str, dict[str, object]]:
    names = {_A: "D0h5", _B: "Bravo"}
    return {
        hex_id: {"shortName": names[hex_id], "seenBy": {"gw1": int(now) - 60}} for hex_id in known
    }


def _run(
    runner: CliRunner,
    env: dict[str, str],
    mock_sources: Callable[..., respx.MockRouter],
    args: Sequence[str],
    rows: Mapping[str, Any],
    *,
    known: Sequence[str] = (_A, _B),
    status: int = 200,
) -> tuple[Any, _Lorastats]:
    router = mock_sources(nodes=_nodes(time.time(), known=known))
    lorastats = _Lorastats(router, rows, status=status)
    with router:
        result = invoke(runner, ["health", *args], env)
    return result, lorastats


@pytest.fixture
def rows() -> dict[str, Any]:
    now = time.time()
    return {_A: _reports(_A, now), _B: _reports(_B, now)}


def test_the_table_judges_every_active_node_with_two_requests_each(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
    rows: dict[str, Any],
) -> None:
    _seed(seed_db)

    result, lorastats = _run(runner, env, mock_sources, [], rows)

    assert result.exit_code == 0, result.output
    assert "D0h5" in result.stdout
    assert "OK" in result.stdout
    assert "2 node(s): 2 ok, 0 warn, 0 crit, 0 unknown; window 7 d" in result.stdout
    assert len(lorastats.reports) == len(lorastats.parsed) == 2
    assert lorastats.uplinked == []
    assert {r.url.params["fromNode"] for r in lorastats.reports} == {_A, _B}
    assert all("since" not in r.url.params for r in lorastats.reports)


def test_a_second_run_within_ten_minutes_asks_lorastats_nothing_new(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
    rows: dict[str, Any],
) -> None:
    _seed(seed_db)
    _run(runner, env, mock_sources, [], rows)

    again, lorastats = _run(runner, env, mock_sources, ["--refresh"], rows)

    assert again.exit_code == 0, again.output
    assert lorastats.reports == lorastats.parsed == []
    assert "2 ok" in again.stdout


def test_json_carries_metrics_with_their_samples(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
    rows: dict[str, Any],
) -> None:
    _seed(seed_db)

    result, _ = _run(runner, env, mock_sources, ["--json", "--days", "1"], rows)

    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert (document["days"], document["fetched"]) == (1, True)
    assert document["refresh"]["refreshed"] == [_A, _B]
    node = document["nodes"][0]
    assert node["node_id"] == _A
    assert node["verdict"] == "ok"
    metrics = node["metrics"]
    assert (metrics["receptions"], metrics["packets"], metrics["gateway_count"]) == (36, 12, 3)
    assert metrics["hops"] == {"1": 9, "2": 9, "3": 9}
    assert (metrics["hop_samples"], metrics["hop_start"], metrics["hops_max"]) == (27, 7, 3)
    assert metrics["decoded_share"] == 0.75
    assert metrics["battery"]["latest"] == 80
    assert metrics["relays"][0]["byte"] == 0x61
    assert node["suggestions"][0]["code"] == "hop_limit"


def test_the_detailed_report_adds_one_gateway_check(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
    rows: dict[str, Any],
) -> None:
    _seed(seed_db)
    uplinked = [{"FromNode": _B, "PacketId": "1"}, {"FromNode": "12345678", "PacketId": "2"}]

    result, lorastats = _run(runner, env, mock_sources, [_A], {**rows, "uplinked": uplinked})

    assert result.exit_code == 0, result.output
    assert len(lorastats.reports) == len(lorastats.parsed) == len(lorastats.uplinked) == 1
    assert lorastats.uplinked[0].url.params["gateway"] == _A
    assert "Verdict: OK" in result.stdout
    assert "Hops: 1:9 2:9 3:9" in result.stdout
    assert "uplinked 2 reports from 2 node(s)" in result.stdout
    assert "consider a hop limit of 4" in result.stdout
    assert "Limits:" in result.stdout


def test_no_fetch_asks_nothing_and_needs_no_contact(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
    rows: dict[str, Any],
) -> None:
    _seed(seed_db)
    _run(runner, env, mock_sources, [], rows)
    del env["MESHPROVISION_CONTACT"]

    with respx.mock(assert_all_mocked=True) as router:
        result = invoke(runner, ["health", "--no-fetch", "--json"], env)

    assert result.exit_code == 0, result.output
    assert router.calls.call_count == 0
    document = json.loads(result.stdout)
    assert document["fetched"] is False
    assert document["network_requests"] == 0
    assert [node["metrics"]["receptions"] for node in document["nodes"]] == [36, 36]


def test_no_fetch_without_history_reports_unknown(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    _seed(seed_db)

    result = invoke(runner, ["health", "--no-fetch"], env)

    assert result.exit_code == 0
    assert "0 ok, 0 warn, 0 crit, 2 unknown" in result.stdout
    assert "history only, nothing fetched" in result.stdout


def test_refresh_with_no_fetch_is_a_usage_error(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    _seed(seed_db)

    result = invoke(runner, ["health", "--no-fetch", "--refresh"], env)

    assert result.exit_code == 2
    assert "--refresh has no effect with --no-fetch" in result.stderr


@pytest.mark.parametrize("days", ["0", "31"])
def test_days_outside_the_history_is_a_usage_error(
    runner: CliRunner, env: dict[str, str], days: str
) -> None:
    assert invoke(runner, ["health", "--days", days], env).exit_code == 2


def test_a_node_lorastats_does_not_know_is_never_asked_about(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
    rows: dict[str, Any],
) -> None:
    _seed(seed_db)

    result, lorastats = _run(runner, env, mock_sources, [], rows, known=(_A,))

    assert result.exit_code == 0, result.output
    assert [r.url.params["fromNode"] for r in lorastats.reports] == [_A]
    assert "1 node(s) without lorastats data" in result.stdout


def test_a_critical_node_makes_the_exit_code_seven(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    _seed(seed_db)
    now = time.time()
    rows = {_A: _reports(_A, now, battery=5), _B: _reports(_B, now)}

    result, _ = _run(runner, env, mock_sources, [], rows)

    assert result.exit_code == 7
    assert "CRIT" in result.stdout
    assert "battery at 5%" in result.stdout


def test_a_rate_limited_refresh_is_reported_and_degrades_the_exit_code(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
    rows: dict[str, Any],
) -> None:
    _seed(seed_db)

    result, lorastats = _run(runner, env, mock_sources, ["--json"], rows, status=429)

    assert result.exit_code == 7
    document = json.loads(result.stdout)
    assert [f["node"] for f in document["failures"]] == [_A, _B]
    assert len(lorastats.reports) == 0
    assert document["refresh"]["refreshed"] == []


def test_mesh_health_never_writes_the_database_and_keeps_an_owner_only_history(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    db_path: Path,
    mock_sources: Callable[..., respx.MockRouter],
    rows: dict[str, Any],
) -> None:
    _seed(seed_db)
    before = db_fingerprint(db_path)

    _run(runner, env, mock_sources, [], rows)

    assert db_fingerprint(db_path) == before
    history = Path(env["MESHPROVISION_CACHE_DIR"]) / "health" / f"{_A}.json"
    assert json.loads(history.read_text())["node"] == _A
    if sys.platform != "win32":
        assert stat.S_IMODE(history.stat().st_mode) == 0o600


def test_an_archived_node_is_left_out_unless_asked_for(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
    rows: dict[str, Any],
) -> None:
    seed_db(
        nodes=[
            NodeRecord(node_id=_A, short_name="D0h5", long_name="Alpha D0h5"),
            NodeRecord(
                node_id=_B,
                short_name="Bravo",
                long_name="Bravo node",
                archived_at=datetime(2026, 1, 1, tzinfo=UTC),
            ),
        ]
    )

    default, lorastats = _run(runner, env, mock_sources, ["--json"], rows)
    asked, _ = _run(runner, env, mock_sources, ["--json", "--no-fetch", _B], rows)

    assert [node["node_id"] for node in json.loads(default.stdout)["nodes"]] == [_A]
    assert [r.url.params["fromNode"] for r in lorastats.reports] == [_A]
    assert [node["node_id"] for node in json.loads(asked.stdout)["nodes"]] == [_B]


def test_a_node_not_in_the_database_can_be_asked_for_and_counts_as_ours(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
    rows: dict[str, Any],
) -> None:
    seed_db(nodes=[NodeRecord(node_id=_A, short_name="D0h5", long_name="Alpha D0h5")])

    result, lorastats = _run(runner, env, mock_sources, ["--json", _B, _B], rows)

    assert result.exit_code == 0, result.output
    (node,) = json.loads(result.stdout)["nodes"]
    assert node["node_id"] == _B
    assert [r.url.params["fromNode"] for r in lorastats.reports] == [_B]


def _age_histories(env: Mapping[str, str], seconds: float) -> None:
    """Make every stored history look refreshed ``seconds`` ago."""
    for path in (Path(env["MESHPROVISION_CACHE_DIR"]) / "health").glob("*.json"):
        document = json.loads(path.read_text())
        document["fetched_at"] = time.time() - seconds
        path.write_text(json.dumps(document))


def test_refresh_asks_again_after_a_minute_and_a_plain_run_waits_ten(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
    rows: dict[str, Any],
) -> None:
    _seed(seed_db)
    _run(runner, env, mock_sources, [], rows)
    _age_histories(env, 120)

    _, plain = _run(runner, env, mock_sources, [], rows)
    _, forced = _run(runner, env, mock_sources, ["--refresh"], rows)

    assert plain.reports == []
    assert len(forced.reports) == len(forced.parsed) == 2
    assert all("since" in request.url.params for request in forced.reports)


def test_a_history_that_cannot_be_stored_is_still_reported(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
    rows: dict[str, Any],
) -> None:
    _seed(seed_db)
    cache = Path(env["MESHPROVISION_CACHE_DIR"])
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "health").write_text("a file where the directory should be")

    result, _ = _run(runner, env, mock_sources, ["--json"], rows)

    assert result.exit_code == 0, result.output
    receptions = [node["metrics"]["receptions"] for node in json.loads(result.stdout)["nodes"]]
    assert receptions == [36, 36]


def test_lorastats_last_boot_is_recorded_in_the_history(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    rows: dict[str, Any],
) -> None:
    _seed(seed_db)
    boot = int(time.time()) - 3 * 3600
    router = respx.MockRouter(assert_all_called=False)
    router.get(LORANET_NODES_URL).mock(
        return_value=httpx.Response(200, json={NodeId.from_hex(_A).decimal: {}})
    )
    nodes_url = LORASTATS_BASE_URL + LORASTATS_NODES_PATH.format(region="PL")
    record = {
        "NodeId": _A,
        "LastSeen": since_param(time.time() - 60),
        "LastBoot": since_param(boot),
    }
    router.get(url__startswith=nodes_url).mock(return_value=httpx.Response(200, json=[record]))
    _Lorastats(router, rows)

    with router:
        result = invoke(runner, ["health", "--json", _A], env)

    (node,) = json.loads(result.stdout)["nodes"]
    assert node["metrics"]["boots"] == [
        datetime.fromtimestamp(boot, tz=UTC).isoformat().replace("+00:00", "Z")
    ]
