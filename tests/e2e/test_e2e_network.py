"""``mesh network`` against respx-mocked lorastats.pl, on the synthetic mini region."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
import pytest
import respx

from meshprovision.datasources.lorastats import LORASTATS_BASE_URL, LORASTATS_NODES_PATH
from meshprovision.datasources.lorastats_region import LORASTATS_PACKETS_RAW_PATH
from meshprovision.datasources.region_memo import REGION_MEMO_FILENAME
from meshprovision.db.keys import KeyRecord
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import KeyType, ref_for
from meshprovision.network.store import NETWORK_DIRNAME, region_dirname
from tests.e2e.conftest import db_fingerprint, invoke
from tests.unit import network_fixtures as mini

if TYPE_CHECKING:
    from click.testing import CliRunner

pytestmark = pytest.mark.e2e


def _seed(seed_db: Callable[..., Path], keys: dict[str, bytes] | None = None) -> Path:
    owned = {mini.OURS_ONE: mini.KEY_OURS_ONE} if keys is None else keys
    return seed_db(
        nodes=[
            NodeRecord(node_id=mini.OURS_ONE, short_name="Our1", long_name="Our one"),
            NodeRecord(node_id=mini.OURS_TWO, short_name="Our2", long_name="Our two"),
            NodeRecord(node_id=mini.OURS_RELAY, short_name="Our3", long_name="Our three"),
        ],
        keys=[
            KeyRecord(
                key_ref=ref_for(node, KeyType.ADMIN_PUBLIC),
                owner_node_id=node,
                key_type=KeyType.ADMIN_PUBLIC,
                key_value=base64.b64encode(key).decode("ascii"),
            )
            for node, key in owned.items()
        ],
    )


class _Lorastats:
    """respx routes for a region's PacketsRaw and Nodes, recording each request."""

    def __init__(self, *, status: int = 200, rows: Sequence[dict[str, object]] = ()) -> None:
        now = time.time()
        self.rows = list(rows) or mini.mini_region(now)
        self.nodes = mini.mini_region_nodes(now)
        self.status = status
        self.raw: list[httpx.Request] = []
        self.listed: list[httpx.Request] = []
        self.router = respx.MockRouter(assert_all_called=False)
        base = LORASTATS_BASE_URL
        self.router.get(url__startswith=base + LORASTATS_PACKETS_RAW_PATH.format(region="PL")).mock(
            side_effect=self._raw
        )
        self.router.get(url__startswith=base + LORASTATS_NODES_PATH.format(region="PL")).mock(
            side_effect=self._nodes
        )

    def _raw(self, request: httpx.Request) -> httpx.Response:
        self.raw.append(request)
        if self.status != 200:
            return httpx.Response(self.status)
        return httpx.Response(200, json=self.rows)

    def _nodes(self, request: httpx.Request) -> httpx.Response:
        self.listed.append(request)
        return httpx.Response(200, json=self.nodes)


def _run(
    runner: CliRunner,
    env: dict[str, str],
    args: Sequence[str],
    lorastats: _Lorastats | None = None,
) -> tuple[Any, _Lorastats]:
    source = lorastats or _Lorastats()
    with source.router:
        result = invoke(runner, ["network", *args], env)
    return result, source


def _age_the_store(env: dict[str, str], seconds: float) -> None:
    """Make the PL store look fetched ``seconds`` earlier."""
    path = Path(env["MESHPROVISION_CACHE_DIR"]) / NETWORK_DIRNAME / region_dirname("PL")
    state_file = path / "state.json"
    state = json.loads(state_file.read_text(encoding="utf-8"))
    state["fetched_at"] -= seconds
    state_file.write_text(json.dumps(state), encoding="utf-8")


def test_the_key_scan_reports_outsiders_and_exits_zero(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    db = _seed(seed_db)
    before = db_fingerprint(db)

    result, lorastats = _run(runner, env, ["keys", "--region", "PL"])

    assert result.exit_code == 0, result.output
    out = result.stdout
    assert "Key scan: PL, last 30 days (data as of " in out
    assert "10 node(s) advertised a key (of 2 in lorastats' node list)." in out
    assert "Our nodes: 1 of 3 advertised a key; no finding involves them." in out
    assert "CRITICAL  clone (outsiders)" in out
    assert "2 nodes heard at the same time: c1000001 Cl1, c2000002 Cl2" in out
    assert "CRITICAL  weak key (outsiders)" in out
    assert "5e000001 Weak: blocklist, low_entropy, small_order" in out
    assert "WARNING   hand-over (outsiders)" in out
    assert "used by 4a000001 Old, then 4a000002 New; the older id was last heard" in out
    assert "INFO      migration (outsiders)" in out
    assert f"11110001 Mig became {mini.MIGRATION_NEW} Mig" in out
    assert "Info: 1 node(s) use a key-derived id (firmware >= 2.8)." in out
    assert (len(lorastats.raw), len(lorastats.listed)) == (1, 1)
    assert dict(lorastats.raw[0].url.params) == {}
    assert db_fingerprint(db) == before


def test_no_key_and_no_raw_packet_is_ever_written_to_the_cache(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    _seed(seed_db)

    _run(runner, env, ["keys", "--region", "PL"])

    cache = Path(env["MESHPROVISION_CACHE_DIR"])
    text = "".join(p.read_text(encoding="utf-8") for p in cache.rglob("*.json"))
    for key in (mini.KEY_OURS_ONE, mini.KEY_CLONE, mini.KEY_ROUTER):
        assert base64.b64encode(key).decode() not in text
        assert key.hex() not in text
    assert "PacketsRaw" not in text
    keys_file = cache / NETWORK_DIRNAME / region_dirname("PL") / "keys.json"
    assert json.loads(keys_file.read_text(encoding="utf-8"))["region"] == "PL"


def test_a_second_run_within_the_interval_asks_nothing(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    _seed(seed_db)
    _run(runner, env, ["keys", "--region", "PL"])

    again, lorastats = _run(runner, env, ["keys", "--region", "PL", "--refresh"])

    assert again.exit_code == 0, again.output
    assert (lorastats.raw, lorastats.listed) == ([], [])
    assert "CRITICAL  clone (outsiders)" in again.stdout


def test_a_later_run_asks_only_since_the_previous_fetch(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    _seed(seed_db)
    _run(runner, env, ["keys", "--region", "PL"])
    _age_the_store(env, 1800)

    _, lorastats = _run(runner, env, ["keys", "--region", "PL"])

    assert len(lorastats.raw) == 1
    assert "since" in lorastats.raw[0].url.params


def test_our_database_key_on_another_id_exits_six(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    _seed(seed_db, {mini.OURS_ONE: mini.KEY_OURS_ONE, mini.OURS_TWO: mini.KEY_ROUTER})

    result, _ = _run(runner, env, ["keys", "--region", "PL"])

    assert result.exit_code == 6, result.output
    assert "CRITICAL  our key on another id (ours)" in result.stdout
    assert (
        f"{mini.OURS_TWO} Our2's database key is advertised by {mini.ROUTER} Rtr" in result.stdout
    )


def test_our_id_with_another_key_is_a_warning(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    _seed(seed_db, {mini.OURS_ONE: hashlib.sha256(b"an older key").digest()})

    result, _ = _run(runner, env, ["keys", "--region", "PL"])

    assert result.exit_code == 0, result.output
    assert "WARNING   our id, other key (ours)" in result.stdout
    assert "Our nodes: 1 of 3 advertised a key; 1 finding(s) involve them." in result.stdout


def test_json_names_every_finding_by_its_key_digest(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    _seed(seed_db)

    result, _ = _run(runner, env, ["keys", "--region", "PL", "--json"])

    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert sorted(document) == [
        "days",
        "exit_code",
        "fleet_nodes",
        "generated_at",
        "refresh",
        "regions",
    ]
    assert (document["days"], document["fleet_nodes"], document["exit_code"]) == (30, 3, 0)
    assert document["refresh"] == {"refreshed": ["PL"], "failures": [], "skipped_rows": 0}
    (region,) = document["regions"]
    assert sorted(region) == [
        "data_as_of",
        "derived_ids",
        "findings",
        "fleet_seen",
        "nodes_listed",
        "nodes_with_key",
        "region",
    ]
    assert (region["region"], region["nodes_with_key"], region["nodes_listed"]) == ("PL", 10, 2)
    assert region["fleet_seen"] == [mini.OURS_ONE]
    assert region["derived_ids"] == [mini.MIGRATION_NEW]
    clone = region["findings"][0]
    assert clone == {
        "kind": "clone",
        "severity": "critical",
        "key": clone["key"],
        "nodes": list(mini.CLONES),
        "fleet": False,
        "checks": [],
        "last_heard": None,
    }
    assert clone["key"].startswith("sha256:") and len(clone["key"]) == 23
    assert [f["kind"] for f in region["findings"]] == ["clone", "weak-key", "handover", "migration"]


def test_a_rate_limit_without_stored_data_exits_three(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    _seed(seed_db)

    result, lorastats = _run(runner, env, ["keys", "--region", "PL"], _Lorastats(status=429))

    assert result.exit_code == 3, result.output
    assert "no data yet" in result.stdout
    assert lorastats.listed == []


def test_a_failed_refresh_with_stored_data_exits_seven_and_shows_it(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    _seed(seed_db)
    _run(runner, env, ["keys", "--region", "PL"])
    _age_the_store(env, 3600)

    result, _ = _run(runner, env, ["keys", "--region", "PL"], _Lorastats(status=503))

    assert result.exit_code == 7, result.output
    assert "CRITICAL  clone (outsiders)" in result.stdout
    assert "PL: " in result.stdout


def test_no_fetch_asks_nothing_and_needs_no_contact(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    _seed(seed_db)
    _run(runner, env, ["keys", "--region", "PL"])
    offline = {key: value for key, value in env.items() if key != "MESHPROVISION_CONTACT"}

    result, lorastats = _run(runner, offline, ["keys", "--region", "PL", "--no-fetch"])

    assert result.exit_code == 0, result.output
    assert (lorastats.raw, lorastats.listed) == ([], [])
    assert "Nothing fetched (--no-fetch): stored data only." in result.stdout
    assert "CRITICAL  clone (outsiders)" in result.stdout


def test_no_fetch_without_stored_data_exits_three(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    _seed(seed_db)

    result, _ = _run(runner, env, ["keys", "--region", "PL", "--no-fetch"])

    assert result.exit_code == 3, result.output


@pytest.mark.parametrize(
    "args",
    [
        pytest.param(["--region", "../Nodes"], id="malformed-region"),
        pytest.param(["--region", "PL", "--refresh", "--no-fetch"], id="refresh-and-no-fetch"),
        pytest.param([], id="no-region-known"),
    ],
)
def test_bad_options_exit_two_without_a_request(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path], args: list[str]
) -> None:
    _seed(seed_db)

    result, lorastats = _run(runner, env, ["keys", *args])

    assert result.exit_code == 2, result.output
    assert (lorastats.raw, lorastats.listed) == ([], [])


def test_without_region_our_nodes_remembered_regions_are_used(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    _seed(seed_db)
    memo = Path(env["MESHPROVISION_CACHE_DIR"]) / REGION_MEMO_FILENAME
    memo.parent.mkdir(parents=True, exist_ok=True)
    entry = {"region": "PL", "stored_at": time.time()}
    memo.write_text(
        json.dumps({"version": 1, "nodes": {mini.OURS_ONE: entry, mini.OURS_TWO: entry}}),
        encoding="utf-8",
    )

    result, lorastats = _run(runner, env, ["keys"])

    assert result.exit_code == 0, result.output
    assert "Key scan: PL," in result.stdout
    assert len(lorastats.raw) == 1


def test_names_from_the_air_are_made_terminal_safe(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    _seed(seed_db)
    now = time.time()
    port, payload = mini.node_info(0xC3000003, mini.KEY_CLONE, short_name="\x1b[2J")
    hostile = mini.row(mini.packet(0xC3000003, 999, port=port, payload=payload), time=now - 2000)

    result, _ = _run(
        runner, env, ["keys", "--region", "PL"], _Lorastats(rows=[*mini.mini_region(now), hostile])
    )

    assert result.exit_code == 0, result.output
    assert "\x1b" not in result.stdout
    assert "c3000003 \\x1b[2J" in result.stdout


def _cells(out: str, first: str) -> list[str]:
    """Split the table row starting with ``first`` into its cells."""
    (line,) = [line for line in out.splitlines() if line.strip().startswith(first)]
    return [cell for cell in line.strip().split("  ") if cell.strip()]


def test_relays_shows_the_relays_we_depend_on(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    db = _seed(seed_db)
    before = db_fingerprint(db)

    result, lorastats = _run(runner, env, ["relays", "--region", "PL"])

    assert result.exit_code == 0, result.output
    out = result.stdout
    assert "Relays we depend on but don't own: PL, last 24 h (data as of " in out
    assert "20 of our packets, 10 of their receptions relayed; 153 relayed receptions" in out
    router = [cell.strip() for cell in _cells(out, mini.ROUTER)]
    assert router[:4] == [mini.ROUTER, "Rtr", "ROUTER", "high"]
    assert router[4:9] == ["70.0%", "1", f"{mini.OURS_ONE} Our1", "69.9%", "2 (max 100.0%)"]
    assert router[-1] == "id not key-derived"
    ambiguous = [cell.strip() for cell in _cells(out, "0xe4")]
    assert ambiguous[:3] == ["0xe4", "ambiguous (e10000e4, e20000e4, e30000e4)", "-"]
    assert mini.COLLIDER not in out
    assert "Shares are of receptions at gateways, by last hop." in out
    assert (len(lorastats.raw), len(lorastats.listed)) == (1, 1)
    assert db_fingerprint(db) == before


def test_relays_all_lists_every_relay_but_ours_by_region_share(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    _seed(seed_db)

    result, _ = _run(runner, env, ["relays", "--region", "PL", "--all"])

    assert result.exit_code == 0, result.output
    out = result.stdout
    assert "Relays by share of relayed traffic: PL" in out
    order = [line.split()[0] for line in out.splitlines() if line.startswith("  ") and line.split()]
    assert order[1:] == [mini.ROUTER, "0xe4", mini.COLLIDER]
    assert mini.OURS_RELAY not in out
    collider = [cell.strip() for cell in _cells(out, mini.COLLIDER)]
    assert collider[3] == "high"


def test_relays_limit_and_a_mute_node_are_respected(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    _seed(seed_db)

    result, _ = _run(runner, env, ["relays", "--region", "PL", "--all", "--limit", "1"])

    assert result.exit_code == 0, result.output
    assert "2 more (--limit)." in result.stdout
    assert mini.MUTE not in result.stdout


def test_relays_json_carries_every_row_and_field(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    _seed(seed_db)

    result, _ = _run(runner, env, ["relays", "--region", "PL", "--json", "--limit", "1"])

    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert sorted(document) == ["days", "exit_code", "generated_at", "refresh", "regions"]
    (region,) = document["regions"]
    assert (
        region["relayed_receptions"],
        region["our_packets"],
        region["our_relayed_receptions"],
    ) == (153, 20, 10)
    router, ambiguous = region["relays"]
    assert router == {
        "byte": 0x61,
        "node": mini.ROUTER,
        "confidence": "high",
        "learned_at": None,
        "candidates": [
            {
                "node": mini.ROUTER,
                "coverage": 1.0,
                "distance_db": router["candidates"][0]["distance_db"],
            }
        ],
        "relayed_receptions": 107,
        "region_share": 0.6993,
        "origins": 3,
        "our_receptions": 7,
        "our_share": 0.7,
        "our_origins": [mini.OURS_ONE],
        "our_sole_first_hop": [mini.OURS_ONE],
        "our_sole_path_packets": 7,
        "gateways_relying": 2,
        "max_gateway_share": 1.0,
        "gateways_hearing_directly": 2,
        "role": "ROUTER",
        "last_seen": router["last_seen"],
        "last_boot": None,
        "gaps": ["id not key-derived"],
    }
    assert router["candidates"][0]["distance_db"] < 4
    assert router["last_seen"].endswith("Z")
    assert (ambiguous["byte"], ambiguous["node"], ambiguous["confidence"]) == (
        0xE4,
        None,
        "ambiguous",
    )
    assert [c["node"] for c in ambiguous["candidates"]] == list(mini.AMBIGUOUS)


_MARKUP_NAMES = ("[/]", "[link=https://x]a[/link]")


def _hostile_rows(now: float, name: str) -> list[dict[str, object]]:
    """The mini region, with the router and a third clone named ``name`` (rich markup)."""
    rows = mini.mini_region(now)
    for number, key in ((0xC3000003, mini.KEY_CLONE), (int(mini.ROUTER, 16), mini.KEY_ROUTER)):
        port, payload = mini.node_info(number, key, short_name=name, role=2)
        built = mini.packet(number, 4242, port=port, payload=payload)
        rows.append(mini.row(built, gateway=mini.G1, time=now - 1000))
    return rows


@pytest.mark.parametrize("name", _MARKUP_NAMES)
@pytest.mark.parametrize("view", [["keys"], ["relays"]])
def test_a_name_that_is_rich_markup_is_printed_as_text(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    view: list[str],
    name: str,
) -> None:
    _seed(seed_db)
    source = _Lorastats(rows=_hostile_rows(time.time(), name))

    result, _ = _run(runner, env, [*view, "--region", "PL"], source)

    assert result.exit_code == 0, result.output
    assert "\x1b" not in result.stdout
    assert name in result.stdout


def test_a_learned_relay_is_stamped_with_its_datas_time_not_renewed_offline(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    _seed(seed_db)
    _run(runner, env, ["relays", "--region", "PL"])
    directory = Path(env["MESHPROVISION_CACHE_DIR"]) / NETWORK_DIRNAME / region_dirname("PL")
    fetched_at = json.loads((directory / "state.json").read_text(encoding="utf-8"))["fetched_at"]
    learned = json.loads((directory / "relays.json").read_text(encoding="utf-8"))["relays"]
    assert {byte: entry[1] for byte, entry in learned.items()} == {
        str(0x61): fetched_at,
        str(0x03): fetched_at,
        str(0xBC): fetched_at,
    }
    _age_the_store(env, 3600)
    before = (directory / "relays.json").read_bytes()

    result, _ = _run(runner, env, ["relays", "--region", "PL", "--no-fetch"])

    assert result.exit_code == 0, result.output
    assert (directory / "relays.json").read_bytes() == before
