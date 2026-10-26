"""``mesh status --detail``: brief and full tables; default and JSON unchanged."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from meshprovision.db.nodes import NodeRecord
from tests.e2e.conftest import invoke
from tests.e2e.test_e2e_health import _A, _B, _age_histories, _Lorastats, _nodes, _reports, _seed

if TYPE_CHECKING:
    import respx
    from click.testing import CliRunner

pytestmark = pytest.mark.e2e

_VOLATILE = frozenset({"generated_at", "age_seconds", "age_text", "data_as_of", "cache"})


def _status(
    runner: CliRunner,
    env: dict[str, str],
    mock_sources: Callable[..., respx.MockRouter],
    args: Sequence[str],
    *,
    source_args: Sequence[str] = (),
) -> tuple[Any, _Lorastats]:
    now = time.time()
    router = mock_sources(nodes=_nodes(now))
    lorastats = _Lorastats(router, {_A: _reports(_A, now), _B: _reports(_B, now)})
    with router:
        result = invoke(runner, ["status", *source_args, *args], env)
    return result, lorastats


def _stable(value: object) -> object:
    """Drop the keys that change from one run to the next."""
    if isinstance(value, dict):
        return {k: _stable(v) for k, v in value.items() if k not in _VOLATILE}
    if isinstance(value, list):
        return [_stable(item) for item in value]
    return value


_CADENCE_KEYS = frozenset(
    {
        "health",
        "availability",
        "expected_interval_seconds",
        "expected_interval_source",
        "stale_after_seconds",
        "offline_after_seconds",
    }
)


def _uncadenced(node: dict[str, Any]) -> dict[str, Any]:
    """A JSON node without its health and the keys its expected interval decides."""
    return {k: v for k, v in node.items() if k not in _CADENCE_KEYS}


def _headers(output: str) -> str:
    """The table's two header lines (some headers have two)."""
    lines = [line for line in output.splitlines() if line.strip()]
    return f"{lines[0]} {lines[1]}"


@pytest.fixture
def seeded(seed_db: Callable[..., Path]) -> None:
    _seed(seed_db)


@pytest.mark.usefixtures("seeded")
def test_brief_keeps_only_the_essential_columns(
    runner: CliRunner, env: dict[str, str], mock_sources: Callable[..., respx.MockRouter]
) -> None:
    result, lorastats = _status(runner, env, mock_sources, ["--detail", "brief"])

    assert result.exit_code == 0, result.output
    assert sorted(_headers(result.stdout).split()) == sorted(
        ["Node", "Short", "Status", "Last", "seen", "Batt", "Seen", "By", "1d/7d/30d", "Uptime"]
    )
    assert "Mgmt" not in result.stdout
    assert len(lorastats.reports) == len(lorastats.parsed) == 2


@pytest.mark.usefixtures("seeded")
def test_the_default_table_hides_node_and_mgmt(
    runner: CliRunner,
    env: dict[str, str],
    mock_sources: Callable[..., respx.MockRouter],
    tmp_path: Path,
) -> None:
    plain, lorastats = _status(runner, env, mock_sources, [])
    # A fresh cache: the first run's refreshed histories would change the cells.
    fresh = {**env, "MESHPROVISION_CACHE_DIR": str(tmp_path / "fresh-cache")}
    explicit, _ = _status(runner, fresh, mock_sources, ["--detail", "default"])

    assert _headers(plain.stdout).split() == _headers(explicit.stdout).split()
    assert "Mgmt" not in _headers(plain.stdout)
    assert "Node" not in _headers(plain.stdout).split()
    assert "Short" in _headers(plain.stdout)
    assert "Health" not in plain.stdout
    assert len(lorastats.reports) == len(lorastats.parsed) == 2


@pytest.mark.usefixtures("seeded")
@pytest.mark.parametrize("detail", ["brief", "default"])
def test_json_is_the_same_whatever_brief_or_default(
    runner: CliRunner,
    env: dict[str, str],
    mock_sources: Callable[..., respx.MockRouter],
    detail: str,
) -> None:
    plain, _ = _status(runner, env, mock_sources, ["--json"])
    detailed, lorastats = _status(runner, env, mock_sources, ["--json", "--detail", detail])

    assert _stable(json.loads(detailed.stdout)) == _stable(json.loads(plain.stdout))
    assert list(json.loads(detailed.stdout)) == list(json.loads(plain.stdout))
    assert lorastats.reports == []


@pytest.mark.usefixtures("seeded")
def test_full_adds_health_columns_with_two_requests_per_node_once(
    runner: CliRunner, env: dict[str, str], mock_sources: Callable[..., respx.MockRouter]
) -> None:
    first, lorastats = _status(runner, env, mock_sources, ["--detail", "full"])
    again, repeated = _status(runner, env, mock_sources, ["--detail", "full"])

    assert first.exit_code == 0, first.output
    headers = _headers(first.stdout)
    assert "Mgmt" in headers
    assert "Health" in headers
    assert "Pkt/h" in headers
    assert "health over 7 d; history refreshed for 2 node(s), 4 request(s)" in first.stdout
    assert len(lorastats.reports) == len(lorastats.parsed) == 2
    assert lorastats.uplinked == []
    assert repeated.reports == repeated.parsed == []
    assert "history refreshed for 0 node(s), 0 request(s)" in again.stdout
    assert "OK" in again.stdout


@pytest.mark.usefixtures("seeded")
def test_full_json_adds_health_keys_and_keeps_every_other_one(
    runner: CliRunner, env: dict[str, str], mock_sources: Callable[..., respx.MockRouter]
) -> None:
    plain, _ = _status(runner, env, mock_sources, ["--json"])
    full, _ = _status(runner, env, mock_sources, ["--json", "--detail", "full"])

    plain_doc = json.loads(plain.stdout)
    full_doc = json.loads(full.stdout)
    assert list(full_doc) == [*plain_doc, "health"]
    assert full_doc["health"]["days"] == 7
    assert full_doc["health"]["refresh"]["refreshed"] == [_A, _B]
    assert full_doc["health"]["failures"] == []
    for plain_node, full_node in zip(plain_doc["nodes"], full_doc["nodes"], strict=True):
        assert list(full_node) == [*plain_node, "health"]
        assert _stable(_uncadenced(full_node)) == _stable(_uncadenced(plain_node))
        # the history full refreshed sets the interval (plain JSON refreshes nothing)
        assert full_node["expected_interval_source"] == "history"
        assert plain_node["expected_interval_source"] == "role"
        assert full_node["health"]["verdict"] == "ok"
        assert full_node["health"]["metrics"]["receptions"] == 36


@pytest.mark.usefixtures("seeded")
def test_full_watch_refreshes_each_node_once_across_polls(
    runner: CliRunner,
    env: dict[str, str],
    mock_sources: Callable[..., respx.MockRouter],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"n": 0}

    def fake_sleep(_seconds: float) -> None:
        calls["n"] += 1
        if calls["n"] >= 3:
            raise KeyboardInterrupt

    monkeypatch.setattr(time, "sleep", fake_sleep)

    result, lorastats = _status(
        runner, env, mock_sources, ["--watch", "--interval", "1", "--detail", "full", "--json"]
    )

    assert result.stdout.count('"generated_at"') == 3
    assert len(lorastats.reports) == len(lorastats.parsed) == 2


@pytest.mark.usefixtures("seeded")
def test_full_without_lorastats_asks_no_packets(
    runner: CliRunner, env: dict[str, str], mock_sources: Callable[..., respx.MockRouter]
) -> None:
    result, lorastats = _status(
        runner, env, mock_sources, ["--detail", "full"], source_args=["--source", "loranet"]
    )

    assert result.exit_code == 0, result.output
    assert lorastats.reports == []
    assert "2 node(s) without lorastats data" in result.stdout


def test_an_unknown_detail_level_is_a_usage_error(runner: CliRunner, env: dict[str, str]) -> None:
    assert invoke(runner, ["status", "--detail", "everything"], env).exit_code == 2


@pytest.mark.usefixtures("seeded")
def test_full_waits_ten_minutes_between_refreshes_of_a_node(
    runner: CliRunner, env: dict[str, str], mock_sources: Callable[..., respx.MockRouter]
) -> None:
    _status(runner, env, mock_sources, ["--detail", "full"])
    _age_histories(env, 120)

    _, lorastats = _status(runner, env, mock_sources, ["--detail", "full"])

    assert lorastats.reports == []


@pytest.mark.usefixtures("seeded")
@pytest.mark.parametrize("detail", ["default", "brief"])
def test_the_table_refreshes_a_stale_history_once_an_hour(
    runner: CliRunner,
    env: dict[str, str],
    mock_sources: Callable[..., respx.MockRouter],
    detail: str,
) -> None:
    first, lorastats = _status(runner, env, mock_sources, ["--detail", detail])
    _age_histories(env, 3500)
    soon, soon_requests = _status(runner, env, mock_sources, ["--detail", detail])
    _age_histories(env, 3700)
    later, later_requests = _status(runner, env, mock_sources, ["--detail", detail])

    assert first.exit_code == soon.exit_code == later.exit_code == 0
    assert len(lorastats.reports) == len(lorastats.parsed) == 2
    assert soon_requests.reports == soon_requests.parsed == []
    assert len(later_requests.reports) == len(later_requests.parsed) == 2


@pytest.mark.usefixtures("seeded")
def test_no_history_refresh_json_and_loranet_only_ask_no_packets(
    runner: CliRunner, env: dict[str, str], mock_sources: Callable[..., respx.MockRouter]
) -> None:
    opted_out, a = _status(runner, env, mock_sources, ["--no-history-refresh"])
    as_json, b = _status(runner, env, mock_sources, ["--json"])
    loranet, c = _status(runner, env, mock_sources, [], source_args=["--source", "loranet"])

    assert opted_out.exit_code == as_json.exit_code == loranet.exit_code == 0
    assert a.reports == a.parsed == b.reports == b.parsed == c.reports == c.parsed == []


@pytest.mark.usefixtures("seeded")
def test_a_failing_history_refresh_does_not_fail_the_table(
    runner: CliRunner, env: dict[str, str], mock_sources: Callable[..., respx.MockRouter]
) -> None:
    router = mock_sources(nodes=_nodes(time.time()))
    _Lorastats(router, {}, status=500)
    with router:
        result = invoke(runner, ["status"], env)

    assert result.exit_code == 0, result.output
    assert "D0h5" in result.stdout


_R = "0000abcd"
"""A REPEATER (role default 48 h: stale after 108 h, offline after 252 h)."""


def _repeater_status(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
    args: Sequence[str],
) -> tuple[Any, _Lorastats]:
    """Last seen 30 h ago; lorastats holds its hourly packets from 30-36 h ago (E = 1 h)."""
    seed_db(nodes=[NodeRecord(node_id=_R, short_name="Rpt", long_name="Repeater", role="REPEATER")])
    now = time.time()
    router = mock_sources(nodes={_R: {"shortName": "Rpt", "seenBy": {"gw1": int(now) - 30 * 3600}}})
    lorastats = _Lorastats(router, {_R: _reports(_R, now - 30 * 3600)})
    with router:
        result = invoke(runner, ["status", *args], env)
    return result, lorastats


def _every_and_status(output: str, short: str) -> list[str]:
    (row,) = [line.split() for line in output.splitlines() if f" {short} " in f" {line} "]
    return row


@pytest.mark.usefixtures("seeded")
def test_the_table_judges_by_the_interval_its_own_refresh_learned(
    runner: CliRunner, env: dict[str, str], mock_sources: Callable[..., respx.MockRouter]
) -> None:
    """The refresh learned E = 1 h but Every stayed at the role default until the next run."""
    result, lorastats = _status(runner, env, mock_sources, [])

    assert result.exit_code == 0, result.output
    assert len(lorastats.reports) == 2
    assert "1h" in _every_and_status(result.stdout, "D0h5")
    assert "3h" not in _every_and_status(result.stdout, "D0h5")


def test_a_refreshed_history_sets_the_status_and_exit_code_of_the_same_run(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    result, lorastats = _repeater_status(runner, env, seed_db, mock_sources, [])

    assert len(lorastats.reports) == 1
    assert "offline" in _every_and_status(result.stdout, "Rpt")
    assert result.exit_code == 7, result.output


def test_without_a_refresh_the_role_default_still_decides(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    result, lorastats = _repeater_status(
        runner, env, seed_db, mock_sources, ["--no-history-refresh"]
    )

    assert lorastats.reports == []
    assert "online" in _every_and_status(result.stdout, "Rpt")
    assert result.exit_code == 0, result.output


def test_an_expected_interval_override_is_not_rejudged_by_the_refresh(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    result, lorastats = _repeater_status(
        runner, env, seed_db, mock_sources, ["--expected-interval", "48"]
    )

    assert len(lorastats.reports) == 1
    assert "online" in _every_and_status(result.stdout, "Rpt")
    assert result.exit_code == 0, result.output


def test_full_status_and_health_agree_on_the_refreshed_interval(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    result, _ = _repeater_status(runner, env, seed_db, mock_sources, ["--detail", "full"])

    row = _every_and_status(result.stdout, "Rpt")
    assert "offline" in row
    assert "CRIT" in row
    assert result.exit_code == 7, result.output


def test_full_json_carries_the_refreshed_interval(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    result, _ = _repeater_status(runner, env, seed_db, mock_sources, ["--json", "--detail", "full"])

    (node,) = json.loads(result.stdout)["nodes"]
    assert node["expected_interval_source"] == "history"
    assert node["expected_interval_seconds"] == 3600
    assert node["availability"] == "offline"
    assert node["offline_after_seconds"] == 24 * 3600
    assert result.exit_code == 7, result.output


def test_plain_json_still_refreshes_nothing_and_keeps_the_role_default(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    result, lorastats = _repeater_status(runner, env, seed_db, mock_sources, ["--json"])

    (node,) = json.loads(result.stdout)["nodes"]
    assert lorastats.reports == []
    assert node["expected_interval_source"] == "role"
    assert result.exit_code == 0, result.output


def test_watch_exits_with_the_code_of_the_last_rejudged_poll(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def stop(_seconds: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(time, "sleep", stop)

    result, _ = _repeater_status(runner, env, seed_db, mock_sources, ["--watch", "--interval", "1"])

    assert "offline" in _every_and_status(result.stdout, "Rpt")
    assert result.exit_code == 7, result.output


def test_the_rejudged_thresholds_keep_the_configured_floors(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    result, _ = _repeater_status(runner, env, seed_db, mock_sources, ["--offline-after", "40"])

    assert "stale" in _every_and_status(result.stdout, "Rpt")
    assert result.exit_code == 0, result.output
