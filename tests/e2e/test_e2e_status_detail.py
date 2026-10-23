"""``mesh status --detail``: brief and full tables; default and JSON unchanged."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

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


def _headers(output: str) -> str:
    """The table's two header lines (some headers have two)."""
    lines = [line for line in output.splitlines() if line.strip()]
    return f"{lines[0]} {lines[1]}"


@pytest.fixture
def seeded(seed_db: Callable[..., Path]) -> None:
    _seed(seed_db)


@pytest.mark.usefixtures("seeded")
def test_brief_keeps_only_the_essential_columns_and_asks_no_packets(
    runner: CliRunner, env: dict[str, str], mock_sources: Callable[..., respx.MockRouter]
) -> None:
    result, lorastats = _status(runner, env, mock_sources, ["--detail", "brief"])

    assert result.exit_code == 0, result.output
    assert sorted(_headers(result.stdout).split()) == sorted(
        ["Node", "Short", "Status", "Last", "seen", "Batt", "Seen", "By", "1d/7d/30d", "Uptime"]
    )
    assert "Mgmt" not in result.stdout
    assert lorastats.reports == lorastats.parsed == []


@pytest.mark.usefixtures("seeded")
def test_the_default_table_hides_node_and_mgmt_and_asks_no_packets(
    runner: CliRunner, env: dict[str, str], mock_sources: Callable[..., respx.MockRouter]
) -> None:
    plain, lorastats = _status(runner, env, mock_sources, [])
    explicit, _ = _status(runner, env, mock_sources, ["--detail", "default"])

    assert _headers(plain.stdout) == _headers(explicit.stdout)
    assert "Mgmt" not in _headers(plain.stdout)
    assert "Node" not in _headers(plain.stdout).split()
    assert "Short" in _headers(plain.stdout)
    assert "Health" not in plain.stdout
    assert lorastats.reports == lorastats.parsed == []


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
        assert _stable({k: v for k, v in full_node.items() if k != "health"}) == _stable(plain_node)
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
