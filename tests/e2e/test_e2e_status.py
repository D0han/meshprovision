"""``mesh status`` against respx-mocked loranet.pl and lorastats.pl.

Covers JSON and table output, the HTTP-200-with-HTML soft-404 invalid
region guard, cache TTL behaviour, ``--watch``, and the read-only mtime
guarantee.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
import pytest

from meshprovision.datasources.loranet import LORANET_NODES_URL
from meshprovision.nodeid import NodeId
from tests.e2e.conftest import db_fingerprint, invoke

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    import respx
    from click.testing import CliRunner

    from meshprovision.db.nodes import NodeRecord

pytestmark = pytest.mark.e2e

_SECRET_KEY_NAMES = frozenset({"ble_pin", "key_ref"})
_BASE64_KEY_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])")
_SIX_DIGIT_RE = re.compile(r"(?<![\da-fA-F])\d{6}(?![\da-fA-F])")
"""Matches a bare 6-digit run (a BLE PIN candidate).

Excludes a digit run adjacent to a hex letter (not just another digit),
so an 8-char ``sha256:`` fingerprint digest -- non-secret, deliberately
printed -- is never mistaken for a PIN just because 6 of its 8
hex characters happen to be ASCII digits.
"""


def _scan_document(value: object) -> None:
    """Recursively assert a decoded JSON document names/carries no secret."""
    if isinstance(value, dict):
        for key, val in value.items():
            assert key not in _SECRET_KEY_NAMES
            _scan_document(val)
    elif isinstance(value, list):
        for item in value:
            _scan_document(item)
    elif isinstance(value, str):
        assert not _BASE64_KEY_RE.search(value)
        assert not _SIX_DIGIT_RE.search(value)


def _seed_one_node(seed_db: Callable[..., Path], node_record_cls: type[NodeRecord]) -> str:
    """Seed the database with one node and return its hex id."""
    record = node_record_cls(
        node_id="deadbe01",
        short_name="MTa1",
        long_name="Meshtastic MTa1",
        hw_model="RAK4631",
        role="CLIENT",
        region="EU_868",
    )
    seed_db(nodes=[record])
    return "deadbe01"


def test_json_run_reports_an_online_node(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    from meshprovision.db.nodes import NodeRecord

    node_hex = _seed_one_node(seed_db, NodeRecord)
    recent = int(time.time()) - 60

    with mock_sources(nodes={node_hex: {"shortName": "MTa1", "seenBy": {"gw1": recent}}}):
        result = invoke(runner, ["status", "--json"], env)

    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert set(document) >= {
        "generated_at",
        "thresholds",
        "counts",
        "cache",
        "data_as_of",
        "failures",
        "nodes",
    }
    (node_doc,) = document["nodes"]
    assert node_doc["availability"] == "online"
    assert set(node_doc["sources"]) == {"loranet", "lorastats"}

    # data_as_of stays UTC/Z-suffixed like every other JSON timestamp --
    # only the rich table localizes (see the table-run test below).
    assert set(document["data_as_of"]) == {"loranet", "lorastats"}
    assert document["data_as_of"]["loranet"].endswith("Z")
    assert document["data_as_of"]["lorastats"].endswith("Z")

    _scan_document(document)


def test_table_run_shows_short_name_and_online_label(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    from meshprovision.db.nodes import NodeRecord

    node_hex = _seed_one_node(seed_db, NodeRecord)
    recent = int(time.time()) - 60

    with mock_sources(nodes={node_hex: {"shortName": "MTa1", "seenBy": {"gw1": recent}}}):
        result = invoke(runner, ["status"], env)

    assert result.exit_code == 0
    assert "MTa1" in result.stdout
    assert "online" in result.stdout
    # The summary caption states how stale the data is, per source, in
    # local time (unlike --json's data_as_of, which stays UTC/Z).
    assert "data as of" in result.stdout
    assert result.stderr == ""


def test_default_run_is_silent_on_stderr_with_the_builtin_log_level(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    """Regression test: a plain ``mesh status`` must not print "fetching ..." lines.

    Unlike the sibling table-run test above, this one removes
    ``MESHPROVISION_LOG_LEVEL`` from ``env`` (``tests/conftest.py``
    pins it to ``WARNING`` for the whole suite) so the built-in
    default -- not the test harness's override -- is what is actually
    exercised.
    """
    from meshprovision.db.nodes import NodeRecord

    del env["MESHPROVISION_LOG_LEVEL"]
    node_hex = _seed_one_node(seed_db, NodeRecord)
    recent = int(time.time()) - 60

    with mock_sources(nodes={node_hex: {"shortName": "MTa1", "seenBy": {"gw1": recent}}}):
        result = invoke(runner, ["status"], env)

    assert result.exit_code == 0
    assert result.stderr == ""


def test_verbose_flag_restores_the_fetch_trace(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    """``-v`` is the documented way back to the per-request fetch trace."""
    from meshprovision.db.nodes import NodeRecord

    del env["MESHPROVISION_LOG_LEVEL"]
    node_hex = _seed_one_node(seed_db, NodeRecord)
    recent = int(time.time()) - 60

    with mock_sources(nodes={node_hex: {"shortName": "MTa1", "seenBy": {"gw1": recent}}}):
        result = invoke(runner, ["-v", "status"], env)

    assert result.exit_code == 0
    assert "fetching GET" in result.stderr


def test_table_run_never_interprets_a_node_name_as_rich_markup(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    from meshprovision.db.nodes import NodeRecord

    node_hex = _seed_one_node(seed_db, NodeRecord)
    recent = int(time.time()) - 60
    hostile_name = "[bold red]INJECTED[/bold red][link=file:///etc/passwd]click[/link]"
    # Force a wide console so the cell isn't word-wrapped across lines --
    # Rich reads COLUMNS when it can't detect a real terminal (as under
    # CliRunner), and a wrap would otherwise interleave other columns'
    # text between the two halves of this cell in the captured output.
    wide_env = {**env, "COLUMNS": "300"}

    with mock_sources(nodes={node_hex: {"shortName": hostile_name, "seenBy": {"gw1": recent}}}):
        result = invoke(runner, ["status"], wide_env)

    assert result.exit_code == 0
    # Rendered literally -- the console must not parse a device-reported
    # name (sourced from third-party mesh aggregators, not this operator)
    # as Rich markup, which could otherwise produce a spoofed terminal
    # hyperlink or swallow the tag as invisible styling.
    assert hostile_name in result.stdout


def test_offline_node_exit_code_and_no_fail_on_offline(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    from meshprovision.db.nodes import NodeRecord

    node_hex = _seed_one_node(seed_db, NodeRecord)
    stale = int(time.time()) - 48 * 3600

    with mock_sources(nodes={node_hex: {"shortName": "MTa1", "seenBy": {"gw1": stale}}}):
        degraded = invoke(runner, ["status", "--json"], env)
        assert degraded.exit_code == 7

        ok = invoke(runner, ["status", "--json", "--no-fail-on-offline"], env)
        assert ok.exit_code == 0


def test_unobserved_node_still_shows_its_database_name(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    """A node no source has ever seen must still be identifiable by name.

    Regression test: the Short/Long columns (and JSON `short_name`/
    `long_name`) used to fall back to nothing but the observations, so a
    node absent from both loranet.pl and lorastats.pl rendered `-` even
    though its name was sitting right there in the `Nodes` sheet.
    """
    from meshprovision.db.nodes import NodeRecord

    _seed_one_node(seed_db, NodeRecord)

    with mock_sources():  # neither source reports this (or any) node
        json_result = invoke(runner, ["status", "--json", "--no-fail-on-offline"], env)
        table_result = invoke(runner, ["status", "--no-fail-on-offline"], env)

    assert json_result.exit_code == 0
    (node_doc,) = json.loads(json_result.stdout)["nodes"]
    assert node_doc["short_name"] == "MTa1"
    assert node_doc["long_name"] == "Meshtastic MTa1"
    assert node_doc["sources"] == []
    assert node_doc["database"]["short_name"] == "MTa1"

    assert table_result.exit_code == 0
    assert "MTa1" in table_result.stdout


def test_invalid_region_returns_html_with_http_200(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    from meshprovision.db.nodes import NodeRecord

    node_hex = _seed_one_node(seed_db, NodeRecord)
    recent = int(time.time()) - 60

    with mock_sources(
        nodes={node_hex: {"shortName": "MTa1", "seenBy": {"gw1": recent}}},
        lorastats_body="<html>API docs</html>",
        region="NOTAREGION",
    ):
        result = invoke(
            runner,
            ["--no-cache", "status", "--json", "--region", "NOTAREGION"],
            env,
        )

    assert result.exit_code == 7
    document = json.loads(result.stdout)
    assert document["failures"]
    failure = document["failures"][0]
    assert failure["source"] == "lorastats"
    assert "did not return JSON" in failure["message"]
    assert "text/html" in failure["message"]
    (node_doc,) = document["nodes"]
    assert "loranet" in node_doc["sources"]


def test_a_redirect_loop_on_one_source_degrades_rather_than_crashes(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    """`httpx.TooManyRedirects` must reach the CLI as a degraded source, not a traceback.

    Regression test for the `cache/http.py` gap where `TooManyRedirects`
    and `DecodingError` (both `httpx.RequestError`, neither a
    `TransportError`) escaped `CachedHTTPClient` unwrapped, past
    `collect_observations`'s ``DataSourceError`` catch and past
    `handle_cli_errors`, crashing `mesh status` instead of degrading just
    the one affected source.
    """
    from meshprovision.db.nodes import NodeRecord

    node_hex = _seed_one_node(seed_db, NodeRecord)
    recent = int(time.time()) - 60

    router = mock_sources(nodes={node_hex: {"shortName": "MTa1", "seenBy": {"gw1": recent}}})
    router.get(LORANET_NODES_URL).mock(
        return_value=httpx.Response(302, headers={"Location": LORANET_NODES_URL})
    )

    with router:
        result = invoke(runner, ["--no-cache", "status", "--json"], env)

    assert result.exit_code == 7
    document = json.loads(result.stdout)
    assert document["failures"]
    failure = document["failures"][0]
    assert failure["source"] == "loranet"
    (node_doc,) = document["nodes"]
    assert "lorastats" in node_doc["sources"]
    assert "loranet" not in node_doc["sources"]


def test_cache_behaviour_hits_then_force_refresh(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    from meshprovision.db.nodes import NodeRecord

    node_hex = _seed_one_node(seed_db, NodeRecord)
    recent = int(time.time()) - 60

    with mock_sources(nodes={node_hex: {"shortName": "MTa1", "seenBy": {"gw1": recent}}}) as router:
        loranet_route = next(r for r in router.routes if "loranet.pl" in str(r.pattern))

        first = invoke(runner, ["status", "--json"], env)
        assert first.exit_code == 0
        assert loranet_route.call_count == 1

        second = invoke(runner, ["status", "--json"], env)
        assert second.exit_code == 0
        assert loranet_route.call_count == 1
        second_doc = json.loads(second.stdout)
        assert second_doc["cache"]["hits"] > 0
        assert second_doc["cache"]["network_requests"] == 0

        third = invoke(runner, ["--force-refresh", "status", "--json"], env)
        assert third.exit_code == 0
        assert loranet_route.call_count == 2


def test_watch_two_cache_respecting_polls(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from meshprovision.db.nodes import NodeRecord

    node_hex = _seed_one_node(seed_db, NodeRecord)
    recent = int(time.time()) - 60

    calls = {"n": 0}

    def fake_sleep(_seconds: float) -> None:
        calls["n"] += 1
        if calls["n"] >= 2:
            raise KeyboardInterrupt

    monkeypatch.setattr(time, "sleep", fake_sleep)

    with mock_sources(nodes={node_hex: {"shortName": "MTa1", "seenBy": {"gw1": recent}}}) as router:
        loranet_route = next(r for r in router.routes if "loranet.pl" in str(r.pattern))
        result = invoke(runner, ["status", "--watch", "--interval", "1", "--json"], env)
        assert loranet_route.call_count == 1

    assert result.stdout.count('"generated_at"') == 2
    assert "cache: 2 hit(s)" in result.stderr
    assert result.stderr.rstrip().endswith("Stopped.")


def test_read_only_guarantee_across_run_modes(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from meshprovision.db import backups
    from meshprovision.db.known_good import known_good_info
    from meshprovision.db.nodes import NodeRecord

    node_hex = _seed_one_node(seed_db, NodeRecord)
    recent = int(time.time()) - 60
    db_path = Path(env["MESHPROVISION_DB_PATH"])

    with mock_sources(nodes={node_hex: {"shortName": "MTa1", "seenBy": {"gw1": recent}}}):
        before = db_fingerprint(db_path)
        invoke(runner, ["status"], env)
        assert db_fingerprint(db_path) == before

        # The one intended exception: a successful load refreshes the
        # known-good safety copy (a side-channel file, never a write to
        # the live database itself -- see load_database()'s docstring).
        known_good = known_good_info(db_path)
        assert known_good is not None
        first_known_good_mtime = known_good.path.stat().st_mtime

        invoke(runner, ["status", "--json"], env)
        assert db_fingerprint(db_path) == before
        # Unchanged database -> the refresh is a no-op stat() call, not a
        # rewrite (see refresh_known_good()'s mtime-skip).
        assert known_good.path.stat().st_mtime == first_known_good_mtime

        calls = {"n": 0}

        def fake_sleep(_seconds: float) -> None:
            calls["n"] += 1
            if calls["n"] >= 2:
                raise KeyboardInterrupt

        monkeypatch.setattr(time, "sleep", fake_sleep)
        invoke(runner, ["status", "--watch", "--interval", "1"], env)
        assert db_fingerprint(db_path) == before

    backups_dir = backups.backup_dir_for(db_path)
    assert not any(backups_dir.glob(f"{db_path.stem}-*{db_path.suffix}"))
    # The known-good copy plus its provenance sidecar -- nothing else.
    sidecar = backups_dir / f"{db_path.stem}.known-good.json"
    assert {p.resolve() for p in backups_dir.iterdir()} == {
        known_good.path.resolve(),
        sidecar.resolve(),
    }


def test_missing_contact_exits_two(runner: CliRunner, env: dict[str, str]) -> None:
    env = dict(env)
    del env["MESHPROVISION_CONTACT"]

    result = invoke(runner, ["status", "--json"], env)

    assert result.exit_code == 2
    assert "MESHPROVISION_CONTACT" in result.stderr
    assert "lorastats.pl" in result.stderr


def test_source_filter_makes_zero_lorastats_requests(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    from meshprovision.db.nodes import NodeRecord

    node_hex = _seed_one_node(seed_db, NodeRecord)
    recent = int(time.time()) - 60

    with mock_sources(nodes={node_hex: {"shortName": "MTa1", "seenBy": {"gw1": recent}}}) as router:
        lorastats_route = next(r for r in router.routes if "lorastats.pl" in str(r.pattern))
        result = invoke(runner, ["status", "--json", "--source", "loranet"], env)
        assert result.exit_code == 0
        assert lorastats_route.call_count == 0


def test_loranet_only_does_not_require_contact(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    from meshprovision.db.nodes import NodeRecord

    env = dict(env)
    del env["MESHPROVISION_CONTACT"]

    node_hex = _seed_one_node(seed_db, NodeRecord)
    recent = int(time.time()) - 60

    with mock_sources(nodes={node_hex: {"shortName": "MTa1", "seenBy": {"gw1": recent}}}) as router:
        lorastats_route = next(r for r in router.routes if "lorastats.pl" in str(r.pattern))
        result = invoke(runner, ["status", "--json", "--source", "loranet"], env)
        assert result.exit_code == 0
        assert lorastats_route.call_count == 0


def test_lorastats_source_still_requires_contact(runner: CliRunner, env: dict[str, str]) -> None:
    env = dict(env)
    del env["MESHPROVISION_CONTACT"]

    result = invoke(runner, ["status", "--json", "--source", "lorastats"], env)

    assert result.exit_code == 2
    assert "MESHPROVISION_CONTACT" in result.stderr


def test_node_filter_restricts_the_report(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    from meshprovision.db.nodes import NodeRecord

    record_a = NodeRecord(node_id="deadbe01", short_name="AAAA", region="EU_868")
    record_b = NodeRecord(node_id="deadbe02", short_name="BBBB", region="EU_868")
    seed_db(nodes=[record_a, record_b])
    recent = int(time.time()) - 60

    with mock_sources(
        nodes={
            "deadbe01": {"shortName": "AAAA", "seenBy": {"gw1": recent}},
            "deadbe02": {"shortName": "BBBB", "seenBy": {"gw1": recent}},
        }
    ):
        result = invoke(runner, ["status", "--json", "--node", "!deadbe01"], env)

    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert len(document["nodes"]) == 1
    assert document["nodes"][0]["node_id"] == "deadbe01"


def test_duplicate_node_spellings_are_reported_once(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    """Regression test for Round 35's status-reporting review, Finding 4.

    NodeId accepts several spellings of the same id, so
    `--node deadbe01 --node '!deadbe01'` used to report the one real
    node twice and double-count it in the availability breakdown.
    """
    from meshprovision.db.nodes import NodeRecord

    seed_db(nodes=[NodeRecord(node_id="deadbe01", short_name="AAAA", region="EU_868")])
    recent = int(time.time()) - 60

    with mock_sources(nodes={"deadbe01": {"shortName": "AAAA", "seenBy": {"gw1": recent}}}):
        result = invoke(
            runner, ["status", "--json", "--node", "deadbe01", "--node", "!deadbe01"], env
        )

    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert [n["node_id"] for n in document["nodes"]] == ["deadbe01"]


@pytest.mark.parametrize(
    "node_args",
    [
        pytest.param(["--node", "zzz"], id="alone"),
        pytest.param(["--node", "!deadbe01", "--node", "zzz"], id="after-a-valid-one"),
    ],
)
def test_status_rejects_an_unparseable_node_id_as_a_usage_error(
    runner: CliRunner, env: dict[str, str], node_args: list[str]
) -> None:
    result = invoke(runner, ["status", "--json", *node_args], env)

    assert result.exit_code == 2
    assert "Invalid value for '--node': Cannot parse node id: 'zzz'" in result.stderr
    assert result.stdout == ""


def test_archived_node_is_excluded_by_default_but_shown_if_explicitly_requested(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    """A node archived via `mesh db forget` must not clutter the default report.

    It was deliberately decommissioned; showing it as perpetually
    "offline" on every run would be noise, not signal. An explicit
    `--node` request for it specifically still wins, though -- the
    operator asked for it by name.
    """
    from datetime import UTC, datetime

    from meshprovision.db.nodes import NodeRecord

    active = NodeRecord(node_id="deadbe01", short_name="AAAA", region="EU_868")
    archived = NodeRecord(
        node_id="deadbe02",
        short_name="BBBB",
        region="EU_868",
        archived_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    seed_db(nodes=[active, archived])
    recent = int(time.time()) - 60

    with mock_sources(
        nodes={
            "deadbe01": {"shortName": "AAAA", "seenBy": {"gw1": recent}},
            "deadbe02": {"shortName": "BBBB", "seenBy": {"gw1": recent}},
        }
    ):
        default_result = invoke(runner, ["status", "--json"], env)
        explicit_result = invoke(runner, ["status", "--json", "--node", "!deadbe02"], env)

    assert default_result.exit_code == 0
    default_document = json.loads(default_result.stdout)
    assert [n["node_id"] for n in default_document["nodes"]] == ["deadbe01"]

    assert explicit_result.exit_code == 0
    explicit_document = json.loads(explicit_result.stdout)
    assert [n["node_id"] for n in explicit_document["nodes"]] == ["deadbe02"]


def test_all_archived_database_table_names_the_archived_count(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    """Regression test for Round 35's status-reporting review, Finding 3.

    A database holding only archived nodes is not empty, but
    run_status's default report excludes them -- the table's empty-state
    message must say so ("No active nodes (N archived)"), not the false
    "No nodes in the database".
    """
    from datetime import UTC, datetime

    from meshprovision.db.nodes import NodeRecord

    archived = NodeRecord(
        node_id="deadbe01",
        short_name="AAAA",
        region="EU_868",
        archived_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    seed_db(nodes=[archived])

    with mock_sources(nodes={}):
        result = invoke(runner, ["status"], env)

    assert result.exit_code == 0
    assert "No active nodes (1 archived)" in result.stdout


def test_threshold_ordering_is_validated(runner: CliRunner, env: dict[str, str]) -> None:
    result = invoke(runner, ["status", "--stale-after", "30", "--offline-after", "10"], env)
    assert result.exit_code == 2
    assert "strictly less than" in result.stderr


def test_loranet_decimal_key_matches_from_hex_decimal() -> None:
    """Sanity check the design note: never hand-write a loranet dump key."""
    assert NodeId.from_hex("deadbe01").decimal == str(int("deadbe01", 16))


def _mock_loranet_raw_long_name(
    mock_sources: Callable[..., respx.MockRouter], node_hex: str, long_name_json: str
) -> respx.MockRouter:
    r"""Mock both sources, then serve loranet's dump as raw JSON text.

    ``long_name_json`` is spliced into the body verbatim, so it can carry
    a ``\ud800`` escape: valid JSON that decodes to a lone surrogate,
    which ``httpx.Response(json=...)`` itself can't encode.
    """
    recent = int(time.time()) - 60
    router = mock_sources(nodes={node_hex: {"shortName": "MTa1", "seenBy": {"gw1": recent}}})
    body = (
        f'{{"{NodeId.from_hex(node_hex).decimal}": {{"shortName": "MTa1", '
        f'"longName": "{long_name_json}", "seenBy": {{"gw1": {recent}}}}}}}'
    )
    router.get(LORANET_NODES_URL).mock(
        return_value=httpx.Response(
            200, content=body.encode(), headers={"content-type": "application/json"}
        )
    )
    return router


def test_table_run_escapes_a_lone_surrogate_in_a_node_name(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    """A self-reported name holding a lone surrogate is shown escaped, not a crash.

    Unescaped, writing it to the UTF-8 stdout raised ``UnicodeEncodeError``
    (exit 1) on every run for the whole cache TTL.
    """
    from meshprovision.db.nodes import NodeRecord

    node_hex = _seed_one_node(seed_db, NodeRecord)
    with _mock_loranet_raw_long_name(mock_sources, node_hex, "Evil\\ud800Name"):
        result = invoke(runner, ["status", "--source", "loranet"], {**env, "COLUMNS": "300"})

    assert result.exit_code == 0
    assert "Evil\\ud800Name" in result.stdout


def test_json_run_escapes_a_lone_surrogate_in_a_node_name(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    from meshprovision.db.nodes import NodeRecord

    node_hex = _seed_one_node(seed_db, NodeRecord)
    with _mock_loranet_raw_long_name(mock_sources, node_hex, "Evil\\ud800Name"):
        result = invoke(runner, ["status", "--json", "--source", "loranet"], env)

    assert result.exit_code == 0
    (node_doc,) = json.loads(result.stdout)["nodes"]
    assert node_doc["long_name"] == "Evil\\ud800Name"


@pytest.fixture
def warsaw_local_tz(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Run the test with the C library's local timezone set to Europe/Warsaw (UTC+1/+2).

    ``time.tzset()`` runs again only after the monkeypatch context has
    restored ``TZ``, so the process's local timezone is back to normal
    for every later test.
    """
    with monkeypatch.context() as patch:
        patch.setenv("TZ", "Europe/Warsaw")
        time.tzset()
        yield
    time.tzset()


@pytest.mark.usefixtures("warsaw_local_tz")
def test_table_run_survives_timestamps_at_the_edge_of_the_datetime_range(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    """A "never" sentinel from either source is an unparseable field, not a crash.

    lorastats' naive ``0001-01-01T00:00:00`` (.NET ``DateTime.MinValue``)
    used to raise ``OverflowError`` while being converted to UTC; loranet's
    epoch ``253402300799`` (9999-12-31T23:59:59Z) parsed, then crashed the
    table's local-time rendering east of UTC. Round 41's logic review,
    Finding 2.
    """
    from meshprovision.db.nodes import NodeRecord

    node_hex = _seed_one_node(seed_db, NodeRecord)
    fields = {
        "shortName": "MTa1",
        "seenBy": {"gw1": 253_402_300_799},
        "last_seen_iso": "0001-01-01T00:00:00",
    }
    with mock_sources(nodes={node_hex: fields}):
        result = invoke(runner, ["status"], {**env, "COLUMNS": "300"})

    # Degraded (7) only because the node is now "unknown", never 1 (a crash).
    assert result.exit_code == 7
    assert "never" in result.stdout
    assert "loranet: 1 field(s) could not be coerced" in result.stdout
    assert "lorastats: 1 field(s) could not be coerced" in result.stdout
