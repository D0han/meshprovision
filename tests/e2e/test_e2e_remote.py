"""``mesh remote diff --dry-run`` end to end: offline, read-only, and sending nothing."""

from __future__ import annotations

import base64
import dataclasses
import json
import socket
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
import serial

from meshprovision.db.keys import KeyRecord
from meshprovision.db.known_good import known_good_path
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import KeyType, ManagementMode, ref_for
from meshprovision.health.history import TelemetryPoint
from meshprovision.health.store import HISTORY_DIRNAME, HistoryStore
from meshprovision.nodeid import NodeId
from meshprovision.remote.render import ESTIMATE_LINE
from tests.e2e.conftest import db_fingerprint, invoke

if TYPE_CHECKING:
    from click.testing import CliRunner

    from tests.e2e.conftest import DeviceBus

pytestmark = pytest.mark.e2e

GATEWAY_KEY = bytes(range(32))
NODE = NodeId.from_hex("deadbe01")


def _seed(
    seed_db: Callable[..., Path],
    *,
    firmware: str = "2.8.3",
    gateway_firmware: str = "2.8.3",
    authorized: bool = True,
) -> Path:
    return seed_db(
        nodes=[
            NodeRecord(
                node_id="deadbe01",
                management=ManagementMode.TEMPLATE,
                firmware_version=firmware,
                authorized_admin_keys=("deadbe0a_pub",) if authorized else (),
            ),
            NodeRecord(
                node_id="deadbe0a",
                management=ManagementMode.TEMPLATE,
                firmware_version=gateway_firmware,
            ),
        ],
        keys=[
            KeyRecord(
                key_ref=ref_for("deadbe0a", KeyType.ADMIN_PUBLIC),
                owner_node_id="deadbe0a",
                key_type=KeyType.ADMIN_PUBLIC,
                key_value=base64.b64encode(GATEWAY_KEY).decode("ascii"),
            )
        ],
    )


def _no_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("mesh remote opened a socket")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def _no_serial(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("mesh remote opened a serial port")

    monkeypatch.setattr(serial.Serial, "open", refuse)
    monkeypatch.setattr(serial, "serial_for_url", refuse)


@pytest.fixture(autouse=True)
def _offline(monkeypatch: pytest.MonkeyPatch, bus: DeviceBus) -> Iterator[None]:
    """Every test here runs with no socket, no serial port and no device connection."""
    _no_sockets(monkeypatch)
    _no_serial(monkeypatch)
    yield
    assert bus.targets == ()


def _files(directory: Path) -> dict[Path, tuple[int, str]]:
    if not directory.exists():
        return {}
    return {
        path.relative_to(directory): db_fingerprint(path)
        for path in directory.rglob("*")
        if path.is_file()
    }


def _lora(preset: str) -> dict[str, Any]:
    return {
        "region": "EU_868",
        "use_preset": True,
        "modem_preset": preset,
        "hop_limit": 3,
        "tx_enabled": True,
    }


def _json(stdout: str) -> dict[str, Any]:
    document = json.loads(stdout)
    assert isinstance(document, dict)
    return document


def _codes(findings: list[dict[str, str]]) -> list[str]:
    return [finding["code"] for finding in findings]


def test_without_dry_run_it_refuses_before_reading_anything(
    runner: CliRunner, cli_env: dict[str, str], tmp_path: Path
) -> None:
    env = {
        **cli_env,
        "MESHPROVISION_DB_PATH": str(tmp_path / "missing.ods"),
        "MESHPROVISION_TEMPLATE_PATH": str(tmp_path / "missing.yaml"),
    }

    result = invoke(runner, ["remote", "diff", "deadbe01"], env)

    assert result.exit_code == 2
    assert "no live mode" in result.stderr
    # Bare hex: an unquoted "!deadbe01" is bash history expansion.
    assert "`mesh remote diff --dry-run deadbe01`" in result.stderr
    assert "Template file not found" not in result.stderr
    assert "Node database not found" not in result.stderr
    assert result.stdout == ""


def test_dry_run_on_medium_fast_with_an_authorized_gateway_is_allowed(
    runner: CliRunner,
    env: dict[str, str],
    db_path: Path,
    seed_db: Callable[..., Path],
    write_template: Callable[..., Path],
    bus: DeviceBus,
) -> None:
    _seed(seed_db)
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(lora=_lora("MEDIUM_FAST")))
    cache = Path(env["MESHPROVISION_CACHE_DIR"])
    before_cache, before_dir = _files(cache), _files(db_path.parent)
    before_db = db_fingerprint(db_path)

    result = invoke(
        runner, ["remote", "diff", "deadbe01", "--dry-run", "--gateway", "deadbe0a", "--json"], env
    )

    assert result.exit_code == 0
    document = _json(result.stdout)
    assert document["verdict"] == "allowed"
    assert document["gateway"]["authorization"] == "authorized"
    assert document["estimate"]["ledger"]["relay_seconds"] == 9.767
    assert document["estimate"]["ledger"]["per_window"] == 3
    assert len(document["requests"]) == 16
    assert bus.targets == ()
    assert _files(cache) == before_cache
    after_dir = _files(db_path.parent)
    changed = {path for path, state in after_dir.items() if before_dir.get(path) != state}
    known_good = known_good_path(db_path)
    sidecar = known_good.with_suffix(".json")  # its provenance record
    assert changed <= {known_good.relative_to(db_path.parent), sidecar.relative_to(db_path.parent)}
    assert db_fingerprint(db_path) == before_db


def test_dry_run_of_the_example_template_on_long_fast_is_allowed_at_cw_7(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    _seed(seed_db, firmware="2.7.11")

    result = invoke(runner, ["remote", "diff", "deadbe01", "--dry-run"], env)

    assert result.exit_code == 0
    for text in (
        "Verdict: allowed offline",
        "worst_case_over_share",
        "largest_replies_over_share",
        "security_skipped",
        "does not fit at CW 8",
    ):
        assert text in result.stdout
    assert " ".join(ESTIMATE_LINE.split()) in " ".join(result.stdout.split())


def test_a_section_on_long_moderate_fits(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    write_template: Callable[..., Path],
) -> None:
    _seed(seed_db)
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(lora=_lora("LONG_MODERATE")))

    result = invoke(
        runner, ["remote", "diff", "deadbe01", "--dry-run", "--section", "lora", "--json"], env
    )

    assert result.exit_code == 0
    document = _json(result.stdout)
    assert document["estimate"]["ledger"]["relay_seconds"] == 13.734
    assert document["estimate"]["ledger_worst_case"]["relay_seconds"] == 17.238
    assert "two_frequency_slots" in _codes(document["notes"])


def test_a_full_diff_on_long_moderate_is_refused(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    write_template: Callable[..., Path],
) -> None:
    _seed(seed_db)
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(lora=_lora("LONG_MODERATE")))

    result = invoke(runner, ["remote", "diff", "deadbe01", "--dry-run", "--json"], env)

    assert result.exit_code == 5
    codes = _codes(_json(result.stdout)["refusals"])
    assert "full_diff_on_slow_preset" in codes
    assert "over_polite_share" in codes


def test_the_destination_history_is_read_not_written(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    write_template: Callable[..., Path],
) -> None:
    _seed(seed_db)
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(lora=_lora("MEDIUM_FAST")))
    store = HistoryStore(Path(env["MESHPROVISION_CACHE_DIR"]) / HISTORY_DIRNAME)
    store.update(
        NODE,
        lambda history: dataclasses.replace(
            history, telemetry=(TelemetryPoint(time.time() - 600, air_util_tx=6.0),)
        ),
    )
    stored = db_fingerprint(store.path_for(NODE))

    result = invoke(runner, ["remote", "diff", "deadbe01", "--dry-run", "--json"], env)

    assert result.exit_code == 5
    document = _json(result.stdout)
    assert "destination_busy" in _codes(document["refusals"])
    assert document["destination_air_util_tx"]["percent"] == 6.0
    assert db_fingerprint(store.path_for(NODE)) == stored


def test_an_unknown_node_is_refused(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    _seed(seed_db)

    result = invoke(runner, ["remote", "diff", "deadbe99", "--dry-run", "--json"], env)

    assert result.exit_code == 5
    document = _json(result.stdout)
    assert _codes(document["refusals"]) == ["not_in_database"]
    assert document["firmware"]["recorded"] == ""
    notes = _codes(document["notes"])
    assert "admin_key_fallback" not in notes
    assert "busy_unknown" not in notes


def test_remote_help_says_it_sends_nothing(runner: CliRunner, env: dict[str, str]) -> None:
    group = invoke(runner, ["remote", "--help"], env)
    command = invoke(runner, ["remote", "diff", "--help"], env)

    assert group.exit_code == 0
    assert command.exit_code == 0
    assert "sends nothing" in " ".join(group.stdout.split())
    flat = " ".join(command.stdout.split())
    assert "nothing is sent" in flat
    assert "polite share" in flat
