"""``mesh provision``'s maintenance warning, read from a pre-seeded ``mesh network`` store."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.errors import ExitCode
from meshprovision.network.buckets import summarize
from meshprovision.network.rawpackets import parse_raw
from meshprovision.network.store import NETWORK_DIRNAME, RegionStore, region_dirname
from tests.e2e.conftest import FakeMeshInterface, invoke
from tests.unit.network_fixtures import packet, row

if TYPE_CHECKING:
    from click.testing import CliRunner

    from tests.e2e.conftest import DeviceBus

pytestmark = pytest.mark.e2e

_NODE = "deadbe01"
_GATEWAY = "6a000073"
_WARNING = f"warning: !{_NODE} carried "


def _seed_store(env: dict[str, str], *, relay: int = 0x01, fetched_ago: float = 600.0) -> Path:
    """Store a region where the device is the only first hop of an outsider (relay byte 0x01)."""
    now = time.time()
    fetched_at = now - fetched_ago
    at = fetched_at - 3600
    rows = [
        row(
            packet(0xA3000013, n, relay=relay, hop_limit=2, snr=6.0, rssi=-85),
            gateway=_GATEWAY,
            time=at + n,
        )
        for n in range(1, 26)
    ]
    rows += [
        row(packet(int(_NODE, 16), 100 + n, snr=6.0, rssi=-85), gateway=_GATEWAY, time=at + n)
        for n in range(5)
    ]
    hours = summarize(parse_raw(rows, now=fetched_at), since=None, fetched_at=fetched_at)
    directory = Path(env["MESHPROVISION_CACHE_DIR"]) / NETWORK_DIRNAME
    RegionStore(directory, clock=lambda: fetched_at).update("Zachód", hours, fetched_at=fetched_at)
    return directory


def test_a_node_others_depend_on_is_warned_about_before_applying(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    iface = bus.use(FakeMeshInterface(_NODE))
    _seed_store(env)

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0, result.output
    assert _WARNING in result.stderr
    assert "of Zachód's stored relayed traffic in the 24 h before " in result.stderr
    assert "1 node(s) used it as their only first hop" in result.stderr
    assert f"Applying this plan reboots it. See: mesh network impact {_NODE}" in result.stderr
    assert _WARNING not in result.stdout
    assert iface.localNode.written_sections


def test_the_warning_comes_before_the_question_and_changes_nothing(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    iface = bus.use(FakeMeshInterface(_NODE))
    _seed_store(env)

    result = invoke(
        runner, ["--interactive", "provision", "--port", "/dev/ttyFAKE0"], env, input="n\n"
    )

    assert result.exit_code == int(ExitCode.INTERRUPTED)
    assert result.stderr.index(_WARNING) < result.stderr.index("Apply this plan to")
    assert iface.localNode.written_sections == []


def test_json_output_stays_one_document_and_the_warning_goes_to_stderr(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    bus.use(FakeMeshInterface(_NODE))
    _seed_store(env)

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes", "--json"], env)

    assert result.exit_code == 0, result.output
    json.loads(result.stdout)
    assert _WARNING in result.stderr


def test_a_dry_run_gets_no_warning(runner: CliRunner, env: dict[str, str], bus: DeviceBus) -> None:
    bus.use(FakeMeshInterface(_NODE))
    _seed_store(env)

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--dry-run"], env)

    assert result.exit_code == 0, result.output
    assert _WARNING not in result.stderr


def test_non_interactive_without_yes_still_warns_then_refuses(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    iface = bus.use(FakeMeshInterface(_NODE))
    _seed_store(env)

    result = invoke(runner, ["--non-interactive", "provision", "--port", "/dev/ttyFAKE0"], env)

    assert result.exit_code != 0
    assert _WARNING in result.stderr
    assert iface.localNode.written_sections == []


@pytest.mark.parametrize(
    "case",
    [
        pytest.param("no-store", id="no-store"),
        pytest.param("stale", id="older-than-48-hours"),
        pytest.param("not-carrying", id="its-byte-carries-nothing"),
        pytest.param("corrupt", id="corrupt-state"),
    ],
)
def test_no_warning_without_recent_evidence(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, case: str
) -> None:
    iface = bus.use(FakeMeshInterface(_NODE))
    if case == "stale":
        _seed_store(env, fetched_ago=48 * 3600 + 60)
    elif case == "not-carrying":
        _seed_store(env, relay=0x61)
    elif case == "corrupt":
        directory = _seed_store(env)
        (directory / region_dirname("Zachód") / "state.json").write_text("{", encoding="utf-8")

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0, result.output
    assert "carried " not in result.stderr
    assert iface.localNode.written_sections


def test_an_already_provisioned_node_with_nothing_to_apply_gets_no_warning(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    bus.use(FakeMeshInterface(_NODE))
    first = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)
    assert first.exit_code == 0, first.output
    _seed_store(env)

    again = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert again.exit_code == 0, again.output
    assert _WARNING not in again.stderr


@pytest.mark.parametrize(
    ("firmware", "renumbers"), [("2.8.0.47db0e3", True), ("2.7.11", False)], ids=["2.8", "2.7"]
)
def test_the_warning_says_a_key_write_on_firmware_2_8_changes_the_node_id(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, firmware: str, renumbers: bool
) -> None:
    iface = FakeMeshInterface(_NODE, firmware_version=firmware)
    iface.localNode.localConfig.lora.region = 3  # EU_868: the plan writes no region
    bus.use(iface)
    _seed_store(env)

    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes"], env)

    assert result.exit_code == 0, result.output
    changes = "Applying this plan reboots it and changes its node id (firmware >= 2.8 derives"
    assert (changes in result.stderr) is renumbers
