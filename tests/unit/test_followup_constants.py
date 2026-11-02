"""The constants of the firmware 2.8, health-importance and loranet follow-ups, as documented.

Like ``test_network_constants.py``: each tunable is pinned to its value, and
its wording in ``docs/commands.md`` (or ``docs/firmware-compatibility.md``)
is checked to be there, so that changing one without the other fails here.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from meshprovision import firmware, nodeid
from meshprovision.cli import provision_keys
from meshprovision.datasources import loranet
from meshprovision.db import pending_keys, renumber
from meshprovision.health import rules
from meshprovision.network import graph, relays, render_graph

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[2]
_DOCS = (_ROOT / "docs" / "commands.md").read_text(encoding="utf-8")
_FIRMWARE_DOCS = (_ROOT / "docs" / "firmware-compatibility.md").read_text(encoding="utf-8")
_PROVISION = _DOCS[_DOCS.index("## `mesh provision`") : _DOCS.index("## `mesh adopt`")]
_HEALTH = _DOCS[_DOCS.index("## `mesh health`") : _DOCS.index("## `mesh network`")]
_NETWORK = _DOCS[_DOCS.index("## `mesh network`") : _DOCS.index("## `mesh admin`")]
_DB = _DOCS[_DOCS.index("## `mesh db`") : _DOCS.index("## `mesh peers`")]


def _flat(text: str) -> str:
    return " ".join(text.split())


def test_the_firmware_2_8_identity_constants() -> None:
    assert (
        nodeid.RESERVED_NODE_NUMS_BELOW,
        nodeid.BROADCAST_NODE_NUM,
        nodeid.KEY_DERIVED_ID_KEY_BYTES,
        firmware.KEY_DERIVED_ID_MIN_FIRMWARE,
        provision_keys.KEYGEN_ATTEMPTS,
        pending_keys.MAX_PENDING_SCANNED,
        renumber.NOTE_SEPARATOR,
    ) == (4, 0xFFFFFFFF, 32, (2, 8, 0), 16, 256, "; ")


def test_the_relay_device_constants() -> None:
    assert (relays.MAX_PLAUSIBLE_VOLTAGE, relays.MAX_UPTIME_SECONDS) == (100.0, 0xFFFFFFFF)
    assert (
        relays.EXTERNAL_POWER_LEVEL,
        relays.DEVICE_METRICS_FRESH_SECONDS,
        relays.RECENT_REBOOT_SECONDS,
        relays.NOT_IN_LORANET,
        rules.BATTERY_WARN_PERCENT,
    ) == (101, 24 * 3600.0, 3600.0, "not in loranet", 20)


def test_the_loranet_neighbour_constants() -> None:
    assert (loranet.MAX_REPORTED_NEIGHBORS, graph.LORANET_NEIGHBOR) == (64, "loranet_neighbor")


@pytest.mark.parametrize(
    "phrase",
    [
        "reserved (below 4, or the broadcast address), another row's or a key row's owner "
        "is drawn again (up to 16 times)",
        "warning code `node_id_changes`, for a parseable firmware version >= 2.8",
        "reboots it and changes its node id (firmware >= 2.8 derives it from the new key)",
        "A firmware >= 2.8 device whose LoRa region is still `UNSET` is refused",
        "`mesh db renumber OLD NEW`",
    ],
)
def test_the_provision_docs_state_these(phrase: str) -> None:
    assert _flat(phrase) in _flat(_PROVISION)


def test_the_db_docs_state_the_renumber_guards() -> None:
    text = _flat(_DB)

    assert "reserved (below 4, or `ffffffff`)" in text
    assert "node id was !OLD until <date> (firmware 2.8 key-derived id)" in text


def test_the_note_wording_is_the_documented_one() -> None:
    note = renumber.renumber_note(nodeid.NodeId(0xDEADBE01), until=datetime(2026, 1, 1, tzinfo=UTC))

    assert note == "node id was !deadbe01 until 2026-01-01 (firmware 2.8 key-derived id)"


def test_the_health_docs_state_the_region_rule() -> None:
    text = _flat(_HEALTH)

    assert "stored that region at most 48 hours ago" in text
    assert "in the 24 hours before the fetch" in text
    assert "Only `medium` or `high` counts" in text
    assert "the level is the higher of the two, never a sum" in text


@pytest.mark.parametrize(
    "phrase",
    [
        "or below 20 %, the `mesh health` warning level",
        "or above 100 V, a percentage outside 0-100, a negative uptime or one past a 32-bit "
        "counter",
        "an entry that does not parse is skipped",
        "(which itself never reads them)",
        "(`ext` on external power, level 101)",
        "more than 24 hours old",
        "under an hour",
        "not in loranet",
        "at most 64 per node",
        "`loranet_neighbor` evidence",
        render_graph.LORANET_NON_CLAIM,
    ],
)
def test_the_network_docs_state_these(phrase: str) -> None:
    assert _flat(phrase) in _flat(_NETWORK)


@pytest.mark.parametrize(
    "phrase",
    [
        "**Verified** means read in the firmware source",
        "**Nothing here was tried on a device.**",
        "*Unverified:* the CRC is zlib's CRC-32",
        "below 4",
    ],
)
def test_the_firmware_docs_keep_their_labels(phrase: str) -> None:
    assert _flat(phrase) in _flat(_FIRMWARE_DOCS)
