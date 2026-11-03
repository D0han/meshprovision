"""The constants of the firmware 2.8, health-importance and loranet follow-ups, as documented.

Like ``test_network_constants.py``: each tunable is pinned to its value, and
the value, rendered from its constant, is checked to occur in
``docs/commands.md`` (or ``docs/firmware-compatibility.md``), so that
changing one without the other fails here.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from meshprovision import firmware, nodeid
from meshprovision.cli import provision_keys
from meshprovision.datasources import loranet
from meshprovision.db import pending_keys, renumber
from meshprovision.health import rules
from meshprovision.network import graph, maintenance, relays, render_graph

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


def test_the_note_wording_is_the_documented_one() -> None:
    note = renumber.renumber_note(nodeid.NodeId(0xDEADBE01), until=datetime(2026, 1, 1, tzinfo=UTC))

    assert note == "node id was !deadbe01 until 2026-01-01 (firmware 2.8 key-derived id)"


def _hours(seconds: float) -> str:
    return f"{seconds / 3600:g} hours"


def _standalone(phrase: str, docs: str) -> int:
    """Count the occurrences of ``phrase`` not inside a longer number or word."""
    pattern = r"(?<![0-9A-Za-z.])" + re.escape(_flat(phrase)) + r"(?![0-9])"
    return len(re.findall(pattern, _flat(docs)))


_FIRMWARE_FLOOR = ".".join(str(part) for part in firmware.KEY_DERIVED_ID_MIN_FIRMWARE[:2])


@pytest.mark.parametrize(
    ("docs", "phrase"),
    [
        pytest.param(
            _PROVISION,
            f"below {nodeid.RESERVED_NODE_NUMS_BELOW}, or the broadcast address",
            id="provision-reserved",
        ),
        pytest.param(
            _PROVISION, f"up to {provision_keys.KEYGEN_ATTEMPTS} times", id="keygen-attempts"
        ),
        pytest.param(
            _PROVISION,
            f"the device runs firmware >= {_FIRMWARE_FLOOR}, it ends",
            id="provision-firmware-plan",
        ),
        pytest.param(
            _PROVISION,
            f"(firmware >= {_FIRMWARE_FLOOR} derives it from the new key)",
            id="provision-firmware-warning",
        ),
        pytest.param(
            _PROVISION,
            f"(firmware >= {_FIRMWARE_FLOOR} derives the node id from the public key)",
            id="provision-firmware-renumber",
        ),
        pytest.param(
            _PROVISION,
            f"A firmware >= {_FIRMWARE_FLOOR} device whose LoRa region is still `UNSET`",
            id="provision-firmware-region",
        ),
        pytest.param(
            _PROVISION,
            f"A node that firmware >= {_FIRMWARE_FLOOR} renumbered",
            id="provision-firmware-renumbered",
        ),
        pytest.param(
            _DB,
            f"reserved (below {nodeid.RESERVED_NODE_NUMS_BELOW}, or "
            f"`{nodeid.BROADCAST_NODE_NUM:08x}`)",
            id="db-reserved",
        ),
        pytest.param(
            _DB,
            renumber.renumber_note(nodeid.NodeId(1), until=datetime(2026, 1, 1, tzinfo=UTC)).split(
                " until 2026-01-01 "
            )[1],
            id="db-note",
        ),
        pytest.param(
            _HEALTH,
            f"at most {_hours(maintenance.MAINTENANCE_MAX_AGE_SECONDS)} ago",
            id="health-max-age",
        ),
        pytest.param(
            _HEALTH,
            f"in the {_hours(maintenance.MAINTENANCE_WINDOW_SECONDS)} before the fetch",
            id="health-window",
        ),
        pytest.param(_NETWORK, f"below {rules.BATTERY_WARN_PERCENT} %", id="battery-warn"),
        pytest.param(
            _NETWORK, f"above {relays.MAX_PLAUSIBLE_VOLTAGE:g} V", id="max-plausible-voltage"
        ),
        pytest.param(_NETWORK, f"level {relays.EXTERNAL_POWER_LEVEL}", id="external-power-level"),
        pytest.param(
            _NETWORK,
            f"more than {_hours(relays.DEVICE_METRICS_FRESH_SECONDS)} old",
            id="device-metrics-fresh",
        ),
        pytest.param(_NETWORK, relays.NOT_IN_LORANET, id="not-in-loranet"),
        pytest.param(
            _NETWORK, f"at most {loranet.MAX_REPORTED_NEIGHBORS} per node", id="max-neighbors"
        ),
        pytest.param(
            _NETWORK, f"`{graph.LORANET_NEIGHBOR}` is kept apart", id="loranet-neighbor-kind"
        ),
        pytest.param(
            _NETWORK, f"as `{graph.LORANET_NEIGHBOR}` evidence", id="loranet-neighbor-evidence"
        ),
        pytest.param(_NETWORK, render_graph.LORANET_NON_CLAIM, id="loranet-non-claim"),
        pytest.param(
            _FIRMWARE_DOCS,
            f"below {nodeid.RESERVED_NODE_NUMS_BELOW}",
            id="firmware-reserved",
        ),
    ],
)
def test_the_docs_state_each_value(docs: str, phrase: str) -> None:
    # Exactly once: a value inside a longer number, or repeated in another
    # sentence, would let a change to this one go unnoticed.
    assert _standalone(phrase, docs) == 1
