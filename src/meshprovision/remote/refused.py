"""What remote work never sends: no flag, no override.

These configuration sections and administrative operations stay out of reach of any remote
write, however it is asked for (OPINION-REMOTE-ADMIN Q2, REFINED section 1, SIM-REVIEW).
The consequence is deliberate: refusing security writes means revoking a lost gateway's
admin key on remote nodes takes a site visit.

Conditional refusals (firmware version, gateway authorisation, management mode,
``MAX_RETRANSMIT``) are preflight rules, not listed here. Pure: nothing here talks to a
device.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

__all__ = ["MAX_CHANNEL_INDEX_READ", "REFUSED_CONFIG", "REFUSED_OPERATIONS", "refused_config"]

_TRANSACTION_REASON: Final[str] = (
    "a transaction is shared with every other admin and is committed or flushed by whoever "
    "speaks next"
)

REFUSED_CONFIG: Final[Mapping[str, str]] = MappingProxyType(
    {
        "lora": (
            "moves or silences the radio, and the change's own acknowledgement leaves on the "
            "new settings, so a mistake cuts the node and every node behind it"
        ),
        "lora.override_duty_cycle": (
            "lifts the firmware's duty-cycle limit, which breaks ETSI EN 300 220 (10 % in "
            "869.4-869.65 MHz) for the node's owner"
        ),
        "default_channel": (
            "a key or name change isolates the node's own traffic and, on LONG_MODERATE or "
            "LONG_SLOW, may move it to the other frequency slot"
        ),
        "security": (
            "admin keys, managed mode and the keypair decide who can reach the node at all; "
            "a mistake locks everyone out until a site visit"
        ),
        "device.role": (
            "a role change makes the firmware rewrite other sections, and some roles stop "
            "relaying for the nodes behind it"
        ),
        "device.rebroadcast_mode": (
            "NONE, LOCAL_ONLY and KNOWN_ONLY stop relaying for the nodes behind it"
        ),
        "device.node_info_broadcast_secs": (
            "slows how fast other nodes learn its key, and shares its message with the role"
        ),
        "power": "sleep settings can make the node miss every later request",
        "network": (
            "WiFi and Ethernet settings are not mesh settings and can cut a gateway's uplink"
        ),
        "bluetooth": "the pairing settings are the owner's local way in",
        "mqtt": "uplink settings carry credentials and change what the node publishes",
        "owner.is_licensed": "ham mode turns off encryption and regenerates the key",
    }
)
"""``"section"`` or ``"section.field"`` -> why a remote write of it is refused forever.
[policy: OPINION-REMOTE-ADMIN Q2, REFINED section 1, SIM-REVIEW]"""

REFUSED_OPERATIONS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "set_channel": "see default_channel; true of every channel slot",
        "set_ham_mode": "see owner.is_licensed",
        "begin_edit_settings": _TRANSACTION_REASON,
        "commit_edit_settings": _TRANSACTION_REASON,
        "reboot_seconds": "a reboot drops the session key and the node is silent until it is back",
        "reboot_ota_seconds": "see reboot_seconds; firmware updates are a site visit",
        "shutdown_seconds": "a shut-down node stays off until someone powers it",
        "factory_reset_device": "erases the node, its keys and its admin list",
        "factory_reset_config": "erases the node's configuration and admin list",
        "nodedb_reset": "erases what the node knows of others, our key included",
    }
)
"""``AdminMessage`` variant name -> why remote work never sends it.
[policy: OPINION-REMOTE-ADMIN Q2, REFINED section 1, SIM-REVIEW]"""

MAX_CHANNEL_INDEX_READ: Final[int] = 0
"""The only channel slot remote work may read (never ``requestChannels=True``).
[policy: OPINION-REMOTE-ADMIN Q2, REFINED section 1, SIM-REVIEW]"""


def refused_config(section: str, field: str | None = None) -> str | None:
    """Return why writing ``section`` (or one of its fields) remotely is refused forever.

    A ``section.field`` entry wins over its section's entry.

    Args:
        section: The section name.
        field: One field of it, or ``None`` for the section as a whole.

    Returns:
        The reason, or ``None`` when no unconditional refusal covers it.
    """
    if field is not None:
        reason = REFUSED_CONFIG.get(f"{section}.{field}")
        if reason is not None:
            return reason
    return REFUSED_CONFIG.get(section)
