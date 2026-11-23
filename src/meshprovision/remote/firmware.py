"""What remote work must assume about a node's firmware.

Version gates, the gateway's retry count and the admin session timings, each with its
class in brackets: ``[source: ...]`` read in the firmware, ``[measured: ...]`` seen in
simulator runs, ``[policy: ...]`` a choice (see :mod:`meshprovision.remote`). Pure: nothing
here talks to a device.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from meshprovision.firmware import parse_firmware_version

__all__ = [
    "ADMIN_KEY_FALLBACK_MIN_FIRMWARE",
    "GATEWAY_ATTEMPTS_BEFORE_2_8",
    "GATEWAY_ATTEMPTS_FROM_2_8",
    "LONG_CAD_MIN_FIRMWARE",
    "PASSKEY_ROTATE_SECONDS",
    "PASSKEY_VALID_SECONDS",
    "PRIVATE_KEY_REDACTED_MIN_FIRMWARE",
    "RELIABLE_UNICAST_ATTEMPTS_MIN_FIRMWARE",
    "REMOTE_READ_MIN_FIRMWARE",
    "TRANSACTION_EXPIRY_MIN_FIRMWARE",
    "TRANSACTION_IDLE_FLUSH_SECONDS",
    "FirmwareTraits",
    "RadioChip",
    "cad_symbols",
    "firmware_traits",
]

REMOTE_READ_MIN_FIRMWARE: Final[tuple[int, int, int]] = (2, 7, 0)
"""A live remote read is allowed from this firmware on.
[policy: OPINION verdict and Q2 item 3; stricter than COMPARE section 2.0's 2.6.11 floor]"""

PRIVATE_KEY_REDACTED_MIN_FIRMWARE: Final[tuple[int, int, int]] = (2, 8, 0)
"""A remote ``security`` read leaves out the private key from this firmware on.
[source: 2.8.3 ``AdminModule.cpp:1528-1531`` redacts; measured: 2.7.26 sends the 32 B key,
COMPARE row 11, pk27. Boundary assumed at the first 2.8 release, not bisected]"""

TRANSACTION_EXPIRY_MIN_FIRMWARE: Final[tuple[int, int, int]] = (2, 8, 0)
"""An abandoned edit transaction is flushed after :data:`TRANSACTION_IDLE_FLUSH_SECONDS`
from this firmware on. [source: 2.8.3 ``AdminModule.h:45``; 2.7.26 and 2.6.13 have no
expiry, COMPARE row 6. Boundary assumed]"""

ADMIN_KEY_FALLBACK_MIN_FIRMWARE: Final[tuple[int, int, int]] = (2, 8, 0)
"""A node decrypts an admin request from a sender it holds only as an admin key from this
firmware on. [measured: COMPARE row 3, 2.7 and 2.6 answer ``PKI_UNKNOWN_PUBKEY`` first.
Boundary assumed]"""

RELIABLE_UNICAST_ATTEMPTS_MIN_FIRMWARE: Final[tuple[int, int, int]] = (2, 8, 0)
"""A reliable unicast is sent :data:`GATEWAY_ATTEMPTS_FROM_2_8` times from this firmware
on. [source: 2.8.3 ``NextHopRouter.h:115``, ``ReliableRouter.cpp:36``; 2.7.26
``ReliableRouter.cpp:24`` uses ``NUM_RELIABLE_RETX``; PRESETS-PL section 2.5 says 2.8.0
added it. Boundary assumed]"""

GATEWAY_ATTEMPTS_FROM_2_8: Final[int] = 5
"""Transmissions of one unanswered reliable unicast on 2.8, the first send included.
[source: ``NextHopRouter.h:115``, ``ReliableRouter.cpp:36`` (2.8.3)]"""

GATEWAY_ATTEMPTS_BEFORE_2_8: Final[int] = 3
"""Transmissions of one unanswered reliable unicast before 2.8.
[source: ``NUM_RELIABLE_RETX = 3``; measured: T7, 3 transmissions, ``MAX_RETRANSMIT`` after
21 s]"""

LONG_CAD_MIN_FIRMWARE: Final[tuple[int, int, int]] = (2, 8, 0)
"""An SX126x-family radio scans 4 CAD symbols from this firmware on (RF95 scans 2, as does
every chip before). [source: 2.8 ``SX126xInterface.h:97``, ``RF95Interface.h:58``; 2.6 and
2.7 ``NUM_SYM_CAD = 2`` for every chip; T1 section a. Boundary assumed]"""

PASSKEY_ROTATE_SECONDS: Final[int] = 150
"""How often a node issues a new admin session key.
[source: ``AdminModule.cpp:1976``; the same on 2.6, 2.7 and 2.8, COMPARE row 1]"""

PASSKEY_VALID_SECONDS: Final[int] = 300
"""How long an admin session key stays valid. [source: ``AdminModule.cpp:2002``]"""

TRANSACTION_IDLE_FLUSH_SECONDS: Final[int] = 60
"""Idle time after which an edit transaction is flushed, from
:data:`TRANSACTION_EXPIRY_MIN_FIRMWARE` on. [source: ``AdminModule.h:45``]"""


class RadioChip(StrEnum):
    """The radio family of a node, as far as its CAD scan length goes.

    Attributes:
        SX126X: SX126x, LR11x0 and LR20x0 drivers.
        RF95: SX127x boards (the ``RF95`` driver).
        UNKNOWN: Not known; treated as :attr:`SX126X` (the longer slot).
    """

    SX126X = "sx126x"
    RF95 = "rf95"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class FirmwareTraits:
    """What remote work must assume about one node's firmware.

    Attributes:
        version: The parsed ``(major, minor, patch)``, or ``None`` when unparseable.
        remote_read_allowed: A remote read of it is allowed at all.
        private_key_redacted: A remote ``security`` read leaves out the private key.
        transaction_expires: An abandoned edit transaction is flushed after
            :data:`TRANSACTION_IDLE_FLUSH_SECONDS` idle. Nothing reads it
            yet: groundwork for a remote write, which there is none of.
        admin_key_fallback: It decrypts an admin request from a sender it holds only
            as an admin key.
        unicast_attempts: Transmissions it makes of one unanswered reliable unicast.
        long_cad_on_sx126x: An SX126x-family radio scans 4 CAD symbols (else 2).
    """

    version: tuple[int, int, int] | None
    remote_read_allowed: bool
    private_key_redacted: bool
    transaction_expires: bool
    admin_key_fallback: bool
    unicast_attempts: int
    long_cad_on_sx126x: bool


def firmware_traits(raw: str) -> FirmwareTraits:
    """Derive the traits of a firmware version string; an unparseable one gets the most careful.

    Each trait of an unparseable version takes the value that makes remote work more
    careful: no read, the private key may be present, an abandoned transaction may never
    expire, no admin-key fallback, the larger number of gateway transmissions to charge,
    and the longer slot (longer deadlines, more spurious retransmits).

    Args:
        raw: The raw firmware version string (a leading ``v`` and a build hash are fine).

    Returns:
        The node's traits.
    """
    version = parse_firmware_version(raw)
    if version is None:
        return FirmwareTraits(None, False, False, False, False, GATEWAY_ATTEMPTS_FROM_2_8, True)
    return FirmwareTraits(
        version=version,
        remote_read_allowed=version >= REMOTE_READ_MIN_FIRMWARE,
        private_key_redacted=version >= PRIVATE_KEY_REDACTED_MIN_FIRMWARE,
        transaction_expires=version >= TRANSACTION_EXPIRY_MIN_FIRMWARE,
        admin_key_fallback=version >= ADMIN_KEY_FALLBACK_MIN_FIRMWARE,
        unicast_attempts=(
            GATEWAY_ATTEMPTS_FROM_2_8
            if version >= RELIABLE_UNICAST_ATTEMPTS_MIN_FIRMWARE
            else GATEWAY_ATTEMPTS_BEFORE_2_8
        ),
        long_cad_on_sx126x=version >= LONG_CAD_MIN_FIRMWARE,
    )


def cad_symbols(traits: FirmwareTraits, chip: RadioChip) -> int:
    """Return the CAD symbols a node scans.

    Args:
        traits: The node's firmware traits.
        chip: Its radio family.

    Returns:
        4 for an SX126x-family (or unknown) radio on firmware with
        :attr:`FirmwareTraits.long_cad_on_sx126x`, else 2.
    """
    return 4 if traits.long_cad_on_sx126x and chip is not RadioChip.RF95 else 2
