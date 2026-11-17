"""Time-on-air and timing arithmetic for remote admin on the seven EU_868 presets.

Everything is in seconds and pure. Every formula carries its source; every constant ends
with its class in brackets (``[source: ...]``, ``[measured: ...]``, ``[policy: ...]`` or
``[model: ...]``). The results are a worst-case planning model, never a measurement of a
real link (OPINION-REMOTE-ADMIN "Claims I consider unsafe" 1-4).
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fractions import Fraction
from types import MappingProxyType
from typing import Final

from meshprovision.lora_regions import REGION_BANDS

__all__ = [
    "CLIENT_OVERHEAD_SECONDS",
    "CW_LIMIT",
    "CW_MIN",
    "HEADER_BYTES",
    "HOUR_SECONDS",
    "LATE_REPLY_GRACE_FACTOR",
    "LDRO_SYMBOL_SECONDS",
    "MAX_LINKS",
    "MAX_LORA_PACKET_BYTES",
    "MAX_PKC_DATA_BYTES",
    "MAX_REPLY_BYTES",
    "MEASURED_TEMPLATE_REPLY_BYTES",
    "ORIGIN_BACKOFF_SLOTS",
    "PKC_OVERHEAD_BYTES",
    "POLITE_RELAY_SHARE",
    "PREAMBLE_SYMBOLS",
    "PRESET_RADIO",
    "PROCESSING_SECONDS",
    "RELAY_FIXED_BACKOFF_SLOTS",
    "REQUEST_BYTES",
    "RETRANSMIT_SLOTS",
    "SETTLE_MAX_SECONDS",
    "SETTLE_MIN_SECONDS",
    "SETTLE_MIN_SLOW_PRESET_SECONDS",
    "SETTLE_QUIET_PACKETS",
    "SLOW_PRESETS",
    "STRONG_LINK_CW",
    "T1_REPLY_BYTES",
    "TYPICAL_CW",
    "WORST_CASE_CW",
    "PresetRadio",
    "SettleRule",
    "air_time_seconds",
    "deadline_seconds",
    "diff_airtime_seconds",
    "diffs_per_hour",
    "late_reply_grace_seconds",
    "low_data_rate_optimize",
    "relay_budget_seconds",
    "retransmit_timer_seconds",
    "settle_rule",
    "slot_ms",
    "spurious_factor",
    "spurious_retransmit_probability",
    "symbol_seconds",
    "unanswered_request_seconds",
]


@dataclass(frozen=True, slots=True)
class PresetRadio:
    """A modem preset's LoRa parameters.

    Attributes:
        bandwidth_hz: Bandwidth.
        spreading_factor: Spreading factor.
        coding_rate: Coding-rate denominator (5 for 4/5, 8 for 4/8).
    """

    bandwidth_hz: int
    spreading_factor: int
    coding_rate: int


@dataclass(frozen=True, slots=True)
class SettleRule:
    """How long to listen before the first request (PRESETS-PL section 2.2).

    Attributes:
        quiet_seconds: The channel must have been quiet this long.
        min_seconds: Listen at least this long.
        max_seconds: Give up waiting for quiet after this long.
    """

    quiet_seconds: float
    min_seconds: float
    max_seconds: float


PRESET_RADIO: Final[Mapping[str, PresetRadio]] = MappingProxyType(
    {
        "SHORT_FAST": PresetRadio(250_000, 7, 5),
        "SHORT_SLOW": PresetRadio(250_000, 8, 5),
        "MEDIUM_FAST": PresetRadio(250_000, 9, 5),
        "MEDIUM_SLOW": PresetRadio(250_000, 10, 5),
        "LONG_FAST": PresetRadio(250_000, 11, 5),
        "LONG_MODERATE": PresetRadio(125_000, 11, 8),
        "LONG_SLOW": PresetRadio(125_000, 12, 8),
    }
)
"""The seven EU_868 presets' radio parameters.
[source: ``MeshRadio.h`` ``modemPresetToParams``, identical in 2.6.13, 2.7.26 and 2.8.3; T1
section a]"""

PREAMBLE_SYMBOLS: Final[int] = 16
"""Preamble length. [source: ``RadioInterface.h:113-114`` ``preambleLengthDefault``]"""

LDRO_SYMBOL_SECONDS: Final[float] = 0.016
"""Low-data-rate optimisation is on when the symbol time exceeds this (125 kHz SF11 and
SF12). [source: Semtech and RadioLib]"""

MAX_LORA_PACKET_BYTES: Final[int] = 255
"""The most a LoRa packet carries. [source: ``RadioInterface.h:21``]"""

HEADER_BYTES: Final[int] = 16
"""The Meshtastic packet header. [source: ``RadioInterface.h:22`` ``MESHTASTIC_HEADER_LENGTH``]"""

PKC_OVERHEAD_BYTES: Final[int] = 12
"""What public-key encryption adds. [source: ``RadioInterface.h:23`` ``MESHTASTIC_PKC_OVERHEAD``]"""

MAX_PKC_DATA_BYTES: Final[int] = MAX_LORA_PACKET_BYTES - HEADER_BYTES - PKC_OVERHEAD_BYTES
"""The largest Data a PKC send carries (227).
[source: ``Router.cpp:1337`` refuses a PKC send above this]"""

REQUEST_BYTES: Final[int] = 54
"""A get request on air: 38 B encrypted (12 B PKC overhead included) plus the 16 B header.
[measured: A1, every get request; T1 section d]"""

MAX_REPLY_BYTES: Final[int] = MAX_PKC_DATA_BYTES + PKC_OVERHEAD_BYTES + HEADER_BYTES
"""The largest PKC reply on air (255). PRESETS-PL and T1 used 243 (227 + 16, without the PKC
overhead); see :data:`T1_REPLY_BYTES`.
[source: :data:`MAX_PKC_DATA_BYTES` plus the PKC overhead plus the header]"""

T1_REPLY_BYTES: Final[int] = MAX_PKC_DATA_BYTES + HEADER_BYTES
"""The documents' maximum reply (243): the 227 B Data limit plus the header, without the
12 B PKC overhead. Kept only so their tables can be reproduced; never a default.
[model: T1 b2 and d; PRESETS-PL sections 1.1, 2.1 and 2.2]"""

MEASURED_TEMPLATE_REPLY_BYTES: Final[tuple[int, ...]] = (
    91,
    136,
    73,
    87,
    83,
    103,
    73,
    89,
    78,
    174,
    118,
    76,
    77,
)
"""On-air sizes of the 13 replies to a full template read, in order.
[measured: A1 run s01_3, firmware 2.7.26; T1 section d gives 75, 120, 57, 71, 67, 87, 57, 73,
62, 158, 102, 60, 61, each plus the 16 B header; total 1258 B]"""

MAX_LINKS: Final[int] = 7
"""The most links (the request's hop limit, T1's convention). [source: ``MeshTypes.h:38``
``HOP_MAX``]"""

CW_MIN: Final[int] = 3
"""The smallest contention-window exponent. [source: ``CWmin``]"""

CW_LIMIT: Final[int] = 11
"""The largest contention-window exponent: ``getCWsize`` is unclamped and reaches 11 at
+30 dB. [source: T1 b1]"""

RELAY_FIXED_BACKOFF_SLOTS: Final[int] = 16
"""A relay's fixed backoff, ``2 * CWmax`` slots.
[source: ``getTxDelayMsecWeighted``, ``RadioInterface.cpp:872-885``]"""

ORIGIN_BACKOFF_SLOTS: Final[int] = 14
"""The backoff of the two origins (the gateway's request, the node's reply): at most
``2**CW_MIN - 1 = 7`` slots each. [source: T1 b1 and b4]"""

RETRANSMIT_SLOTS: Final[int] = 56
"""Slots in the retransmit timer on a quiet channel: ``2**3 + 2*8 + 2**5``. The slot count is
exact; the airtime term of the functions using it is the T1 model.
[source: ``RadioInterface.cpp:822-824``]"""

PROCESSING_SECONDS: Final[float] = 4.5
"""The processing time in the retransmit timer, as T1 b3 reads it.
[source: ``PROCESSING_TIME_MSEC``, ``RadioInterface.h:117``]"""

STRONG_LINK_CW: Final[int] = 8
"""The contention-window exponent of a strong link: ``getCWsize`` maps SNR -20..10 to 3..8, so
SNR 10 to 15 dB gives 8. [source: T1 b1]"""

WORST_CASE_CW: Final[int] = STRONG_LINK_CW
"""The contention-window exponent of the worst case: every link at SNR 10 to 15 dB, which
``getCWsize`` maps to 8; above 15 dB it gives 9 and more, outside the model. The deadline
always assumes it (the conservative direction there), and the ledger shows the airtime at it
next to :data:`TYPICAL_CW`. [policy: PRESETS-PL section 2.1]"""

TYPICAL_CW: Final[int] = 7
"""The contention-window exponent a plan's airtime is judged at: ``getCWsize`` gives at most 7
below SNR 10 dB (RadioInterface.cpp:841-857). [policy: OPINION Q3.3 recommends 7 as the
default with 8 as the worst case; T3's measured LONG_FAST relay total for 13 sections, 18.3 s,
is below the unfactored model's 20.97 s, so no CW 8 spurious retransmits showed there]"""

CLIENT_OVERHEAD_SECONDS: Final[float] = 4.0
"""The deadline's allowance for the client's own overhead (``a``). A guess, to be measured on
a bench. [policy, uncalibrated: PRESETS-PL section 2.1]"""

SLOW_PRESETS: Final[frozenset[str]] = frozenset({"LONG_MODERATE", "LONG_SLOW"})
"""The presets whose deadline carries the retransmit timer and whose settle minimum is
longer. [measured: T3 found the formula too tight at 1 link on exactly these; PRESETS-PL
section 2.1 "Why R is needed"]"""

LATE_REPLY_GRACE_FACTOR: Final[int] = 2
"""A reply is still accepted up to this many deadlines after the request.
[policy: PRESETS-PL section 2.1; covers the 61.8 s LS1 outlier]"""

SETTLE_QUIET_PACKETS: Final[int] = 2
"""The channel must have been quiet for this many largest replies' airtimes.
[policy: PRESETS-PL section 2.2]"""

SETTLE_MIN_SECONDS: Final[float] = 25.0
"""Listen at least this long before the first request. [policy: PRESETS-PL section 2.2]"""

SETTLE_MIN_SLOW_PRESET_SECONDS: Final[float] = 45.0
"""Listen at least this long on :data:`SLOW_PRESETS`. [policy: PRESETS-PL section 2.2; 45-60 s
is the observed working value on LM and LS, T4 and T7]"""

SETTLE_MAX_SECONDS: Final[float] = 120.0
"""Give up waiting for a quiet channel after this long. [policy: PRESETS-PL section 2.2]"""

HOUR_SECONDS: Final[int] = 3600
"""Seconds in an hour."""

POLITE_RELAY_SHARE: Final[float] = 0.10
"""The share of a relay's legal duty-cycle hour that remote work may use; on EU_868 it is
36 s. Not a safety threshold. [policy: SIM-REVIEW section 2.2; OPINION Q3.1 and "unsafe" 4]"""


def _radio(preset: str) -> PresetRadio:
    radio = PRESET_RADIO.get(preset)
    if radio is None:
        raise ValueError(f"preset must be one of {sorted(PRESET_RADIO)}, got {preset!r}")
    return radio


def _check_bytes(name: str, value: int) -> None:
    if not 1 <= value <= MAX_LORA_PACKET_BYTES:
        raise ValueError(f"{name} must be 1..{MAX_LORA_PACKET_BYTES}, got {value}")


def _check_slot(slot: int) -> None:
    if slot < 1:
        raise ValueError(f"slot_ms must be at least 1, got {slot}")


def _check_cw(cw: int) -> None:
    if not CW_MIN <= cw <= CW_LIMIT:
        raise ValueError(f"cw must be {CW_MIN}..{CW_LIMIT}, got {cw}")


def symbol_seconds(preset: str) -> float:
    """Return a preset's symbol time, ``2**sf / bandwidth``.

    Args:
        preset: A key of :data:`PRESET_RADIO`.

    Returns:
        Seconds.

    Raises:
        ValueError: If the preset is unknown.
    """
    radio = _radio(preset)
    return (1 << radio.spreading_factor) / radio.bandwidth_hz


def low_data_rate_optimize(preset: str) -> bool:
    """Tell whether a preset runs low-data-rate optimisation (symbol time above 16 ms).

    Args:
        preset: A key of :data:`PRESET_RADIO`.

    Returns:
        ``True`` for the 125 kHz presets.

    Raises:
        ValueError: If the preset is unknown.
    """
    return symbol_seconds(preset) > LDRO_SYMBOL_SECONDS


def air_time_seconds(preset: str, payload_bytes: int) -> float:
    """Return the Semtech time on air: explicit header, CRC on, :data:`PREAMBLE_SYMBOLS`.

    ``n = 8 + max(ceil((8*PL - 4*SF + 28 + 16) / (4*(SF - 2*DE))) * CR, 0)`` and
    ``T = (PREAMBLE_SYMBOLS + 4.25 + n) * symbol_seconds``, where ``PL`` is the bytes on
    air including the 16 B header, ``DE`` is 1 with low-data-rate optimisation and ``CR`` is
    the coding-rate denominator.

    Args:
        preset: A key of :data:`PRESET_RADIO`.
        payload_bytes: The bytes on air, ``1..MAX_LORA_PACKET_BYTES``.

    Returns:
        Seconds.

    Raises:
        ValueError: If the preset is unknown or the size is out of range.
    """
    radio = _radio(preset)
    _check_bytes("payload_bytes", payload_bytes)
    sf = radio.spreading_factor
    de = 1 if low_data_rate_optimize(preset) else 0
    numerator = 8 * payload_bytes - 4 * sf + 28 + 16
    symbols = 8 + max(math.ceil(numerator / (4 * (sf - 2 * de))) * radio.coding_rate, 0)
    return (PREAMBLE_SYMBOLS + 4.25 + symbols) * symbol_seconds(preset)


def slot_ms(preset: str, cad_symbols: int) -> int:
    """Return the firmware's slot time, ``int(max(2.25, cad + 0.5) * Tsym_ms + 7.6)``.

    [source: ``computeSlotTimeMsec``, ``RadioInterface.cpp:1483``]

    Args:
        preset: A key of :data:`PRESET_RADIO`.
        cad_symbols: The CAD symbols the node scans (see
            :func:`~meshprovision.remote.firmware.cad_symbols`).

    Returns:
        Whole milliseconds.

    Raises:
        ValueError: If the preset is unknown or ``cad_symbols`` is below 1.
    """
    radio = _radio(preset)
    if cad_symbols < 1:
        raise ValueError(f"cad_symbols must be at least 1, got {cad_symbols}")
    symbol_ms = 1000 * (1 << radio.spreading_factor) / radio.bandwidth_hz
    return int(max(2.25, cad_symbols + 0.5) * symbol_ms + 7.6)


def retransmit_timer_seconds(preset: str, slot_ms: int) -> float:
    """Return T1 b3's model of ``getRetransmissionMsec`` on a quiet channel.

    ``2 * air(REQUEST_BYTES) + RETRANSMIT_SLOTS * slot + PROCESSING_SECONDS``. The firmware
    times the decoded size (``REQUEST_BYTES - PKC_OVERHEAD_BYTES``), which shortens the timer
    by ``2 * (air(54) - air(42))``; so this is exact for the model, approximate (long) for
    the firmware. [model: T1 b3]

    Args:
        preset: A key of :data:`PRESET_RADIO`.
        slot_ms: The node's slot time in milliseconds.

    Returns:
        Seconds.

    Raises:
        ValueError: If the preset is unknown or ``slot_ms`` is below 1.
    """
    _check_slot(slot_ms)
    return (
        2 * air_time_seconds(preset, REQUEST_BYTES)
        + RETRANSMIT_SLOTS * slot_ms / 1000
        + PROCESSING_SECONDS
    )


def deadline_seconds(
    preset: str,
    links: int,
    *,
    slot_ms: int,
    cw: int = WORST_CASE_CW,
    client_seconds: float = CLIENT_OVERHEAD_SECONDS,
    reply_bytes: int = MAX_REPLY_BYTES,
) -> float:
    """Return how long to wait for one reply (PRESETS-PL section 2.1's hard bound).

    ``a + L*(air(REQUEST_BYTES) + air(reply_bytes)) + slot*[2(L-1)*(RELAY_FIXED_BACKOFF_SLOTS
    + 2**cw) + ORIGIN_BACKOFF_SLOTS] + R``, where ``R`` is the retransmit timer for
    :data:`SLOW_PRESETS` and 0 otherwise.

    Args:
        preset: A key of :data:`PRESET_RADIO`.
        links: The links to the node, ``1..MAX_LINKS``.
        slot_ms: The node's slot time in milliseconds.
        cw: The contention-window exponent of the relays.
        client_seconds: The client's own overhead.
        reply_bytes: The reply's size on air.

    Returns:
        Seconds.

    Raises:
        ValueError: If an argument is out of range.
    """
    _radio(preset)
    if not 1 <= links <= MAX_LINKS:
        raise ValueError(f"links must be 1..{MAX_LINKS}, got {links}")
    _check_cw(cw)
    _check_slot(slot_ms)
    _check_bytes("reply_bytes", reply_bytes)
    backoff_slots = 2 * (links - 1) * (RELAY_FIXED_BACKOFF_SLOTS + (1 << cw)) + ORIGIN_BACKOFF_SLOTS
    retransmit = retransmit_timer_seconds(preset, slot_ms) if preset in SLOW_PRESETS else 0.0
    return (
        client_seconds
        + links * (air_time_seconds(preset, REQUEST_BYTES) + air_time_seconds(preset, reply_bytes))
        + backoff_slots * slot_ms / 1000
        + retransmit
    )


def late_reply_grace_seconds(deadline: float) -> float:
    """Return how long after the request a reply is still accepted.

    Args:
        deadline: The reply deadline, in seconds.

    Returns:
        :data:`LATE_REPLY_GRACE_FACTOR` times ``deadline``.
    """
    return LATE_REPLY_GRACE_FACTOR * deadline


def settle_rule(preset: str, *, reply_bytes: int = MAX_REPLY_BYTES) -> SettleRule:
    """Return how long to listen before the first request.

    ``quiet = SETTLE_QUIET_PACKETS * air(reply_bytes)``; ``min`` is
    :data:`SETTLE_MIN_SLOW_PRESET_SECONDS` on :data:`SLOW_PRESETS`, else
    :data:`SETTLE_MIN_SECONDS`; ``max`` is :data:`SETTLE_MAX_SECONDS`.

    Args:
        preset: A key of :data:`PRESET_RADIO`.
        reply_bytes: The largest reply's size on air.

    Returns:
        The rule.

    Raises:
        ValueError: If the preset is unknown or the size is out of range.
    """
    _check_bytes("reply_bytes", reply_bytes)
    slow = preset in SLOW_PRESETS
    return SettleRule(
        quiet_seconds=SETTLE_QUIET_PACKETS * air_time_seconds(preset, reply_bytes),
        min_seconds=SETTLE_MIN_SLOW_PRESET_SECONDS if slow else SETTLE_MIN_SECONDS,
        max_seconds=SETTLE_MAX_SECONDS,
    )


def spurious_retransmit_probability(slot_ms: int, cw: int) -> Fraction:
    """Return the chance that a relayed reply outlasts the sender's retransmit timer.

    T1 b3's model, exact for the model: ``P(O + B > RETRANSMIT_SLOTS + PROCESSING/slot)``
    for ``O ~ U{0..2**CW_MIN - 1}`` (0..7) and ``B = RELAY_FIXED_BACKOFF_SLOTS + U{0..2**cw
    - 1}``, compared in integer milliseconds: ``(o + 16 + b) * slot_ms > 56 * slot_ms +
    4500``. The firmware's timer is shorter by ``2 * (air(54) - air(42))`` (it times the
    decoded size), which raises the probability by 2-9 points on LONG_MODERATE and
    LONG_SLOW; the ledger uses the faithful variant,
    :func:`~meshprovision.remote.ledger.firmware_spurious_probability`. [model: T1 b3]

    Args:
        slot_ms: The node's slot time in milliseconds.
        cw: The contention-window exponent of the relays.

    Returns:
        The exact probability.

    Raises:
        ValueError: If ``slot_ms`` or ``cw`` is out of range.
    """
    _check_slot(slot_ms)
    _check_cw(cw)
    threshold = RETRANSMIT_SLOTS * slot_ms + round(PROCESSING_SECONDS * 1000)
    origins = 1 << CW_MIN
    backoffs = 1 << cw
    spurious = sum(
        1
        for o in range(origins)
        for b in range(backoffs)
        if (o + RELAY_FIXED_BACKOFF_SLOTS + b) * slot_ms > threshold
    )
    return Fraction(spurious, origins * backoffs)


def spurious_factor(slot_ms: int, cw: int) -> float:
    """Return ``1 + spurious_retransmit_probability`` (T1 d2's upper bound per hop).

    Args:
        slot_ms: The node's slot time in milliseconds.
        cw: The contention-window exponent of the relays.

    Returns:
        The multiplier for a relay's airtime cost.

    Raises:
        ValueError: If ``slot_ms`` or ``cw`` is out of range.
    """
    return float(1 + spurious_retransmit_probability(slot_ms, cw))


def diff_airtime_seconds(
    preset: str, reply_bytes: Sequence[int], *, request_bytes: int = REQUEST_BYTES
) -> float:
    """Return the airtime one relay spends on one diff: each request plus its reply, once.

    The caller applies :func:`spurious_factor`.

    Args:
        preset: A key of :data:`PRESET_RADIO`.
        reply_bytes: The on-air size of each section's reply.
        request_bytes: The on-air size of each request.

    Returns:
        Seconds.

    Raises:
        ValueError: If the preset is unknown or a size is out of range.
    """
    _check_bytes("request_bytes", request_bytes)
    request = air_time_seconds(preset, request_bytes)
    total = 0.0
    for size in reply_bytes:
        _check_bytes("reply_bytes", size)
        total += request + air_time_seconds(preset, size)
    return total


def unanswered_request_seconds(preset: str, attempts: int) -> float:
    """Return what the gateway sends for a request that never gets an answer.

    ``attempts * air(REQUEST_BYTES)`` (PRESETS-PL section 2.5).

    Args:
        preset: A key of :data:`PRESET_RADIO`.
        attempts: The gateway's transmissions, the first send included.

    Returns:
        Seconds.

    Raises:
        ValueError: If the preset is unknown or ``attempts`` is below 1.
    """
    if attempts < 1:
        raise ValueError(f"attempts must be at least 1, got {attempts}")
    return attempts * air_time_seconds(preset, REQUEST_BYTES)


def relay_budget_seconds(region: str) -> float | None:
    """Return the polite share of a relay's legal hour in ``region``.

    ``HOUR_SECONDS * duty_cycle / 100 * POLITE_RELAY_SHARE``.

    Args:
        region: A key of :data:`~meshprovision.lora_regions.REGION_BANDS`.

    Returns:
        Seconds, or ``None`` for an unknown region and for one without a legal limit
        (duty cycle 100), as :func:`~meshprovision.lora_regions.duty_cycle_limit` does.
    """
    band = REGION_BANDS.get(region)
    if band is None or band.duty_cycle >= 100:
        return None
    return HOUR_SECONDS * band.duty_cycle / 100 * POLITE_RELAY_SHARE


def diffs_per_hour(cost_seconds: float, budget_seconds: float) -> int:
    """Return how many diffs of ``cost_seconds`` fit in ``budget_seconds``.

    Args:
        cost_seconds: One diff's relay airtime, above 0.
        budget_seconds: The relay's budget, 0 or more.

    Returns:
        ``floor(budget / cost)``.

    Raises:
        ValueError: If ``cost_seconds`` is not above 0 or ``budget_seconds`` is negative.
    """
    if cost_seconds <= 0:
        raise ValueError(f"cost_seconds must be above 0, got {cost_seconds}")
    if budget_seconds < 0:
        raise ValueError(f"budget_seconds must be 0 or more, got {budget_seconds}")
    return math.floor(budget_seconds / cost_seconds)
