"""What one planned remote diff costs in airtime, per transmitter, in one rolling hour.

Three transmitters pay:

- the gateway sends every request;
- a relay that passes the diff on sends every request and every reply once;
- the destination sends every reply.

Each charge is raised by the chance of a spurious retransmission (the firmware-faithful
variant of T1 b3's race, defined here) and compared with the polite share of
:func:`~meshprovision.remote.budget.relay_budget_seconds`. The firmware's duty-cycle limit
counts a rolling hour, so the ledger judges a plan as if all of it falls in one such hour; a
run longer than an hour costs less per hour than that.

Pure: nothing here talks to a device, reads a file or reads the clock. Every constant ends
with its class in brackets, as in :mod:`~meshprovision.remote.budget`.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from fractions import Fraction
from typing import Final

from meshprovision.lora_regions import REGION_BANDS
from meshprovision.remote.budget import (
    CW_MIN,
    HOUR_SECONDS,
    MAX_REPLY_BYTES,
    PKC_OVERHEAD_BYTES,
    PROCESSING_SECONDS,
    RELAY_FIXED_BACKOFF_SLOTS,
    REQUEST_BYTES,
    RETRANSMIT_SLOTS,
    _check_cw,
    _check_slot,
    air_time_seconds,
    diff_airtime_seconds,
    diffs_per_hour,
    relay_budget_seconds,
    unanswered_request_seconds,
)

__all__ = [
    "DECODED_REQUEST_BYTES",
    "WINDOW_SECONDS",
    "Ledger",
    "diff_ledger",
    "firmware_retransmit_timer_seconds",
    "firmware_spurious_factor",
    "firmware_spurious_probability",
]

WINDOW_SECONDS: Final[int] = HOUR_SECONDS
"""The window the ledger judges a plan in: a rolling hour, not an hour of the clock.
[source: 2.8.3 ``airtime.cpp:60-63`` ``getPeriodUtilHour`` files TX time in 60 one-minute
buckets and ``:215-226`` ``utilizationTXPercent`` sums all 60, the current, partial minute
included, so the window is 59 to 60 minutes; ``Router.cpp:495-498`` stops a send above the
duty cycle on that sum. An hour-of-day ledger would let two hours' shares land within one
rolling hour]"""

DECODED_REQUEST_BYTES: Final[int] = REQUEST_BYTES - PKC_OVERHEAD_BYTES
"""The size the firmware times a pending request's retransmission on (42): the decoded Data
plus the header, without the PKC overhead. [measured: REQUEST_BYTES, A1; source: the PKC
overhead, ``RadioInterface.h:23``; the timer on the decoded size, ``RadioInterface.cpp:814-817``
and ``ReliableRouter.cpp:32`` (copied before encryption); PLAN-REVIEW-59 M1]"""

_MICROSECONDS: Final[int] = 1_000_000


def _us(seconds: float) -> int:
    """Return whole microseconds (every airtime, and so every timer here, is a whole number)."""
    return round(seconds * _MICROSECONDS)


def firmware_retransmit_timer_seconds(preset: str, slot_ms: int) -> float:
    """Return the firmware's retransmit timer for a pending request on a quiet channel.

    ``2 * air(DECODED_REQUEST_BYTES) + RETRANSMIT_SLOTS * slot + PROCESSING_SECONDS``.
    :func:`~meshprovision.remote.budget.retransmit_timer_seconds` (T1's model, 54 B) is
    longer and stays the deadline's ``R`` term, the conservative direction there.
    [source: ``RadioInterface.cpp:812-826`` ``getRetransmissionMsec`` on a quiet channel,
    timed on the decoded size]

    Args:
        preset: A key of :data:`~meshprovision.remote.budget.PRESET_RADIO`.
        slot_ms: The node's slot time in milliseconds.

    Returns:
        Seconds.

    Raises:
        ValueError: If the preset is unknown or ``slot_ms`` is below 1.
    """
    _check_slot(slot_ms)
    return (
        2 * air_time_seconds(preset, DECODED_REQUEST_BYTES)
        + RETRANSMIT_SLOTS * slot_ms / 1000
        + PROCESSING_SECONDS
    )


def firmware_spurious_probability(preset: str, slot_ms: int, cw: int) -> Fraction:
    """Return the chance that the first relay's rebroadcast comes after the sender's timer.

    The rebroadcast is the sender's implicit acknowledgement. The sender waits
    ``O ~ U{0..2**CW_MIN - 1}`` slots and sends ``air(REQUEST_BYTES)``; the relay waits
    ``B = RELAY_FIXED_BACKOFF_SLOTS + U{0..2**cw - 1}`` slots and sends the same. The
    retransmission is spurious when ``(O + B) * slot + 2 * air(REQUEST_BYTES)`` is longer
    than :func:`firmware_retransmit_timer_seconds`. Compared in integer microseconds, so
    the result is exact. [source: the firmware's timer and backoffs,
    ``RadioInterface.cpp:829-838`` (the sender's) and ``:871-889`` (the relay's);
    the race is T1 b3's, with the timer the firmware
    computes. Exact for a quiet channel]

    Args:
        preset: A key of :data:`~meshprovision.remote.budget.PRESET_RADIO`.
        slot_ms: The node's slot time in milliseconds.
        cw: The contention-window exponent of the relays.

    Returns:
        The exact probability.

    Raises:
        ValueError: If ``slot_ms`` or ``cw`` is out of range or the preset is unknown.
    """
    _check_slot(slot_ms)
    _check_cw(cw)
    threshold_us = _us(firmware_retransmit_timer_seconds(preset, slot_ms)) - 2 * _us(
        air_time_seconds(preset, REQUEST_BYTES)
    )
    spurious = sum(
        1
        for o in range(1 << CW_MIN)
        for b in range(1 << cw)
        if (o + RELAY_FIXED_BACKOFF_SLOTS + b) * slot_ms * 1000 > threshold_us
    )
    return Fraction(spurious, (1 << CW_MIN) * (1 << cw))


def firmware_spurious_factor(preset: str, slot_ms: int, cw: int) -> float:
    """Return ``1 + firmware_spurious_probability`` (T1 d2's per-hop upper bound).

    Args:
        preset: A key of :data:`~meshprovision.remote.budget.PRESET_RADIO`.
        slot_ms: The node's slot time in milliseconds.
        cw: The contention-window exponent of the relays.

    Returns:
        The multiplier for a transmitter's airtime.

    Raises:
        ValueError: If ``slot_ms`` or ``cw`` is out of range or the preset is unknown.
    """
    return float(1 + firmware_spurious_probability(preset, slot_ms, cw))


@dataclass(frozen=True, slots=True)
class Ledger:
    """One planned diff's airtime, per transmitter, in one rolling window.

    Attributes:
        preset: The modem preset.
        region: The region.
        cw: The contention-window exponent the spurious factor was taken at.
        budget_seconds: The polite share of one relay's window, or ``None`` when the
            region has no duty-cycle limit.
        spurious_factor: The multiplier applied to every charge except
            :attr:`gateway_unanswered_seconds`.
        gateway_seconds: What the gateway sends when every request is answered.
        gateway_unanswered_seconds: What the gateway sends when no request is answered:
            every attempt of every request, no multiplier (the attempts are the retransmits).
        relay_seconds: What one relay sends: each request and each reply once.
        relay_largest_replies_seconds: :attr:`relay_seconds` if every reply had
            :data:`~meshprovision.remote.budget.MAX_REPLY_BYTES`.
        destination_seconds: What the destination sends: each reply.
    """

    preset: str
    region: str
    cw: int
    budget_seconds: float | None
    spurious_factor: float
    gateway_seconds: float
    gateway_unanswered_seconds: float
    relay_seconds: float
    relay_largest_replies_seconds: float
    destination_seconds: float

    @property
    def fits(self) -> bool | None:
        """Whether one relay's charge is within the polite share.

        The share protects relays, which are often other people's nodes; the gateway's own
        airtime is reported but not judged (its firmware stops it at its own limit), and
        when every request is answered a relay pays more than the gateway or the
        destination.

        Returns:
            ``None`` when the region has no budget.
        """
        if self.budget_seconds is None:
            return None
        return self.relay_seconds <= self.budget_seconds

    @property
    def per_window(self) -> int | None:
        """How many such diffs one relay's share allows per window, or ``None`` without a budget."""
        if self.budget_seconds is None:
            return None
        return diffs_per_hour(self.relay_seconds, self.budget_seconds)


def diff_ledger(
    preset: str,
    region: str,
    reply_bytes: Sequence[int],
    *,
    slot_ms: int,
    cw: int,
    gateway_attempts: int,
) -> Ledger:
    """Return the ledger of a diff whose requests are answered by replies of these sizes.

    ``cw`` is required; there is no default exponent anywhere in the ledger.
    [model: T1 d2 applies the per-hop factor to every transmitter. Checked against 2.8.3: the
    destination's reply inherits ``want_ack`` (MeshModule.cpp:272) and so retransmits; a
    relay retransmits a relayed unicast only with a next hop set (NextHopRouter.cpp:122-128)
    and drops an origin's duplicate (:117, :138), so the relay's factor is an upper bound,
    exact for 2.8 with a learnt route.]

    Args:
        preset: A key of :data:`~meshprovision.remote.budget.PRESET_RADIO`.
        region: A key of :data:`~meshprovision.lora_regions.REGION_BANDS`.
        reply_bytes: The on-air size of each request's reply; one request per entry.
        slot_ms: The relays' slot time in milliseconds.
        cw: The contention-window exponent of the relays.
        gateway_attempts: The gateway's transmissions per unanswered request.

    Returns:
        The ledger.

    Raises:
        ValueError: If ``reply_bytes`` is empty, the region is unknown, or another
            argument is out of range.
    """
    if not reply_bytes:
        raise ValueError("a diff has at least one request")
    if region not in REGION_BANDS:
        raise ValueError(f"region must be one of the known regions, got {region!r}")
    count = len(reply_bytes)
    factor = firmware_spurious_factor(preset, slot_ms, cw)
    request_air = air_time_seconds(preset, REQUEST_BYTES)
    reply_air = sum(air_time_seconds(preset, size) for size in reply_bytes)
    return Ledger(
        preset=preset,
        region=region,
        cw=cw,
        budget_seconds=relay_budget_seconds(region),
        spurious_factor=factor,
        gateway_seconds=count * request_air * factor,
        gateway_unanswered_seconds=count * unanswered_request_seconds(preset, gateway_attempts),
        relay_seconds=diff_airtime_seconds(preset, reply_bytes) * factor,
        relay_largest_replies_seconds=(
            diff_airtime_seconds(preset, (MAX_REPLY_BYTES,) * count) * factor
        ),
        destination_seconds=reply_air * factor,
    )
