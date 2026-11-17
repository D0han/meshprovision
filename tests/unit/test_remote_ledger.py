"""The airtime ledger, against the plan's recomputed goldens.

The goldens were recomputed by two independent scripts that import nothing from
``meshprovision.remote``.

Float goldens are the plan's six-decimal values, compared with ``abs=5e-6``.
"""

from __future__ import annotations

from fractions import Fraction

import pytest

from meshprovision.remote.budget import (
    PRESET_RADIO,
    REQUEST_BYTES,
    air_time_seconds,
    slot_ms,
    spurious_retransmit_probability,
)
from meshprovision.remote.ledger import (
    DECODED_REQUEST_BYTES,
    WINDOW_SECONDS,
    Ledger,
    diff_ledger,
    firmware_retransmit_timer_seconds,
    firmware_spurious_factor,
    firmware_spurious_probability,
)

pytestmark = pytest.mark.unit

PRESETS = (
    "SHORT_FAST",
    "SHORT_SLOW",
    "MEDIUM_FAST",
    "MEDIUM_SLOW",
    "LONG_FAST",
    "LONG_MODERATE",
    "LONG_SLOW",
)

_TIMERS = {
    "SHORT_FAST": 5.099488,
    "SHORT_SLOW": 5.342496,
    "MEDIUM_FAST": 5.716512,
    "MEDIUM_SLOW": 6.556064,
    "LONG_FAST": 8.082208,
    "LONG_MODERATE": 12.583136,
    "LONG_SLOW": 19.749984,
}

_ZERO = Fraction(0)

# preset: (slot at 4 CAD symbols, CW 7, CW 8, slot at 2 CAD symbols, CW 7, CW 8)
_FAITHFUL = {
    "SHORT_FAST": (9, _ZERO, _ZERO, 8, _ZERO, _ZERO),
    "SHORT_SLOW": (12, _ZERO, _ZERO, 10, _ZERO, _ZERO),
    "MEDIUM_FAST": (16, _ZERO, _ZERO, 12, _ZERO, _ZERO),
    "MEDIUM_SLOW": (26, _ZERO, Fraction(99, 512), 17, _ZERO, _ZERO),
    "LONG_FAST": (44, _ZERO, Fraction(241, 512), 28, _ZERO, Fraction(129, 512)),
    "LONG_MODERATE": (
        81,
        Fraction(83, 256),
        Fraction(339, 512),
        48,
        Fraction(17, 256),
        Fraction(273, 512),
    ),
    "LONG_SLOW": (
        155,
        Fraction(137, 256),
        Fraction(393, 512),
        89,
        Fraction(105, 256),
        Fraction(361, 512),
    ),
}

_G1 = [91, 89]
_G2 = [91, 136, 73, 87, 83, 89, 77, 118, 255, 255, 255, 76, 255, 255, 255]
_FULL_2_8 = [91, 136, 73, 87, 83, 89, 77, 142, 118, 255, 255, 255, 76, 255, 255, 255]
_G4 = [91, 73]
_G7 = [91, 136, 73, 87, 83, 89, 77, 142, 118, 255, 255, 76, 255]

# id: (preset, replies, slot_ms, gateway attempts, then per CW (7, 8):
#      f, gateway, relay, relay at the largest replies, destination, fits, per window)
# and the CW-independent gateway_unanswered.
_GOLDENS = {
    "G1": ("LONG_FAST", _G1, 44, 3, 3.846144),
    "G2": ("LONG_FAST", _G2, 44, 5, 48.076800),
    "G3": ("LONG_MODERATE", _FULL_2_8, 81, 5, 162.856960),
    "G4": ("LONG_SLOW", _G4, 155, 5, 38.092800),
    "G5": ("MEDIUM_FAST", _FULL_2_8, 16, 5, 15.278080),
    "G6": ("LONG_MODERATE", _G1, 81, 5, 20.357120),
    "G7": ("LONG_FAST", _G7, 44, 5, 41.666560),
    "G8": ("MEDIUM_SLOW", _FULL_2_8, 26, 5, 27.279360),
}

_F = Fraction
# (id, cw): (f, gateway, relay, relay largest, destination, fits, per window)
_CHARGES = {
    ("G1", 7): (_F(1), 1.282048, 3.137536, 5.595136, 1.855488, True, 11),
    ("G2", 7): (_F(1), 9.615360, 30.986240, 41.963520, 21.370880, True, 1),
    ("G3", 7): (_F(339, 256), 43.131648, 150.830592, 211.232256, 107.698944, False, 0),
    ("G4", 7): (_F(393, 256), 11.695680, 28.220544, 55.585920, 16.524864, True, 1),
    ("G5", 7): (_F(1), 3.055616, 9.766912, 13.320192, 6.711296, True, 3),
    ("G6", 7): (_F(339, 256), 5.391456, 13.733568, 26.404032, 8.342112, True, 2),
    ("G7", 7): (_F(1), 8.333312, 24.530944, 36.368384, 16.197632, True, 1),
    ("G8", 7): (_F(1), 5.455872, 17.793024, 24.346624, 12.337152, True, 2),
    ("G1", 8): (_F(753, 512), 1.885512, 4.614384, 8.228784, 2.728872, True, 7),
    ("G2", 8): (_F(753, 512), 14.141340, 45.571560, 61.715880, 31.430220, False, 0),
    ("G3", 8): (_F(851, 512), 54.137216, 189.316864, 265.130752, 135.179648, False, 0),
    ("G4", 8): (_F(905, 512), 13.466400, 32.493120, 64.001600, 19.026720, True, 1),
    ("G5", 8): (_F(1), 3.055616, 9.766912, 13.320192, 6.711296, True, 3),
    ("G6", 8): (_F(851, 512), 6.767152, 17.237856, 33.141344, 10.470704, True, 2),
    ("G7", 8): (_F(753, 512), 12.255828, 36.077736, 53.487096, 23.821908, False, 0),
    ("G8", 8): (_F(611, 512), 6.510816, 21.233472, 29.054272, 14.722656, True, 1),
}


def _approx(value: float) -> object:
    return pytest.approx(value, abs=5e-6)


def test_window_is_the_firmware_rolling_hour() -> None:
    assert WINDOW_SECONDS == 3600


def test_decoded_request_size() -> None:
    assert DECODED_REQUEST_BYTES == 42


@pytest.mark.parametrize("preset", PRESETS)
def test_firmware_timer_matches_the_recomputed_values(preset: str) -> None:
    assert firmware_retransmit_timer_seconds(preset, slot_ms(preset, 4)) == _approx(_TIMERS[preset])


@pytest.mark.parametrize("preset", PRESETS)
@pytest.mark.parametrize(
    ("slot_column", "cad", "cw", "column"),
    [(0, 4, 7, 1), (0, 4, 8, 2), (3, 2, 7, 4), (3, 2, 8, 5)],
)
def test_firmware_spurious_probability_matches_the_table(
    preset: str, slot_column: int, cad: int, cw: int, column: int
) -> None:
    row = _FAITHFUL[preset]
    assert row[slot_column] == slot_ms(preset, cad)
    assert firmware_spurious_probability(preset, row[slot_column], cw) == row[column]


@pytest.mark.parametrize("preset", PRESETS)
@pytest.mark.parametrize("cad", [2, 4])
@pytest.mark.parametrize("cw", range(3, 12))
def test_firmware_spurious_probability_is_never_below_the_model(
    preset: str, cad: int, cw: int
) -> None:
    slot = slot_ms(preset, cad)

    assert firmware_spurious_probability(preset, slot, cw) >= spurious_retransmit_probability(
        slot, cw
    )


@pytest.mark.parametrize(
    ("preset", "slot", "cw"),
    [
        pytest.param("LONG_FAST", 0, 7, id="slot-0"),
        pytest.param("LONG_FAST", 44, 2, id="cw-2"),
        pytest.param("LONG_FAST", 44, 12, id="cw-12"),
        pytest.param("LONG_TURBO", 44, 7, id="unknown-preset"),
    ],
)
def test_firmware_spurious_rejects_bad_input(preset: str, slot: int, cw: int) -> None:
    with pytest.raises(ValueError):
        firmware_spurious_probability(preset, slot, cw)


def test_firmware_timer_rejects_bad_input() -> None:
    with pytest.raises(ValueError, match="slot_ms"):
        firmware_retransmit_timer_seconds("LONG_FAST", 0)


def test_firmware_spurious_factor_is_one_plus_the_probability() -> None:
    assert firmware_spurious_factor("LONG_FAST", 44, 8) == 753 / 512
    assert firmware_spurious_factor("LONG_FAST", 44, 7) == 1.0


@pytest.mark.parametrize(("golden", "cw"), list(_CHARGES), ids=[f"{g}-cw{c}" for g, c in _CHARGES])
def test_diff_ledger_goldens(golden: str, cw: int) -> None:
    preset, replies, slot, attempts, unanswered = _GOLDENS[golden]
    factor, gateway, relay, largest, destination, fits, per_window = _CHARGES[(golden, cw)]

    ledger = diff_ledger(preset, "EU_868", replies, slot_ms=slot, cw=cw, gateway_attempts=attempts)

    assert ledger.cw == cw
    assert ledger.spurious_factor == float(factor)
    assert ledger.gateway_seconds == _approx(gateway)
    assert ledger.gateway_unanswered_seconds == _approx(unanswered)
    assert ledger.relay_seconds == _approx(relay)
    assert ledger.relay_largest_replies_seconds == _approx(largest)
    assert ledger.destination_seconds == _approx(destination)
    assert ledger.budget_seconds == 36.0
    assert ledger.fits is fits
    assert ledger.per_window == per_window


def test_g1_worked_example() -> None:
    """The 2.5 numbers as a reading aid: LONG_FAST at 44 ms, CW 7, two replies."""
    request = air_time_seconds("LONG_FAST", REQUEST_BYTES)
    assert request == _approx(0.641024)
    assert air_time_seconds("LONG_FAST", 91) == _approx(0.927744)
    assert air_time_seconds("LONG_FAST", 255) == _approx(2.156544)

    ledger = diff_ledger("LONG_FAST", "EU_868", _G1, slot_ms=44, cw=7, gateway_attempts=3)

    assert ledger.gateway_seconds == _approx(2 * request)
    assert ledger.gateway_unanswered_seconds == _approx(2 * 3 * request)
    assert ledger.relay_seconds == _approx(2 * request + 2 * 0.927744)
    assert ledger.destination_seconds == _approx(2 * 0.927744)
    assert ledger.relay_largest_replies_seconds == _approx(2 * (request + 2.156544))
    assert ledger.budget_seconds == 3600 * 10 / 100 * 0.10
    assert ledger.per_window == 36 // 3.137536 == 11


@pytest.mark.parametrize("preset", PRESETS)
@pytest.mark.parametrize("cw", [7, 8])
@pytest.mark.parametrize("replies", [[255], [73] * 13, _G1])
def test_relay_pays_the_most_when_every_request_is_answered(
    preset: str, cw: int, replies: list[int]
) -> None:
    ledger = diff_ledger(
        preset, "EU_868", replies, slot_ms=slot_ms(preset, 4), cw=cw, gateway_attempts=5
    )

    assert ledger.relay_seconds >= ledger.destination_seconds
    assert ledger.relay_seconds >= ledger.gateway_seconds


def test_unanswered_gateway_may_exceed_the_relay() -> None:
    """The gateway is reported, not judged: G4 pins it so nobody "fixes" the ledger later."""
    ledger = diff_ledger("LONG_SLOW", "EU_868", _G4, slot_ms=155, cw=7, gateway_attempts=5)

    assert ledger.gateway_unanswered_seconds == _approx(38.0928)
    assert ledger.relay_seconds == _approx(28.220544)
    assert ledger.gateway_unanswered_seconds > ledger.relay_seconds
    assert ledger.fits is True


@pytest.mark.parametrize(
    ("relay", "fits", "per_window"),
    [(36.0, True, 1), (36.000001, False, 0)],
)
def test_fits_boundary(relay: float, fits: bool, per_window: int) -> None:
    ledger = Ledger("LONG_FAST", "EU_868", 7, 36.0, 1.0, 1.0, 1.0, relay, relay, 1.0)

    assert ledger.fits is fits
    assert ledger.per_window == per_window


def test_no_duty_limit_region_has_no_budget() -> None:
    ledger = diff_ledger("LONG_FAST", "US", [91], slot_ms=44, cw=7, gateway_attempts=5)

    assert (ledger.budget_seconds, ledger.fits, ledger.per_window) == (None, None, None)


@pytest.mark.parametrize(
    ("region", "replies", "attempts"),
    [
        pytest.param("EU_868", [], 5, id="empty"),
        pytest.param("MARS", [91], 5, id="unknown-region"),
        pytest.param("EU_868", [91], 0, id="no-attempts"),
        pytest.param("EU_868", [0], 5, id="reply-0"),
        pytest.param("EU_868", [256], 5, id="reply-256"),
    ],
)
def test_diff_ledger_rejects_bad_input(region: str, replies: list[int], attempts: int) -> None:
    with pytest.raises(ValueError):
        diff_ledger("LONG_FAST", region, replies, slot_ms=44, cw=7, gateway_attempts=attempts)


def test_unanswered_charge_has_no_multiplier() -> None:
    ledger = diff_ledger("LONG_FAST", "EU_868", _G1, slot_ms=44, cw=8, gateway_attempts=5)

    assert ledger.spurious_factor > 1
    assert ledger.gateway_unanswered_seconds == 2 * 5 * air_time_seconds("LONG_FAST", 54)


def test_the_presets_are_the_budget_presets() -> None:
    assert set(PRESETS) == set(PRESET_RADIO)
