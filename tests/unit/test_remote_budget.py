"""Airtime, slot, deadline and relay-budget arithmetic, against the simulator documents' tables.

Tolerances: ``abs=0.005`` for seconds given to two decimals, ``abs=0.05`` ms for ms values,
``abs=0.05`` against T1's one-decimal values below 100 s and ``abs=0.5`` at or above 100 s.
"""

from __future__ import annotations

import inspect
from fractions import Fraction
from typing import Any

import pytest

from meshprovision.health.rules import PRESET_AIRTIME_MS
from meshprovision.lora_regions import frequency_slot_count
from meshprovision.remote import budget
from meshprovision.remote.budget import (
    MAX_REPLY_BYTES,
    MEASURED_TEMPLATE_REPLY_BYTES,
    PRESET_RADIO,
    SLOW_PRESETS,
    T1_REPLY_BYTES,
    PresetRadio,
    air_time_seconds,
    deadline_seconds,
    diff_airtime_seconds,
    diffs_per_hour,
    late_reply_grace_seconds,
    low_data_rate_optimize,
    relay_budget_seconds,
    retransmit_timer_seconds,
    settle_rule,
    slot_ms,
    spurious_factor,
    spurious_retransmit_probability,
    unanswered_request_seconds,
)
from meshprovision.remote.firmware import RadioChip, cad_symbols, firmware_traits

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

# Time on air in ms for 40, 42, 54, 56, 243 and 255 B (hardware formula).
_AIR_BYTES = (40, 42, 54, 56, 243, 255)
_AIR_MS = {
    "SHORT_FAST": (45.2, 47.7, 55.4, 58.0, 193.7, 203.9),
    "SHORT_SLOW": (85.2, 85.2, 100.6, 105.7, 346.4, 361.7),
    "MEDIUM_FAST": (160.3, 160.3, 191.0, 191.0, 621.1, 641.5),
    "MEDIUM_SLOW": (300.0, 300.0, 341.0, 361.5, 1119.2, 1180.7),
    "LONG_FAST": (559.1, 559.1, 641.0, 682.0, 2074.6, 2156.5),
    "LONG_MODERATE": (1642.5, 1773.6, 2035.7, 2166.8, 7540.7, 7934.0),
    "LONG_SLOW": (3022.8, 3285.0, 3809.3, 4071.4, 13770.8, 14295.0),
}
# Slot in ms: 2.8 on an SX126x (4 CAD symbols) and RF95 / 2.6 / 2.7 (2 CAD symbols).
_SLOTS = {
    "SHORT_FAST": (9, 8),
    "SHORT_SLOW": (12, 10),
    "MEDIUM_FAST": (16, 12),
    "MEDIUM_SLOW": (26, 17),
    "LONG_FAST": (44, 28),
    "LONG_MODERATE": (81, 48),
    "LONG_SLOW": (155, 89),
}
# T1 model retransmit timer in s, at the cad-4 and the cad-2 slot.
_TIMERS = {
    "SHORT_FAST": (5.11, 5.06),
    "SHORT_SLOW": (5.37, 5.26),
    "MEDIUM_FAST": (5.78, 5.55),
    "MEDIUM_SLOW": (6.64, 6.13),
    "LONG_FAST": (8.25, 7.35),
    "LONG_MODERATE": (13.11, 11.26),
    "LONG_SLOW": (20.80, 17.10),
}
# Deadline in s for 1..4 links at the cad-4 slot, CW 8, a = 4: at 255 B, then at 243 B.
_DEADLINE_255 = {
    "SHORT_FAST": (4.39, 9.54, 14.70, 19.85),
    "SHORT_SLOW": (4.63, 11.62, 18.61, 25.60),
    "MEDIUM_FAST": (5.06, 14.59, 24.13, 33.67),
    "MEDIUM_SLOW": (5.89, 21.55, 37.22, 52.88),
    "LONG_FAST": (7.41, 34.15, 60.88, 87.61),
    "LONG_MODERATE": (28.21, 82.24, 136.28, 190.31),
    "LONG_SLOW": (45.07, 147.50, 249.92, 352.35),
}
_DEADLINE_243 = {
    "SHORT_FAST": (4.38, 9.52, 14.67, 19.81),
    "SHORT_SLOW": (4.61, 11.59, 18.56, 25.54),
    "MEDIUM_FAST": (5.04, 14.55, 24.07, 33.58),
    "MEDIUM_SLOW": (5.82, 21.43, 37.03, 52.64),
    "LONG_FAST": (7.33, 33.98, 60.63, 87.29),
    "LONG_MODERATE": (27.82, 81.46, 135.10, 188.74),
    "LONG_SLOW": (44.55, 146.45, 248.35, 350.25),
}
# T1 b4 "hard" rows: (label, preset, cad, cw, 243 B values, 255 B values), 1..5 links, R subtracted.
_HARD_ROWS = (
    (
        "LF-sx126x-cw7",
        "LONG_FAST",
        4,
        7,
        (7.33, 22.72, 38.11, 53.49, 68.88),
        (7.41, 22.88, 38.35, 53.82, 69.29),
    ),
    (
        "LF-cad2-cw8",
        "LONG_FAST",
        2,
        8,
        (7.11, 25.06, 43.00, 60.95, 78.90),
        (7.19, 25.22, 43.25, 61.28, 79.31),
    ),
    (
        "MS-cad2-cw7",
        "MEDIUM_SLOW",
        2,
        7,
        (5.70, 12.05, 18.41, 24.77, 31.12),
        (5.76, 12.18, 18.59, 25.01, 31.43),
    ),
    (
        "LM-cad2-cw7",
        "LONG_MODERATE",
        2,
        7,
        (14.25, 37.65, 61.05, 84.45, 107.85),
        (14.64, 38.44, 62.23, 86.02, 109.82),
    ),
    (
        "LS-sx126x-cw7",
        "LONG_SLOW",
        4,
        7,
        (23.75, 85.97, 148.19, 210.41, 272.63),
        (24.27, 87.02, 149.76, 212.51, 275.25),
    ),
)
# Spurious-retransmit probability: preset -> (cad-4 CW 7, cad-4 CW 8, cad-2 CW 7, cad-2 CW 8).
_SPURIOUS = {
    "SHORT_FAST": (Fraction(0),) * 4,
    "SHORT_SLOW": (Fraction(0),) * 4,
    "MEDIUM_FAST": (Fraction(0),) * 4,
    "MEDIUM_SLOW": (Fraction(0), Fraction(91, 512), Fraction(0), Fraction(0)),
    "LONG_FAST": (Fraction(0), Fraction(233, 512), Fraction(0), Fraction(117, 512)),
    "LONG_MODERATE": (Fraction(71, 256), Fraction(327, 512), Fraction(1, 1024), Fraction(251, 512)),
    "LONG_SLOW": (Fraction(123, 256), Fraction(379, 512), Fraction(81, 256), Fraction(337, 512)),
}
_B_BASIS_REPLIES = (76, 106, 86, 86, 66, 76, 56, 196, 56, 176, 56, 76, 116)
# Per-diff relay airtime in s: A-measured, B-basis (56 B requests), max-size (13 x 243 B).
_DIFF_AIRTIME = {
    "SHORT_FAST": (1.86, 1.88, 3.24),
    "SHORT_SLOW": (3.35, 3.38, 5.81),
    "MEDIUM_FAST": (6.19, 6.12, 10.56),
    "MEDIUM_SLOW": (11.22, 11.45, 18.98),
    "LONG_FAST": (20.97, 21.25, 35.30),
    "LONG_MODERATE": (70.10, 70.75, 124.49),
    "LONG_SLOW": (129.19, 132.07, 228.54),
}
_MAX_SIZE_255 = {
    "SHORT_FAST": 3.37,
    "SHORT_SLOW": 6.01,
    "MEDIUM_FAST": 10.82,
    "MEDIUM_SLOW": 19.78,
    "LONG_FAST": 36.37,
    "LONG_MODERATE": 129.61,
    "LONG_SLOW": 235.36,
}
# Settle (quiet, min, max) in s: at 255 B, then at 243 B.
_SETTLE_255 = {
    "SHORT_FAST": (0.408, 25, 120),
    "MEDIUM_SLOW": (2.361, 25, 120),
    "LONG_FAST": (4.313, 25, 120),
    "LONG_MODERATE": (15.868, 45, 120),
    "LONG_SLOW": (28.590, 45, 120),
}
_SETTLE_243 = {
    "SHORT_FAST": (0.387, 25, 120),
    "MEDIUM_SLOW": (2.238, 25, 120),
    "LONG_FAST": (4.149, 25, 120),
    "LONG_MODERATE": (15.081, 45, 120),
    "LONG_SLOW": (27.542, 45, 120),
}


def _preset_cells(table: dict[str, tuple[float, ...]]) -> list[Any]:
    return [
        pytest.param(preset, links, value, id=f"{preset}-{links}")
        for preset, values in table.items()
        for links, value in enumerate(values, start=1)
    ]


def test_the_preset_radio_table() -> None:
    assert dict(PRESET_RADIO) == {
        "SHORT_FAST": PresetRadio(250_000, 7, 5),
        "SHORT_SLOW": PresetRadio(250_000, 8, 5),
        "MEDIUM_FAST": PresetRadio(250_000, 9, 5),
        "MEDIUM_SLOW": PresetRadio(250_000, 10, 5),
        "LONG_FAST": PresetRadio(250_000, 11, 5),
        "LONG_MODERATE": PresetRadio(125_000, 11, 8),
        "LONG_SLOW": PresetRadio(125_000, 12, 8),
    }
    for preset, radio in PRESET_RADIO.items():
        expected = 2 if radio.bandwidth_hz == 125_000 else 1
        assert frequency_slot_count("EU_868", preset, firmware_2_8=True) == expected


def test_low_data_rate_optimize_only_on_125_khz() -> None:
    assert {p for p in PRESETS if low_data_rate_optimize(p)} == {"LONG_MODERATE", "LONG_SLOW"}


@pytest.mark.parametrize("preset", PRESETS)
@pytest.mark.parametrize("column", range(len(_AIR_BYTES)))
def test_air_time_matches_the_hardware_table(preset: str, column: int) -> None:
    got = air_time_seconds(preset, _AIR_BYTES[column]) * 1000

    assert got == pytest.approx(_AIR_MS[preset][column], abs=0.05)


def test_the_byte_constants_follow_from_the_firmware_limits() -> None:
    assert budget.MAX_PKC_DATA_BYTES == 227
    assert MAX_REPLY_BYTES == 255 == budget.MAX_LORA_PACKET_BYTES
    assert T1_REPLY_BYTES == budget.MAX_PKC_DATA_BYTES + budget.HEADER_BYTES == 243
    assert budget.REQUEST_BYTES == 54


def test_air_time_agrees_with_the_health_airtime_table() -> None:
    for preset in PRESETS:
        assert abs(air_time_seconds(preset, 40) * 1000 - PRESET_AIRTIME_MS[preset]) <= 0.5


@pytest.mark.parametrize(
    ("preset", "size"), [("SHORT_TURBO", 54), ("LONG_FAST", 0), ("LONG_FAST", 256)]
)
def test_air_time_rejects_bad_input(preset: str, size: int) -> None:
    with pytest.raises(ValueError, match=r"preset|payload_bytes"):
        air_time_seconds(preset, size)


@pytest.mark.parametrize("preset", PRESETS)
@pytest.mark.parametrize(("cad", "column"), [(4, 0), (2, 1)])
def test_slot_matches_the_firmware(preset: str, cad: int, column: int) -> None:
    assert slot_ms(preset, cad) == _SLOTS[preset][column]


@pytest.mark.parametrize(
    ("preset", "cad"), [("LONG_FAST", 0), ("LONG_FAST", -1), ("SHORT_TURBO", 4)]
)
def test_slot_rejects_bad_input(preset: str, cad: int) -> None:
    with pytest.raises(ValueError, match=r"cad_symbols|preset"):
        slot_ms(preset, cad)


def test_slot_from_traits_gives_both_slot_classes() -> None:
    new = firmware_traits("2.8.3")
    old = firmware_traits("2.7.26")

    assert slot_ms("LONG_FAST", cad_symbols(new, RadioChip.SX126X)) == 44
    assert slot_ms("LONG_FAST", cad_symbols(new, RadioChip.RF95)) == 28
    assert slot_ms("LONG_FAST", cad_symbols(old, RadioChip.SX126X)) == 28
    assert slot_ms("LONG_FAST", cad_symbols(firmware_traits("garbage"), RadioChip.UNKNOWN)) == 44


@pytest.mark.parametrize("preset", PRESETS)
@pytest.mark.parametrize("column", [0, 1])
def test_retransmit_timer(preset: str, column: int) -> None:
    timer = retransmit_timer_seconds(preset, _SLOTS[preset][column])

    assert timer == pytest.approx(_TIMERS[preset][column], abs=0.005)


@pytest.mark.parametrize(("preset", "links", "value"), _preset_cells(_DEADLINE_255))
def test_deadline_at_the_default_reply(preset: str, links: int, value: float) -> None:
    assert deadline_seconds(preset, links, slot_ms=_SLOTS[preset][0]) == pytest.approx(
        value, abs=0.005
    )


@pytest.mark.parametrize(("preset", "links", "value"), _preset_cells(_DEADLINE_243))
def test_deadline_matches_presets_pl_2_1(preset: str, links: int, value: float) -> None:
    got = deadline_seconds(preset, links, slot_ms=_SLOTS[preset][0], reply_bytes=T1_REPLY_BYTES)

    assert got == pytest.approx(value, abs=0.005)


def _without_retransmit(preset: str, links: int, cad: int, cw: int, reply_bytes: int) -> float:
    slot = slot_ms(preset, cad)
    value = deadline_seconds(preset, links, slot_ms=slot, cw=cw, reply_bytes=reply_bytes)
    return value - (retransmit_timer_seconds(preset, slot) if preset in SLOW_PRESETS else 0.0)


@pytest.mark.parametrize(("label", "preset", "cad", "cw", "t1", "default"), _HARD_ROWS)
def test_deadline_matches_t1_hard_rows(
    label: str, preset: str, cad: int, cw: int, t1: tuple[float, ...], default: tuple[float, ...]
) -> None:
    got = [_without_retransmit(preset, n, cad, cw, T1_REPLY_BYTES) for n in range(1, 6)]

    assert got == pytest.approx(t1, abs=0.005), label


@pytest.mark.parametrize(("label", "preset", "cad", "cw", "t1", "default"), _HARD_ROWS)
def test_deadline_hard_rows_at_the_default_reply(
    label: str, preset: str, cad: int, cw: int, t1: tuple[float, ...], default: tuple[float, ...]
) -> None:
    got = [_without_retransmit(preset, n, cad, cw, MAX_REPLY_BYTES) for n in range(1, 6)]

    assert got == pytest.approx(default, abs=0.005), label


@pytest.mark.parametrize("preset", PRESETS)
def test_deadline_grows_with_links_cw_and_slot(preset: str) -> None:
    slot = _SLOTS[preset][0]

    def deadline(links: int, **kwargs: int) -> float:
        return deadline_seconds(preset, links, **{"slot_ms": slot, **kwargs})

    for links in range(1, 7):
        assert deadline(links + 1) > deadline(links)
    assert deadline(1, cw=8) == deadline(1, cw=7)
    for links in range(2, 8):
        assert deadline(links, cw=8) > deadline(links, cw=7)
    assert deadline(3, slot_ms=slot + 1) > deadline(3)
    assert deadline(3, reply_bytes=255) > deadline(3, reply_bytes=243)


def test_deadline_covers_the_simulator_means() -> None:
    """The bound must exceed the means of the T3 runs (RF-aware, real 2.8.3 firmware).

    These are simulator means, not hardware; hardware will be slower. This is not a
    calibration, only a check that the bound is not below what the simulator saw.
    """
    means = {
        "LONG_FAST": (2.7, 12.0, 23.6, 30.1),
        "LONG_MODERATE": (11.1, 28.5, 43.6),
        "LONG_SLOW": (25.0, None, 77.3),
        "MEDIUM_SLOW": (1.7, None, 12.9),
    }
    for preset, by_links in means.items():
        for links, mean in enumerate(by_links, start=1):
            if mean is not None:
                assert deadline_seconds(preset, links, slot_ms=_SLOTS[preset][0]) > mean


@pytest.mark.parametrize(
    "kwargs",
    [
        {"links": 0},
        {"links": 8},
        {"cw": 2},
        {"cw": 12},
        {"slot_ms": 0},
        {"reply_bytes": 0},
        {"reply_bytes": 256},
    ],
)
def test_deadline_rejects_bad_input(kwargs: dict[str, int]) -> None:
    args = {"links": 2, "slot_ms": 44, **kwargs}

    with pytest.raises(ValueError, match=r"links|cw|slot_ms|reply_bytes"):
        deadline_seconds("LONG_FAST", **args)


def test_late_reply_grace_is_twice_the_deadline() -> None:
    assert late_reply_grace_seconds(30.0) == 60.0


@pytest.mark.parametrize("preset", PRESETS)
@pytest.mark.parametrize(("column", "cad", "cw"), [(0, 4, 7), (1, 4, 8), (2, 2, 7), (3, 2, 8)])
def test_spurious_probability_is_exact(preset: str, column: int, cad: int, cw: int) -> None:
    assert spurious_retransmit_probability(slot_ms(preset, cad), cw) == _SPURIOUS[preset][column]


def test_spurious_factor_rounds_to_presets_pl_2_3() -> None:
    lm, ls, lf = (slot_ms(p, 4) for p in ("LONG_MODERATE", "LONG_SLOW", "LONG_FAST"))
    lm2, ls2 = slot_ms("LONG_MODERATE", 2), slot_ms("LONG_SLOW", 2)

    got = [spurious_factor(lm, 7), spurious_factor(lm, 8), spurious_factor(lm2, 7)]
    got += [spurious_factor(lm2, 8), spurious_factor(ls, 7), spurious_factor(ls, 8)]
    got += [spurious_factor(ls2, 7), spurious_factor(ls2, 8), spurious_factor(lf, 8)]

    assert got == pytest.approx([1.28, 1.64, 1.00, 1.49, 1.48, 1.74, 1.32, 1.66, 1.46], abs=0.005)


def _diff_cases() -> list[Any]:
    return [
        pytest.param(preset, basis, value, id=f"{preset}-{basis}")
        for preset, values in _DIFF_AIRTIME.items()
        for basis, value in enumerate(values)
    ]


@pytest.mark.parametrize(("preset", "basis", "value"), _diff_cases())
def test_diff_airtime_matches_t1_d1(preset: str, basis: int, value: float) -> None:
    if basis == 0:
        got = diff_airtime_seconds(preset, MEASURED_TEMPLATE_REPLY_BYTES)
    elif basis == 1:
        got = diff_airtime_seconds(preset, _B_BASIS_REPLIES, request_bytes=56)
    else:
        got = diff_airtime_seconds(preset, (T1_REPLY_BYTES,) * 13)

    assert got == pytest.approx(value, abs=0.005)


@pytest.mark.parametrize(("preset", "value"), list(_MAX_SIZE_255.items()))
def test_max_size_diff_airtime_at_the_default_reply(preset: str, value: float) -> None:
    assert diff_airtime_seconds(preset, (MAX_REPLY_BYTES,) * 13) == pytest.approx(value, abs=0.005)


def test_diff_airtime_with_the_factor_matches_t1_d2() -> None:
    lm = diff_airtime_seconds("LONG_MODERATE", _B_BASIS_REPLIES, request_bytes=56)
    ls = diff_airtime_seconds("LONG_SLOW", _B_BASIS_REPLIES, request_bytes=56)

    assert lm * spurious_factor(slot_ms("LONG_MODERATE", 4), 7) == pytest.approx(90.37, abs=0.05)
    assert ls * spurious_factor(slot_ms("LONG_SLOW", 2), 8) == pytest.approx(219.0, abs=0.5)


def test_unanswered_request_charges_every_gateway_attempt() -> None:
    assert unanswered_request_seconds("LONG_SLOW", 5) == pytest.approx(19.05, abs=0.005)
    assert unanswered_request_seconds("LONG_SLOW", 3) == pytest.approx(11.43, abs=0.005)
    assert unanswered_request_seconds("LONG_FAST", 5) == pytest.approx(3.21, abs=0.005)
    with pytest.raises(ValueError, match="attempts"):
        unanswered_request_seconds("LONG_FAST", 0)


@pytest.mark.parametrize(
    ("region", "expected"),
    [("EU_868", 36.0), ("EU_866", 9.0), ("US", None), ("XX_000", None)],
)
def test_relay_budget_is_the_polite_share_of_the_duty_limit(
    region: str, expected: float | None
) -> None:
    got = relay_budget_seconds(region)

    assert got == (None if expected is None else pytest.approx(expected))


def test_diffs_per_hour_in_the_polite_share() -> None:
    measured = [
        diffs_per_hour(diff_airtime_seconds(p, MEASURED_TEMPLATE_REPLY_BYTES), 36.0)
        for p in PRESETS
    ]

    assert measured == [19, 10, 5, 3, 1, 0, 0]
    assert diffs_per_hour(diff_airtime_seconds("LONG_FAST", (MAX_REPLY_BYTES,) * 13), 36.0) == 0
    with pytest.raises(ValueError, match="cost_seconds"):
        diffs_per_hour(0, 36)
    with pytest.raises(ValueError, match="budget_seconds"):
        diffs_per_hour(1, -1)


@pytest.mark.parametrize(("preset", "expected"), list(_SETTLE_255.items()))
def test_settle_rule_at_the_default_reply(preset: str, expected: tuple[float, ...]) -> None:
    rule = settle_rule(preset)

    assert (rule.quiet_seconds, rule.min_seconds, rule.max_seconds) == pytest.approx(
        expected, abs=0.0005
    )


@pytest.mark.parametrize(("preset", "expected"), list(_SETTLE_243.items()))
def test_settle_rule_matches_presets_pl_2_2(preset: str, expected: tuple[float, ...]) -> None:
    rule = settle_rule(preset, reply_bytes=T1_REPLY_BYTES)

    assert (rule.quiet_seconds, rule.min_seconds, rule.max_seconds) == pytest.approx(
        expected, abs=0.0005
    )


def test_policy_values_are_the_documented_ones() -> None:
    """Pins policy, so that changing one is deliberate."""
    assert (
        budget.CLIENT_OVERHEAD_SECONDS,
        budget.DEFAULT_CW,
        budget.POLITE_RELAY_SHARE,
        budget.LATE_REPLY_GRACE_FACTOR,
        budget.SETTLE_MIN_SECONDS,
        budget.SETTLE_MIN_SLOW_PRESET_SECONDS,
        budget.SETTLE_MAX_SECONDS,
    ) == (4.0, 8, 0.10, 2, 25.0, 45.0, 120.0)


def test_the_default_reply_is_the_largest_pkc_reply() -> None:
    for function in (deadline_seconds, settle_rule):
        assert inspect.signature(function).parameters["reply_bytes"].default == MAX_REPLY_BYTES
