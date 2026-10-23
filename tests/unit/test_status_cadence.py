"""Expected intervals and the thresholds they give, each rule at its boundaries (pure)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from meshprovision.status.cadence import (
    GRACE_SHARE,
    LEARN_MIN_HEARD_HOURS,
    LEARN_WINDOW_DAYS,
    MAX_EXPECTED_INTERVAL,
    NODE_INFO_DEFAULT,
    NODE_INFO_MIN,
    OFFLINE_MISSED,
    STALE_MISSED,
    TAK_NODE_INFO,
    Cadence,
    CadenceHint,
    CadenceSource,
    availability_thresholds,
    learned_interval,
    resolve_cadence,
    role_interval,
    template_interval,
)

pytestmark = pytest.mark.unit

_H = 3600
_NOW = 1_760_994_000.0
_LAST = int(_NOW) // _H * _H
_TWO_H = timedelta(hours=2)
_DAY = timedelta(hours=24)


def _hours(heard: set[int], covered: range) -> list[tuple[int, int]]:
    """Covered hours (offsets before the newest hour) with 5 receptions in the heard ones."""
    return [(_LAST - offset * _H, 5 if offset in heard else 0) for offset in covered]


# ---------------------------------------------------------------------------
# The constants keep their documented values.
# ---------------------------------------------------------------------------


def test_the_constants_are_the_documented_ones() -> None:
    intervals = (NODE_INFO_DEFAULT, NODE_INFO_MIN, TAK_NODE_INFO, MAX_EXPECTED_INTERVAL)
    assert intervals == tuple(timedelta(hours=h) for h in (3, 1, 24, 48))
    assert (STALE_MISSED, OFFLINE_MISSED, GRACE_SHARE) == (2, 5, 0.25)
    assert (LEARN_WINDOW_DAYS, LEARN_MIN_HEARD_HOURS) == (7, 3)


# ---------------------------------------------------------------------------
# role_interval / template_interval.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("role", "expected"),
    [
        ("CLIENT", NODE_INFO_DEFAULT),
        ("ROUTER", NODE_INFO_DEFAULT),
        ("CLIENT_MUTE", NODE_INFO_DEFAULT),
        (None, NODE_INFO_DEFAULT),
        ("12", NODE_INFO_DEFAULT),
        ("TAK", TAK_NODE_INFO),
        ("TAK_TRACKER", TAK_NODE_INFO),
        ("CLIENT_HIDDEN", MAX_EXPECTED_INTERVAL),
        ("REPEATER", MAX_EXPECTED_INTERVAL),
    ],
)
def test_role_interval_is_the_firmware_node_info_default(
    role: str | None, expected: timedelta
) -> None:
    assert role_interval(role) == expected


@pytest.mark.parametrize("seconds", [None, 0])
def test_an_unset_template_interval_is_the_role_default(seconds: int | None) -> None:
    assert template_interval(seconds, "CLIENT") == NODE_INFO_DEFAULT
    assert template_interval(seconds, "TAK") == TAK_NODE_INFO


def test_a_template_interval_is_used_as_configured() -> None:
    assert template_interval(6 * _H, "CLIENT") == timedelta(hours=6)


def test_a_template_interval_below_the_firmware_minimum_is_raised_to_it() -> None:
    assert template_interval(_H - 1, "CLIENT") == NODE_INFO_MIN
    assert template_interval(_H + 1, "CLIENT") == timedelta(seconds=_H + 1)


def test_a_template_interval_is_capped() -> None:
    assert template_interval(72 * _H, "CLIENT") == MAX_EXPECTED_INTERVAL
    assert template_interval(48 * _H - 1, "CLIENT") == timedelta(seconds=48 * _H - 1)


def test_a_template_role_without_node_info_ignores_the_interval() -> None:
    assert template_interval(3 * _H, "CLIENT_HIDDEN") == MAX_EXPECTED_INTERVAL


# ---------------------------------------------------------------------------
# learned_interval.
# ---------------------------------------------------------------------------


def test_the_mean_gap_between_heard_hours_is_learned() -> None:
    # Heard every 3 hours over a day, one node info missed (offset 6).
    heard = {0, 3, 9, 12, 15, 18, 21}
    assert learned_interval(_hours(heard, range(24)), now=_NOW) == timedelta(hours=3.5)


def test_an_hourly_reporter_learns_one_hour() -> None:
    assert learned_interval(_hours(set(range(24)), range(24)), now=_NOW) == timedelta(hours=1)


def test_fewer_heard_hours_than_the_minimum_learn_nothing() -> None:
    hours = _hours({0, 12}, range(24))
    assert learned_interval(hours, now=_NOW) is None
    assert learned_interval(_hours({0, 12, 23}, range(24)), now=_NOW) == timedelta(hours=11.5)


def test_trailing_silence_does_not_stretch_the_interval() -> None:
    # Heard hourly from offset 47 to 24, silent for the last 24 hours.
    hours = _hours(set(range(24, 48)), range(48))
    assert learned_interval(hours, now=_NOW) == timedelta(hours=1)


def test_leading_silence_does_not_stretch_the_interval() -> None:
    hours = _hours({0, 1, 2}, range(30))
    assert learned_interval(hours, now=_NOW) == timedelta(hours=1)


def test_uncovered_hours_are_not_counted_as_gaps() -> None:
    # Heard at offsets 0, 10 and 20, but only those hours and two others covered.
    covered = (0, 5, 10, 15, 20)
    hours = [(_LAST - offset * _H, 5 if offset in {0, 10, 20} else 0) for offset in covered]
    assert learned_interval(hours, now=_NOW) == timedelta(hours=2)


def test_only_the_learning_window_counts() -> None:
    window = LEARN_WINDOW_DAYS * 24
    old = _hours({window + 1, window + 2}, range(window + 1, window + 3))
    assert learned_interval(old + _hours({0, 1}, range(2)), now=_NOW) is None
    # The window's first hour itself still counts, the hour before it does not.
    start = int(_NOW) - LEARN_WINDOW_DAYS * 86400
    assert start % _H == 0
    hours = [(start, 1), (start + _H, 1), (start + 2 * _H, 1)]
    assert learned_interval(hours, now=_NOW) == timedelta(hours=1)
    assert learned_interval([(start - _H, 1), *hours[1:]], now=_NOW) is None


def test_future_hours_are_ignored() -> None:
    hours = [*_hours({0, 1}, range(2)), (_LAST + _H, 9)]
    assert learned_interval(hours, now=_NOW) is None


def test_a_repeated_hour_counts_once() -> None:
    hours = [*_hours({0, 2}, range(3)), (_LAST, 3)]
    assert learned_interval(hours, now=_NOW) is None


def test_a_learned_interval_is_capped() -> None:
    window = LEARN_WINDOW_DAYS * 24
    hours = _hours({0, 60, 120}, range(min(window, 121)))
    assert learned_interval(hours, now=_NOW) == MAX_EXPECTED_INTERVAL


# ---------------------------------------------------------------------------
# resolve_cadence.
# ---------------------------------------------------------------------------

_HINT = CadenceHint(
    override=timedelta(hours=7), learned=timedelta(hours=5), configured=timedelta(hours=6)
)


def test_the_override_wins() -> None:
    assert resolve_cadence(_HINT, "TAK") == Cadence(timedelta(hours=7), CadenceSource.OVERRIDE)


def test_the_history_beats_the_template() -> None:
    hint = CadenceHint(learned=timedelta(hours=5), configured=timedelta(hours=6))
    assert resolve_cadence(hint, "TAK") == Cadence(timedelta(hours=5), CadenceSource.HISTORY)


def test_the_template_beats_the_role() -> None:
    hint = CadenceHint(configured=timedelta(hours=6))
    assert resolve_cadence(hint, "TAK") == Cadence(timedelta(hours=6), CadenceSource.TEMPLATE)


def test_the_role_is_the_last_resort() -> None:
    assert resolve_cadence(CadenceHint(), "TAK") == Cadence(TAK_NODE_INFO, CadenceSource.ROLE)
    assert resolve_cadence(CadenceHint(), None) == Cadence(NODE_INFO_DEFAULT, CadenceSource.ROLE)


@pytest.mark.parametrize("field", ["override", "learned", "configured"])
def test_every_source_is_capped(field: str) -> None:
    hint = CadenceHint(**{field: timedelta(hours=100)})  # type: ignore[arg-type]
    assert resolve_cadence(hint, None).interval == MAX_EXPECTED_INTERVAL


# ---------------------------------------------------------------------------
# availability_thresholds.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("hours", "stale", "offline"),
    [
        (0.5, _TWO_H, _DAY),
        (1, timedelta(hours=2.25), _DAY),
        (3, timedelta(hours=6.75), _DAY),
        (6, timedelta(hours=13.5), timedelta(hours=31.5)),
        (12, timedelta(hours=27), timedelta(hours=63)),
        (24, timedelta(hours=54), timedelta(hours=126)),
        (48, timedelta(hours=108), timedelta(hours=252)),
    ],
)
def test_thresholds_are_missed_intervals_plus_grace_above_the_floors(
    hours: float, stale: timedelta, offline: timedelta
) -> None:
    result = availability_thresholds(timedelta(hours=hours), stale_floor=_TWO_H, offline_floor=_DAY)
    assert result == (stale, offline)


def test_the_floors_hold_exactly_at_the_boundary() -> None:
    # 2.25 * 3200 s == 7200 s and 5.25 * 3200 s == 16800 s exactly.
    floors = {"stale_floor": timedelta(seconds=7200), "offline_floor": timedelta(seconds=16800)}
    exact = availability_thresholds(timedelta(seconds=3200), **floors)
    assert exact == (timedelta(seconds=7200), timedelta(seconds=16800))
    above = availability_thresholds(timedelta(seconds=3204), **floors)
    assert above == (timedelta(seconds=7209), timedelta(seconds=16821))


def test_custom_floors_are_honoured() -> None:
    stale, offline = availability_thresholds(
        timedelta(hours=3), stale_floor=timedelta(hours=10), offline_floor=timedelta(hours=11)
    )
    assert (stale, offline) == (timedelta(hours=10), timedelta(hours=15.75))
