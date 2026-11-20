"""A lorastats ``LastSeen``/``LastBoot`` after the record was fetched: dropped at parse time."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from meshprovision.datasources.lorastats import parse_node
from meshprovision.datasources.models import LAST_SEEN_FUTURE_SKEW, NodeObservation
from meshprovision.network.buckets import Traffic
from meshprovision.network.resolve import relay_candidates
from meshprovision.status.merge import merge_observations

pytestmark = pytest.mark.unit

_FETCHED = datetime(2026, 10, 20, 21, 0, tzinfo=UTC)
_NODE = "000003c3"


def _parse(**times: datetime) -> NodeObservation:
    payload = {"NodeId": _NODE, **{key: value.isoformat() for key, value in times.items()}}
    observation = parse_node(payload, region="PL", observed_at=_FETCHED)
    assert observation is not None
    return observation


@pytest.mark.parametrize(
    ("ahead", "kept"),
    [
        pytest.param(LAST_SEEN_FUTURE_SKEW, True, id="at-the-skew"),
        pytest.param(LAST_SEEN_FUTURE_SKEW + timedelta(seconds=1), False, id="past-the-skew"),
        pytest.param(timedelta(days=365 * 30), False, id="decades-ahead"),
    ],
)
def test_a_time_after_the_fetch_is_dropped_past_the_skew(ahead: timedelta, kept: bool) -> None:
    observation = _parse(LastSeen=_FETCHED + ahead, LastBoot=_FETCHED + ahead)

    expected = _FETCHED + ahead if kept else None
    assert (observation.last_seen, observation.last_boot) == (expected, expected)


def test_a_future_last_boot_no_longer_wins_the_merge() -> None:
    real_boot = _FETCHED - timedelta(hours=5)
    lorastats = _parse(LastSeen=_FETCHED, LastBoot=_FETCHED + timedelta(days=1))
    loranet = lorastats.model_copy(update={"source": "loranet", "last_boot": real_boot})

    merged = merge_observations(lorastats.node_id, [lorastats, loranet], now=_FETCHED)

    assert merged.last_boot == real_boot


def test_a_future_last_seen_does_not_make_a_relay_candidate() -> None:
    nodes = [_parse(LastSeen=_FETCHED + timedelta(days=1))]
    start = (_FETCHED - timedelta(hours=1)).timestamp()

    assert relay_candidates(Traffic(), nodes, start=start) == {}
