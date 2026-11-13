"""Passive drift: a template row against what was heard of the node."""

from __future__ import annotations

import dataclasses

import pytest

from meshprovision.health.drift import (
    DriftSource,
    ObservedHardware,
    RecordedIdentity,
    passive_drift,
)
from meshprovision.health.history import NodeInfoSeen

pytestmark = pytest.mark.unit

NOW = 1_800_000_000.0
UPDATED = NOW - 2 * 86400
_REC = RecordedIdentity("AB12", "Alpha", "CLIENT", "HELTEC_V3", UPDATED)


def _info(
    short: str = "AB12", long: str = "Alpha", role: str | None = "CLIENT", time: float = NOW - 3600
) -> NodeInfoSeen:
    return NodeInfoSeen(time=time, short_name=short, long_name=long, role=role)


def _hw(model: str = "HELTEC_V3", seen: float = NOW - 600) -> ObservedHardware:
    return ObservedHardware(model, seen)


def test_no_record_gives_no_drift() -> None:
    assert passive_drift(None, _info(short="ZZ"), _hw("T_ECHO"), now=NOW) == ()


def test_matching_names_role_and_hardware_give_no_drift() -> None:
    assert passive_drift(_REC, _info(), _hw(), now=NOW) == ()


def test_a_renamed_node_drifts_on_both_names() -> None:
    found = passive_drift(_REC, _info(short="ZZ99", long="Beta"), None, now=NOW)

    assert [(d.field, d.recorded, d.observed) for d in found] == [
        ("short_name", "AB12", "ZZ99"),
        ("long_name", "Alpha", "Beta"),
    ]
    assert all(d.source is DriftSource.NODE_INFO and d.seen_at == NOW - 3600 for d in found)


def test_observed_names_are_compared_stripped() -> None:
    assert passive_drift(_REC, _info(short=" AB12 "), None, now=NOW) == ()


@pytest.mark.parametrize("field", ["short_name", "long_name", "role", "hw_model"])
def test_an_empty_recorded_value_is_no_claim(field: str) -> None:
    record = dataclasses.replace(_REC, **{field: ""})

    found = passive_drift(record, _info("ZZ99", "Beta", "ROUTER"), _hw("T_ECHO"), now=NOW)

    assert field not in {d.field for d in found}
    assert len(found) == 3


def test_a_role_change_drifts() -> None:
    (found,) = passive_drift(_REC, _info(role="ROUTER"), None, now=NOW)

    assert (found.field, found.recorded, found.observed) == ("role", "CLIENT", "ROUTER")


def test_an_unknown_role_is_no_drift() -> None:
    assert passive_drift(_REC, _info(role=None), None, now=NOW) == ()


def test_hardware_drift_comes_from_the_sources() -> None:
    (found,) = passive_drift(_REC, None, _hw("T_ECHO"), now=NOW)

    assert (found.field, found.recorded, found.observed) == ("hw_model", "HELTEC_V3", "T_ECHO")
    assert found.source is DriftSource.SOURCES
    assert found.seen_at == NOW - 600


@pytest.mark.parametrize("model", ["UNSET", "999", "NOT_A_BOARD_YET"])
def test_unset_or_unrecognised_hardware_is_no_drift(model: str) -> None:
    assert passive_drift(_REC, None, _hw(model), now=NOW) == ()


@pytest.mark.parametrize("kind", ["node_info", "hardware"])
@pytest.mark.parametrize(("seen", "drifts"), [(UPDATED + 300, False), (UPDATED + 300.001, True)])
def test_an_observation_must_be_newer_than_the_row_update_plus_grace(
    kind: str, seen: float, drifts: bool
) -> None:
    if kind == "node_info":
        found = passive_drift(_REC, _info(long="Beta", time=seen), None, now=NOW)
    else:
        found = passive_drift(_REC, None, _hw("T_ECHO", seen), now=NOW)

    assert bool(found) is drifts


def test_a_row_never_updated_has_no_update_guard() -> None:
    record = dataclasses.replace(_REC, updated_at=None)

    found = passive_drift(record, _info(long="Beta"), None, now=NOW)

    assert [d.field for d in found] == ["long_name"]


@pytest.mark.parametrize(
    ("seen", "drifts"), [(NOW - 7 * 86400, True), (NOW - 7 * 86400 - 1, False)]
)
def test_an_observation_older_than_a_week_is_ignored(seen: float, drifts: bool) -> None:
    record = dataclasses.replace(_REC, updated_at=None)

    assert bool(passive_drift(record, _info(long="Beta", time=seen), None, now=NOW)) is drifts
    assert bool(passive_drift(record, None, _hw("T_ECHO", seen), now=NOW)) is drifts


@pytest.mark.parametrize(("seen", "drifts"), [(NOW + 300, True), (NOW + 300.001, False)])
def test_an_observation_beyond_the_future_skew_is_ignored(seen: float, drifts: bool) -> None:
    assert bool(passive_drift(_REC, _info(long="Beta", time=seen), None, now=NOW)) is drifts
    assert bool(passive_drift(_REC, None, _hw("T_ECHO", seen), now=NOW)) is drifts


def test_findings_come_in_a_fixed_order() -> None:
    found = passive_drift(_REC, _info("ZZ99", "Beta", "ROUTER"), _hw("T_ECHO"), now=NOW)

    assert [d.field for d in found] == ["short_name", "long_name", "hw_model", "role"]
