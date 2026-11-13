"""The remote section diff: "not read" is never a change."""

from __future__ import annotations

import struct

import pytest

from meshprovision.remote.diff import SectionDiff, SectionState, diff_sections

pytestmark = pytest.mark.unit


def test_a_section_that_was_not_read_is_not_read_never_a_change() -> None:
    got = diff_sections({"lora": {"hop_limit": 3}}, {})

    assert got == (SectionDiff("lora", SectionState.NOT_READ),)


def test_a_read_section_that_matches() -> None:
    (got,) = diff_sections({"lora": {"hop_limit": 3}}, {"lora": {"hop_limit": 3}})

    assert (got.state, got.changes, got.unread_fields) == (SectionState.MATCHES, (), ())


def test_a_read_section_that_differs_lists_changes_in_desired_order() -> None:
    desired = {"device": {"z_field": 1, "a_field": 2, "same": 3}}
    observed = {"device": {"same": 3, "a_field": 5, "z_field": 4}}

    (got,) = diff_sections(desired, observed)

    assert got.state is SectionState.DIFFERS
    assert [(c.field, c.current, c.desired) for c in got.changes] == [
        ("z_field", 4, 1),
        ("a_field", 5, 2),
    ]
    assert got.unread_fields == ()


def test_a_field_the_read_section_lacks_is_unread_not_changed() -> None:
    desired = {"telemetry": {"a": 1, "b": 2}}

    (lacking,) = diff_sections(desired, {"telemetry": {"a": 1}})
    (differing,) = diff_sections(desired, {"telemetry": {"a": 9}})

    assert (lacking.state, lacking.changes, lacking.unread_fields) == (
        SectionState.NOT_READ,
        (),
        ("b",),
    )
    assert differing.state is SectionState.DIFFERS
    assert [c.field for c in differing.changes] == ["a"]
    assert differing.unread_fields == ("b",)


def test_a_value_the_firmware_holds_counts_as_matching() -> None:
    desired = {"telemetry": {"device_update_interval": 900}}
    observed = {"telemetry": {"device_update_interval": 1800}}

    (got,) = diff_sections(
        desired, observed, adjusted={("telemetry", "device_update_interval"): 1800}
    )

    assert got.state is SectionState.MATCHES


def test_secret_fields_are_marked_secret() -> None:
    (got,) = diff_sections({"bluetooth": {"fixed_pin": 123456}}, {"bluetooth": {"fixed_pin": 1}})

    assert [c.secret for c in got.changes] == [True]


def test_the_private_key_is_never_compared() -> None:
    with pytest.raises(ValueError, match="private key"):
        diff_sections({"security": {"private_key": b"x"}}, {"security": {"private_key": b"x"}})


def test_sections_keep_the_desired_order_and_extra_observed_ones_are_ignored() -> None:
    desired = {"lora": {"hop_limit": 3}, "device": {"role": "CLIENT"}}
    observed = {"device": {"role": "CLIENT"}, "lora": {"hop_limit": 3}, "power": {"x": 1}}

    got = diff_sections(desired, observed)

    assert tuple(d.section for d in got) == ("lora", "device")


def test_values_compare_type_tolerantly() -> None:
    float32 = struct.unpack("f", struct.pack("f", 0.1))[0]

    (flag,) = diff_sections({"device": {"a": True}}, {"device": {"a": 1}})
    (number,) = diff_sections({"position": {"x": 0.1}}, {"position": {"x": float32}})

    assert flag.state is SectionState.DIFFERS
    assert number.state is SectionState.MATCHES


def test_an_empty_desired_section_that_was_read_matches() -> None:
    (got,) = diff_sections({"lora": {}}, {"lora": {"hop_limit": 3}})

    assert got.state is SectionState.MATCHES


def test_the_inputs_are_not_mutated() -> None:
    desired = {"lora": {"hop_limit": 3}}
    observed = {"lora": {"hop_limit": 4}}

    diff_sections(desired, observed)

    assert (desired, observed) == ({"lora": {"hop_limit": 3}}, {"lora": {"hop_limit": 4}})
