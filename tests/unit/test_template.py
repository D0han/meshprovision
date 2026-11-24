"""Tests for meshprovision.config.template."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from meshprovision.config.template import (
    TEMPLATE_VERSION,
    DefaultChannelSection,
    NeighborInfoSection,
    TelemetrySection,
    TemplateConfig,
    load_template,
    load_template_text,
)
from meshprovision.enums import MODULES_WITHOUT_ENABLED
from meshprovision.errors import (
    NameCapacityError,
    NamePatternError,
    NamespaceExhaustedError,
    TemplateValidationError,
)
from meshprovision.name_pattern import (
    BASE36_ALPHABET,
    LONG_NAME_MAX_BYTES,
    PatternSpec,
    check_capacity_utilization,
    ensure_capacity_available,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Byte-length overflow.
# ---------------------------------------------------------------------------


def test_short_name_ascii_overflow() -> None:
    with pytest.raises(NamePatternError) as exc_info:
        TemplateConfig(short_name_pattern="MESH{n}")
    exc = exc_info.value
    assert exc.pattern == "MESH{n}"
    assert exc.byte_length == 5
    assert exc.limit == 4
    assert exc.field == "short_name_pattern"


def test_short_name_multibyte_prefix_overflow_by_bytes_not_chars() -> None:
    with pytest.raises(NamePatternError) as exc_info:
        TemplateConfig(short_name_pattern="ŻŁ{n}{n}")
    assert exc_info.value.byte_length == 6


def test_short_name_multibyte_alphabet_overflow() -> None:
    with pytest.raises(NamePatternError):
        TemplateConfig(short_name_pattern="MT{n}{n}", name_suffix_alphabet="ABŻ")


def test_short_name_multibyte_boundary_loads_cleanly() -> None:
    cfg = TemplateConfig(short_name_pattern="Ż{n}{n}", name_suffix_alphabet=BASE36_ALPHABET)
    assert cfg.short_name_pattern == "Ż{n}{n}"


def test_long_name_overflow() -> None:
    with pytest.raises(NamePatternError) as exc_info:
        TemplateConfig(long_name_pattern="X" * 25 + "{n}")
    assert exc_info.value.limit == 25


def test_long_name_near_limit_warns_but_loads() -> None:
    cfg = TemplateConfig(long_name_pattern="X" * 21 + "{n}{n}")
    spec = cfg.long_name_spec()
    assert 22 <= spec.widest_byte_length() <= 25
    warnings = cfg.collect_warnings()
    assert any(w.code == "long_name_near_limit" for w in warnings)


@pytest.mark.parametrize(("role", "warned"), [("CLIENT_HIDDEN", True), ("CLIENT", False)])
def test_a_hidden_role_warns_that_the_node_never_announces_itself(role: str, warned: bool) -> None:
    cfg = load_template_text(f"version: 1\ndevice:\n  role: {role}\n")

    codes = [w.code for w in cfg.collect_warnings()]

    assert ("role_never_announces" in codes) is warned


# ---------------------------------------------------------------------------
# Namespace capacity, PatternSpec.
# ---------------------------------------------------------------------------


def test_pattern_spec_capacity_and_render() -> None:
    spec = PatternSpec.compile("MT{n}{n}", BASE36_ALPHABET, field="short_name_pattern")
    assert spec.slot_count == 2
    assert spec.capacity == 1296
    assert spec.render(0) == "MT00"
    assert spec.render(35) == "MT0Z"
    assert spec.render(36) == "MT10"
    assert spec.render(1295) == "MTZZ"


def test_pattern_spec_render_out_of_range_raises() -> None:
    spec = PatternSpec.compile("MT{n}{n}", BASE36_ALPHABET, field="short_name_pattern")
    with pytest.raises(NamespaceExhaustedError) as exc_info:
        spec.render(-1)
    assert exc_info.value.pattern == "MT{n}{n}"
    assert exc_info.value.capacity == 1296
    with pytest.raises(NamespaceExhaustedError):
        spec.render(1296)


def test_pattern_spec_parse_index_full_inverse_sweep() -> None:
    spec = PatternSpec.compile("MT{n}{n}", BASE36_ALPHABET, field="short_name_pattern")
    for i in range(spec.capacity):
        assert spec.parse_index(spec.render(i)) == i


@pytest.mark.parametrize("bad_name", ["XX00", "MT0", "MT000", "MT0!"])
def test_pattern_spec_parse_index_none_for_non_matching(bad_name: str) -> None:
    spec = PatternSpec.compile("MT{n}{n}", BASE36_ALPHABET, field="short_name_pattern")
    assert spec.parse_index(bad_name) is None


def test_pattern_spec_literal_braces() -> None:
    spec = PatternSpec.compile("a{{b}}{n}", BASE36_ALPHABET, field="short_name_pattern")
    assert spec.slot_count == 1
    assert spec.render(0) == "a{b}0"


def test_pattern_spec_unsupported_placeholder() -> None:
    with pytest.raises(TemplateValidationError):
        PatternSpec.compile("{x}", BASE36_ALPHABET, field="short_name_pattern")


def test_pattern_spec_unmatched_closing_brace() -> None:
    with pytest.raises(TemplateValidationError):
        PatternSpec.compile("}", BASE36_ALPHABET, field="short_name_pattern")


@pytest.mark.parametrize(
    "alphabet",
    ["", "AAB", "A B", "A{B", "A}B", "aA", "AB\u00df", "AB\ufb01"],
)
def test_alphabet_validation_errors(alphabet: str) -> None:
    with pytest.raises(TemplateValidationError):
        PatternSpec.compile("MT{n}", alphabet, field="short_name_pattern")


def test_alphabet_case_collision_error_names_each_pair() -> None:
    """Case-variant digits are refused, naming every colliding pair.

    ``find_next_free_name`` compares names by ``casefold()``, so ``"aA"``
    would otherwise count two digits that only ever yield one usable name
    and overstate ``capacity``.
    """
    with pytest.raises(TemplateValidationError) as exc_info:
        PatternSpec.compile("MT{n}", "0aAbB", field="short_name_pattern")

    assert exc_info.value.field == "name_suffix_alphabet"
    assert "differ only in case: 'a'/'A', 'b'/'B'." in str(exc_info.value)


def test_render_keeps_the_literals_between_and_after_slots() -> None:
    spec = PatternSpec.compile("N{n}-{n}Z", BASE36_ALPHABET, field="long_name_pattern")

    assert spec.render(37) == "N1-1Z"
    assert spec.render_widest() == "N0-0Z"
    assert spec.widest_byte_length() == 5


@pytest.mark.parametrize(
    "name", ["N1-1Q", "N1-1ZZ", "N1-1"], ids=["wrong-suffix", "extra-tail", "missing-suffix"]
)
def test_parse_index_requires_the_exact_trailing_literal(name: str) -> None:
    spec = PatternSpec.compile("N{n}-{n}Z", BASE36_ALPHABET, field="long_name_pattern")

    assert spec.parse_index(name) is None


def test_parse_index_round_trips_a_pattern_with_a_trailing_literal() -> None:
    spec = PatternSpec.compile("N{n}-{n}Z", BASE36_ALPHABET, field="long_name_pattern")

    assert spec.parse_index("N1-1Z") == 37


def test_compile_refuses_an_empty_pattern() -> None:
    with pytest.raises(TemplateValidationError, match="must not be empty") as excinfo:
        PatternSpec.compile("", BASE36_ALPHABET, field="short_name_pattern")

    assert excinfo.value.field == "short_name_pattern"


# ---------------------------------------------------------------------------
# Capacity floor / near-exhaustion / exhaustion.
# ---------------------------------------------------------------------------


def test_capacity_floor_warns_when_not_strict() -> None:
    cfg = TemplateConfig(
        short_name_pattern="MT{n}", name_min_capacity=100, name_capacity_strict=False
    )
    warnings = cfg.collect_warnings()
    assert any(w.code == "capacity_below_floor" for w in warnings)


def test_capacity_floor_hard_error_when_strict() -> None:
    with pytest.raises(NameCapacityError) as exc_info:
        TemplateConfig(short_name_pattern="MT{n}", name_min_capacity=100, name_capacity_strict=True)
    exc = exc_info.value
    assert exc.capacity == 36
    assert exc.floor == 100
    assert exc.field == "short_name_pattern"


@pytest.mark.parametrize(
    ("long_name_pattern", "capacity"), [("Base Station {n}", 36), ("Base Station", 1)]
)
def test_long_pattern_below_floor_warns_naming_it(long_name_pattern: str, capacity: int) -> None:
    cfg = TemplateConfig(short_name_pattern="MT{n}{n}", long_name_pattern=long_name_pattern)

    (warning,) = [w for w in cfg.collect_warnings() if w.code == "capacity_below_floor"]

    assert warning.field == "long_name_pattern"
    assert warning.message == (
        f"long_name_pattern {long_name_pattern!r} over a 36-character alphabet yields "
        f"only {capacity} names (configured floor 100)."
    )


def test_long_pattern_below_floor_is_an_error_in_strict_mode() -> None:
    with pytest.raises(NameCapacityError) as exc_info:
        TemplateConfig(
            short_name_pattern="MT{n}{n}",
            long_name_pattern="Base Station {n}",
            name_capacity_strict=True,
        )
    exc = exc_info.value
    assert exc.field == "long_name_pattern"
    assert exc.pattern == "Base Station {n}"
    assert exc.capacity == 36
    assert str(exc).startswith("long_name_pattern 'Base Station {n}' over a 36-character")


def test_short_pattern_is_named_when_both_patterns_tie_below_the_floor() -> None:
    cfg = TemplateConfig(short_name_pattern="MT{n}", long_name_pattern="Node {n}")

    (warning,) = [w for w in cfg.collect_warnings() if w.code == "capacity_below_floor"]

    assert warning.field == "short_name_pattern"
    assert warning.message == (
        "short_name_pattern 'MT{n}' over a 36-character alphabet yields only 36 names "
        "(configured floor 100)."
    )


def test_check_capacity_utilization_boundaries() -> None:
    spec = PatternSpec.compile("MT{n}{n}", BASE36_ALPHABET, field="short_name_pattern")
    assert check_capacity_utilization(spec, 1166, warn_at=0.9) is None
    warning = check_capacity_utilization(spec, 1167, warn_at=0.9)
    assert warning is not None
    assert warning.code == "capacity_near_exhaustion"
    assert "1296" in warning.message


def test_check_capacity_utilization_warns_exactly_at_the_threshold() -> None:
    """The comparison is ``ratio >= warn_at``, so landing exactly on it warns.

    The boundary test above straddles a ratio that is not exactly
    representable, so neither side of it pins ``>=`` against ``>``.
    ``capacity // 2`` over ``warn_at=0.5`` lands on the threshold exactly.
    """
    spec = PatternSpec.compile("MT{n}{n}", BASE36_ALPHABET, field="short_name_pattern")
    exactly_at = spec.capacity // 2

    warning = check_capacity_utilization(spec, exactly_at, warn_at=0.5)
    assert warning is not None
    assert warning.code == "capacity_near_exhaustion"
    assert warning.field == "short_name_pattern"

    assert check_capacity_utilization(spec, exactly_at - 1, warn_at=0.5) is None


def test_long_name_near_limit_threshold_is_exact() -> None:
    """The warning fires on ``> LONG_NAME_MAX_BYTES - 4``, i.e. at 22 bytes, not 21."""
    at_threshold = TemplateConfig(long_name_pattern="X" * (LONG_NAME_MAX_BYTES - 5) + "{n}")
    assert at_threshold.long_name_spec().widest_byte_length() == LONG_NAME_MAX_BYTES - 4
    assert not any(w.code == "long_name_near_limit" for w in at_threshold.collect_warnings())

    one_over = TemplateConfig(long_name_pattern="X" * (LONG_NAME_MAX_BYTES - 4) + "{n}")
    assert one_over.long_name_spec().widest_byte_length() == LONG_NAME_MAX_BYTES - 3
    assert any(w.code == "long_name_near_limit" for w in one_over.collect_warnings())


def test_check_capacity_utilization_negative_raises() -> None:
    spec = PatternSpec.compile("MT{n}{n}", BASE36_ALPHABET, field="short_name_pattern")
    with pytest.raises(ValueError, match="negative"):
        check_capacity_utilization(spec, -1)


def test_ensure_capacity_available() -> None:
    spec = PatternSpec.compile("MT{n}{n}", BASE36_ALPHABET, field="short_name_pattern")
    with pytest.raises(NamespaceExhaustedError) as exc_info:
        ensure_capacity_available(spec, 1296)
    exc = exc_info.value
    assert exc.pattern == "MT{n}{n}"
    assert exc.capacity == 1296
    assert "widen" in (exc.hint or "").lower()
    assert ensure_capacity_available(spec, 1295) is None


@pytest.mark.parametrize("floor", [36, 10], ids=["at-floor", "above-floor"])
def test_strict_capacity_floor_accepts_a_pattern_that_meets_it(floor: int) -> None:
    cfg = TemplateConfig(
        short_name_pattern="MT{n}", name_min_capacity=floor, name_capacity_strict=True
    )

    assert cfg.name_capacity_strict is True
    assert not any(w.code == "capacity_below_floor" for w in cfg.collect_warnings())


# ---------------------------------------------------------------------------
# Section models.
# ---------------------------------------------------------------------------


def test_telemetry_section_new_fields_round_trip() -> None:
    section = TelemetrySection(
        device_telemetry_enabled=True,
        health_measurement_enabled=True,
        health_update_interval=600,
        health_screen_enabled=False,
        air_quality_screen_enabled=True,
    )
    dumped = section.model_dump()
    assert dumped["device_telemetry_enabled"] is True
    assert dumped["health_measurement_enabled"] is True
    assert dumped["health_update_interval"] == 600
    assert dumped["health_screen_enabled"] is False
    assert dumped["air_quality_screen_enabled"] is True


def test_neighbor_info_section_fields() -> None:
    section = NeighborInfoSection(enabled=True, update_interval=14400, transmit_over_lora=False)
    dumped = section.model_dump()
    assert dumped == {
        "enabled": True,
        "update_interval": 14400,
        "transmit_over_lora": False,
    }


@pytest.mark.parametrize("seconds", [0, 3599])
def test_node_info_broadcast_secs_below_the_firmware_minimum_is_rejected(seconds: int) -> None:
    with pytest.raises(TemplateValidationError, match="node_info_broadcast_secs"):
        load_template_text(f"version: 1\ndevice:\n  node_info_broadcast_secs: {seconds}\n")


def test_node_info_broadcast_secs_at_the_firmware_minimum_loads() -> None:
    cfg = load_template_text("version: 1\ndevice:\n  node_info_broadcast_secs: 3600\n")

    assert cfg.device is not None
    assert cfg.device.node_info_broadcast_secs == 3600


@pytest.mark.parametrize("seconds", [0, 14399])
def test_neighbor_info_update_interval_below_the_firmware_minimum_is_rejected(
    seconds: int,
) -> None:
    with pytest.raises(TemplateValidationError, match="update_interval"):
        load_template_text(f"version: 1\nneighbor_info:\n  update_interval: {seconds}\n")


def test_neighbor_info_update_interval_at_the_firmware_minimum_loads() -> None:
    cfg = load_template_text("version: 1\nneighbor_info:\n  update_interval: 14400\n")

    assert cfg.neighbor_info is not None
    assert cfg.neighbor_info.update_interval == 14400


@pytest.mark.parametrize("seconds", [1, 29])
def test_on_battery_shutdown_after_secs_below_the_firmware_minimum_is_rejected(
    seconds: int,
) -> None:
    with pytest.raises(TemplateValidationError, match="on_battery_shutdown_after_secs"):
        load_template_text(f"version: 1\npower:\n  on_battery_shutdown_after_secs: {seconds}\n")


def test_on_battery_shutdown_after_secs_disabled_or_at_the_minimum_loads() -> None:
    for seconds in (0, 30):
        cfg = load_template_text(
            f"version: 1\npower:\n  on_battery_shutdown_after_secs: {seconds}\n"
        )

        assert cfg.power is not None
        assert cfg.power.on_battery_shutdown_after_secs == seconds


def test_default_channel_section_round_trip() -> None:
    section = DefaultChannelSection(position_precision=12, is_muted=True)
    dumped = section.model_dump()
    assert dumped == {"position_precision": 12, "is_muted": True}


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("device", "node_info_broadcast_secs", 2**32),
        ("telemetry", "device_update_interval", 2**32),
        ("power", "sds_secs", 2**32),
        ("position", "position_flags", 10**400),
        ("lora", "frequency_offset", 1e40),
        ("lora", "frequency_offset", -1e40),
        ("lora", "frequency_offset", float("nan")),
        ("power", "adc_multiplier_override", float("inf")),
    ],
    ids=[
        "uint32-over",
        "module-uint32-over",
        "power-uint32-over",
        "beyond-float",
        "float32-over",
        "float32-under",
        "nan",
        "inf",
    ],
)
def test_numeric_field_outside_its_protobuf_range_is_rejected(
    section: str, field: str, value: float
) -> None:
    """Refused at load, not mid-``mesh provision`` after the rename and earlier sections."""
    with pytest.raises(TemplateValidationError) as exc_info:
        TemplateConfig(**{section: {field: value}})
    assert exc_info.value.field == f"{section}.{field}"


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("device", "node_info_broadcast_secs", 2**32 - 1),
        ("lora", "frequency_offset", -3.4028234663852886e38),
    ],
)
def test_numeric_field_at_its_protobuf_limit_is_accepted(
    section: str, field: str, value: float
) -> None:
    template = TemplateConfig(**{section: {field: value}})
    assert getattr(getattr(template, section), field) == value


def test_is_unmessagable_round_trip() -> None:
    template = TemplateConfig(is_unmessagable=True)
    assert template.is_unmessagable is True


def test_is_unmessagable_defaults_to_none() -> None:
    template = TemplateConfig()
    assert template.is_unmessagable is None


def test_default_channel_section_negative_position_precision_rejected() -> None:
    with pytest.raises(TemplateValidationError):
        load_template_text(
            "version: 1\ndefault_channel:\n  position_precision: -1\n", source="<test>"
        )


# ---------------------------------------------------------------------------
# Cross-field validation.
# ---------------------------------------------------------------------------


def test_option_in_both_enabled_and_disabled_raises() -> None:
    with pytest.raises(TemplateValidationError) as exc_info:
        TemplateConfig(enabled_options=["mqtt"], disabled_options=["mqtt"])
    assert exc_info.value.field == "enabled_options"
    assert "mqtt" in str(exc_info.value)


def test_neighbor_info_in_enabled_options_is_rejected() -> None:
    with pytest.raises(TemplateValidationError) as exc_info:
        TemplateConfig(enabled_options=["neighbor_info"])
    assert exc_info.value.field == "enabled_options"
    assert exc_info.value.hint is not None
    assert "neighbor_info" in exc_info.value.hint


def test_neighbor_info_in_disabled_options_is_rejected() -> None:
    with pytest.raises(TemplateValidationError) as exc_info:
        TemplateConfig(disabled_options=["neighbor_info"])
    assert exc_info.value.field == "disabled_options"
    assert exc_info.value.hint is not None
    assert "neighbor_info" in exc_info.value.hint


def test_four_admin_nodes_is_a_template_error() -> None:
    with pytest.raises(TemplateValidationError, match="admin_nodes has 4 entries") as exc_info:
        TemplateConfig(admin_nodes=["A1", "A2", "A3", "A4"])
    assert exc_info.value.field == "admin_nodes"
    assert exc_info.value.exit_code == 2


def test_a_template_version_newer_than_known_is_refused() -> None:
    with pytest.raises(TemplateValidationError, match="Template version 2 is newer") as exc_info:
        TemplateConfig(version=TEMPLATE_VERSION + 1)
    assert exc_info.value.field == "version"
    assert exc_info.value.exit_code == 2


def test_the_known_template_version_loads() -> None:
    assert TemplateConfig(version=TEMPLATE_VERSION).version == TEMPLATE_VERSION


@pytest.mark.parametrize("ref", ["A1_pub", "A1_priv", "A1_psk"])
def test_admin_nodes_entry_with_reserved_suffix_raises(ref: str) -> None:
    with pytest.raises(TemplateValidationError):
        TemplateConfig(admin_nodes=[ref])


def test_admin_nodes_entry_invalid_shape_raises() -> None:
    with pytest.raises(TemplateValidationError):
        TemplateConfig(admin_nodes=["1bad ref"])


def test_admin_nodes_entry_with_observed_prefix_raises() -> None:
    """A template must not name a mesh adopt-minted observed-* ref.

    Previously this loaded fine and only broke later, confusingly, once
    `mesh admin import` deleted the observed-* row -- see db.observed_keys
    .owner_ref_problem.
    """
    with pytest.raises(TemplateValidationError) as exc_info:
        TemplateConfig(admin_nodes=["observed-ab12cd34"])
    assert exc_info.value.field == "admin_nodes"
    assert "observed-" in str(exc_info.value)
    hint = exc_info.value.hint or ""
    assert "`mesh admin import <NAME>=<BASE64>`" in hint
    assert "`mesh adopt --show-admin-keys`" in hint
    assert "`mesh admin bootstrap --ref <NAME>`" in hint
    assert "admin import --ref" not in hint  # import takes REF=BASE64, it has no --ref


def test_admin_nodes_entry_that_merely_starts_with_pre_observed_loads() -> None:
    """Only a leading observed- is reserved; the substring elsewhere is fine."""
    TemplateConfig(admin_nodes=["pre-observed"])


def test_admin_channel_enabled_true_raises() -> None:
    with pytest.raises(TemplateValidationError):
        TemplateConfig(security={"admin_channel_enabled": True})


def test_is_managed_true_with_no_admin_nodes_raises() -> None:
    with pytest.raises(TemplateValidationError) as exc_info:
        TemplateConfig(security={"is_managed": True}, admin_nodes=[])
    assert exc_info.value.hint is not None
    assert "admin_nodes" in exc_info.value.hint


@pytest.mark.parametrize("key", ["private_key", "public_key", "admin_key", "adminKey"])
def test_security_key_material_rejected(key: str) -> None:
    with pytest.raises(TemplateValidationError) as exc_info:
        TemplateConfig(security={key: "AAAA"})
    assert exc_info.value.field == f"security.{key}"


def test_unknown_device_role_raises() -> None:
    with pytest.raises(TemplateValidationError):
        TemplateConfig(device={"role": "NOT_A_ROLE"})


def test_unknown_lora_region_raises() -> None:
    with pytest.raises(TemplateValidationError):
        TemplateConfig(lora={"region": "NOT_A_REGION"})


@pytest.mark.parametrize(
    ("kwargs", "field"),
    [
        ({"device": {"role": "NOT_A_ROLE"}}, "device.role"),
        ({"device": {"rebroadcast_mode": "NOT_A_MODE"}}, "device.rebroadcast_mode"),
        ({"lora": {"region": "NOT_A_REGION"}}, "lora.region"),
        ({"lora": {"modem_preset": "long_fsat"}}, "lora.modem_preset"),
        ({"position": {"gps_mode": "NOT_A_MODE"}}, "position.gps_mode"),
        (
            {"security": {"packet_signature_policy": "NOT_A_REAL_POLICY"}},
            "security.packet_signature_policy",
        ),
    ],
)
def test_unknown_enum_field_raises_naming_the_field(kwargs: dict, field: str) -> None:
    """A typo'd enum-name field is rejected at template-load time, naming the field.

    Covers all 6 enum-typed template fields, not just role/region --
    rebroadcast_mode, modem_preset, gps_mode, and packet_signature_policy
    previously passed validation with a typo and only failed mid-``mesh
    provision``.
    """
    with pytest.raises(TemplateValidationError) as exc_info:
        TemplateConfig(**kwargs)
    assert exc_info.value.field == field


def test_enum_fields_are_canonicalized_to_upper_snake() -> None:
    """A lowercase enum value is stored canonicalized, not passed through verbatim.

    Without this, ``role: router`` would pass validation but then fail
    ``apply_field``'s exact-match protobuf lookup at apply time, and
    ``values_equal`` would never match it against the live ``"ROUTER"``.
    """
    cfg = TemplateConfig(device={"role": "router"})
    assert cfg.device.role == "ROUTER"


def test_packet_signature_policy_round_trips() -> None:
    cfg = TemplateConfig(security={"packet_signature_policy": "PACKET_SIGNATURE_POLICY_STRICT"})
    assert cfg.security.packet_signature_policy == "PACKET_SIGNATURE_POLICY_STRICT"


def test_packet_signature_policy_defaults_to_none() -> None:
    assert TemplateConfig().security.packet_signature_policy is None


def test_unknown_packet_signature_policy_raises() -> None:
    with pytest.raises(TemplateValidationError):
        TemplateConfig(security={"packet_signature_policy": "NOT_A_REAL_POLICY"})


@pytest.mark.parametrize(
    ("position", "expected"),
    [(None, None), ({"position_broadcast_secs": 900}, None), ({"fixed_position": False}, False)],
    ids=["no-position-block", "position-without-it", "explicit-false"],
)
def test_fixed_position_is_only_set_when_the_template_says_so(
    position: dict[str, object] | None, expected: bool | None
) -> None:
    """An omitted ``fixed_position`` is ``None``: the device's own setting is left alone."""
    cfg = TemplateConfig() if position is None else TemplateConfig(position=position)

    assert cfg.position.fixed_position is expected
    assert ("fixed_position" in cfg.position.model_dump(exclude_none=True)) is (
        expected is not None
    )


def test_position_fixed_field_rejected() -> None:
    """A template setting fixed_latitude/longitude/altitude is refused outright.

    meshprovision never applies these fields, so loading must fail loudly
    instead of silently doing nothing with them.
    """
    with pytest.raises(TemplateValidationError) as exc_info:
        TemplateConfig(position={"fixed_latitude": 12.5})
    assert exc_info.value.field == "position.fixed_latitude"
    assert exc_info.value.hint is not None
    assert "--setlat" in exc_info.value.hint
    assert "--setlon" in exc_info.value.hint
    assert "--setalt" in exc_info.value.hint


def test_unknown_module_option_is_warning_not_error() -> None:
    cfg = TemplateConfig(enabled_options=["not_a_real_module"])
    warnings = cfg.collect_warnings()
    assert any(w.code == "unknown_option" for w in warnings)


def test_unknown_module_option_warning_says_it_is_ignored() -> None:
    (warning,) = TemplateConfig(disabled_options=["not_a_real_module"]).collect_warnings()

    assert warning.message == (
        "Option 'not_a_real_module' is not a known Meshtastic module option; "
        "it is ignored (nothing is written to the device for it)."
    )
    assert warning.field == "disabled_options"


@pytest.mark.parametrize("field_name", ["enabled_options", "disabled_options"])
def test_option_without_an_on_off_switch_warns_at_load(field_name: str) -> None:
    (warning,) = TemplateConfig(**{field_name: ["telemetry"]}).collect_warnings()

    assert warning.code == "option_has_no_switch"
    assert warning.field == field_name
    assert f"listing it in {field_name} does nothing" in warning.message
    assert "telemetry:" in warning.message


def test_every_module_without_an_on_off_switch_warns() -> None:
    cfg = TemplateConfig(enabled_options=sorted(MODULES_WITHOUT_ENABLED))

    warnings = cfg.collect_warnings()

    assert [w.code for w in warnings] == ["option_has_no_switch"] * len(MODULES_WITHOUT_ENABLED)


def test_options_lowercased() -> None:
    cfg = TemplateConfig(enabled_options=["MQTT", "Serial"])
    assert cfg.enabled_options == ("mqtt", "serial")


def test_duplicate_list_entries_fold_into_template_validation_error() -> None:
    from pydantic import ValidationError

    with pytest.raises((TemplateValidationError, ValidationError)):
        TemplateConfig(admin_nodes=["A1", "A1"])


_Outcome = TemplateConfig | TemplateValidationError
_Check = Callable[[_Outcome], None]


def _assert_raises_with_snippets(*snippets: str) -> _Check:
    def check(outcome: _Outcome) -> None:
        assert isinstance(outcome, TemplateValidationError)
        message = str(outcome)
        for snippet in snippets:
            assert snippet in message

    return check


def _assert_admin_nodes_equal(expected: tuple[str, ...]) -> _Check:
    def check(outcome: _Outcome) -> None:
        assert isinstance(outcome, TemplateConfig)
        assert outcome.admin_nodes == expected

    return check


def _assert_enabled_options_equal(expected: tuple[str, ...]) -> _Check:
    def check(outcome: _Outcome) -> None:
        assert isinstance(outcome, TemplateConfig)
        assert outcome.enabled_options == expected

    return check


@pytest.mark.parametrize(
    ("text", "check"),
    [
        (
            "version: 1\nadmin_nodes: ADMIN1\n",
            _assert_raises_with_snippets("must be a list of strings", "admin_nodes"),
        ),
        (
            "version: 1\nadmin_nodes:\n  - 1\n",
            _assert_raises_with_snippets("expected a string, got 1"),
        ),
        (
            'version: 1\nadmin_nodes:\n  - "  ADMIN1  "\n  - ""\n  - "   "\n',
            _assert_admin_nodes_equal(("ADMIN1",)),
        ),
        (
            'version: 1\nenabled_options:\n  - "  MQTT "\n',
            _assert_enabled_options_equal(("mqtt",)),
        ),
        (
            'version: 1\nadmin_nodes:\n  - "ADMIN1"\n  - " ADMIN1 "\n',
            _assert_raises_with_snippets("duplicate entries", "ADMIN1"),
        ),
    ],
)
def test_string_list_fields_normalize_and_reject(text: str, check: _Check) -> None:
    """Exercise every branch of ``_normalize_str_tuple`` through ``load_template_text``.

    Covers: a bare string (not a list) rejected outright; a non-string list
    element rejected by repr; whitespace stripped and blank entries dropped;
    strip happening before ``enabled_options`` is lowercased (not after,
    which would leave stray whitespace); and a duplicate that only becomes
    one once both entries are stripped.
    """
    try:
        cfg = load_template_text(text, source="<test>")
    except TemplateValidationError as exc:
        check(exc)
    else:
        check(cfg)


_OUT_OF_RANGE: dict[str, Any] = {"device": {"node_info_broadcast_secs": 2**32}}
_BOTH_LISTS: dict[str, Any] = {"enabled_options": ["mqtt"], "disabled_options": ["mqtt"]}
_LONG_SHORT_NAME: dict[str, Any] = {"short_name_pattern": "MESH{n}"}
_LONG_LONG_NAME: dict[str, Any] = {"long_name_pattern": "X" * 40 + "{n}"}
_FOUR_ADMINS: dict[str, Any] = {"admin_nodes": ["A1", "A2", "A3", "A4"]}
_ADMIN_CHANNEL: dict[str, Any] = {"security": {"admin_channel_enabled": True}}


@pytest.mark.parametrize(
    ("first", "second", "expected_type", "expected_field"),
    [
        (
            _OUT_OF_RANGE,
            _BOTH_LISTS,
            TemplateValidationError,
            "device.node_info_broadcast_secs",
        ),
        (_BOTH_LISTS, _LONG_SHORT_NAME, TemplateValidationError, "enabled_options"),
        (_LONG_SHORT_NAME, _LONG_LONG_NAME, NamePatternError, "short_name_pattern"),
        (_LONG_LONG_NAME, _FOUR_ADMINS, NamePatternError, "long_name_pattern"),
        (_FOUR_ADMINS, _ADMIN_CHANNEL, TemplateValidationError, "admin_nodes"),
    ],
    ids=[
        "ranges-before-lists",
        "lists-before-names",
        "short-before-long",
        "names-before-admins",
        "admins-before-interlocks",
    ],
)
def test_consistency_checks_report_the_first_group_in_documented_order(
    first: dict[str, Any],
    second: dict[str, Any],
    expected_type: type[Exception],
    expected_field: str | None,
) -> None:
    """Two simultaneous problems: the earlier check group (per the docstring order) wins."""
    with pytest.raises(expected_type) as excinfo:
        TemplateConfig(**first, **second)

    assert type(excinfo.value) is expected_type
    if expected_field is not None:
        assert getattr(excinfo.value, "field", None) == expected_field


# ---------------------------------------------------------------------------
# Loaders.
# ---------------------------------------------------------------------------


def test_load_template_missing_path_raises_with_hint() -> None:
    with pytest.raises(TemplateValidationError) as exc_info:
        load_template("/nonexistent/path/template.yaml")
    assert (exc_info.value.hint or "").startswith(
        "Run `mesh init` to create a starter template at /nonexistent/path/template.yaml"
    )


def test_load_template_text_malformed_yaml_raises() -> None:
    with pytest.raises(TemplateValidationError):
        load_template_text("key: [unterminated", source="<test>")


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("lora:\n  region: EU_868\n  hop_limit: 3\n  region: US\n", id="nested"),
        pytest.param("lora: {region: EU_868, region: US}\n", id="flow-same-line"),
        pytest.param("version: 1\nversion: 1\n", id="top-level-same-value"),
    ],
)
def test_load_template_text_refuses_a_repeated_key(text: str) -> None:
    with pytest.raises(TemplateValidationError, match="found duplicate key") as exc_info:
        load_template_text(text, source="<test>")

    first_line = 2 if text.startswith("lora:\n") else 1
    assert f"(first given on line {first_line})" in str(exc_info.value)


def test_load_template_text_lets_a_key_override_a_merged_one() -> None:
    text = (
        "x-base: &base {hop_limit: 3}\n"
        "lora:\n  <<: *base\n  hop_limit: 4\n  region: EU_868\n  modem_preset: LONG_FAST\n"
    )

    try:
        load_template_text(text, source="<test>")
    except TemplateValidationError as exc:
        assert "duplicate key" not in str(exc)


def test_load_template_text_lets_a_merge_chain_through() -> None:
    text = "base: &b {k: 1}\na: {x: &mid {<<: *b, k: 2}}\nc: {<<: *mid}\n"

    with pytest.raises(TemplateValidationError) as exc_info:
        load_template_text(text, source="<test>")

    assert "duplicate key" not in str(exc_info.value)


def test_load_template_text_top_level_list_raises() -> None:
    with pytest.raises(TemplateValidationError):
        load_template_text("- 1\n- 2\n", source="<test>")


@pytest.mark.parametrize("text", ["", "   \n", "# only a comment\n"])
def test_load_template_text_empty_document_raises(text: str) -> None:
    """An empty/whitespace-only/comments-only document parses to ``None`` in YAML.

    It must be rejected, not silently treated as ``{}`` and validated with
    every field default (region, preset, role, name pattern) -- see E5.
    """
    with pytest.raises(TemplateValidationError, match="empty"):
        load_template_text(text, source="<test>")


def test_load_template_text_minimal_version_still_loads_defaults() -> None:
    """A non-empty document (even one with just ``version``) is deliberately still allowed."""
    cfg = load_template_text("version: 1\n", source="<test>")
    assert cfg.version == 1
    assert cfg.short_name_pattern == "MT{n}{n}"


def test_shipped_example_template_loads_cleanly(repo_root: Path) -> None:
    example = repo_root / "src" / "meshprovision" / "examples" / "template.example.yaml"
    cfg = load_template(example)
    warnings = cfg.collect_warnings()
    for warning in warnings:
        assert warning.code == "unknown_option", warning


@pytest.mark.parametrize(
    "section",
    sorted(
        name
        for name, field in TemplateConfig.model_fields.items()
        if isinstance(field.annotation, type) and issubclass(field.annotation, BaseModel)
    ),
)
def test_the_example_template_names_every_field_of_each_section(
    repo_root: Path, section: str
) -> None:
    """Set, or listed in a comment of the section, so an operator can find each one."""
    example = repo_root / "src" / "meshprovision" / "examples" / "template.example.yaml"
    text = example.read_text(encoding="utf-8")
    start = text.index(f"\n{section}:\n") + len(f"\n{section}:\n")
    following = re.search(r"^\S", text[start:], flags=re.MULTILINE)
    block = text[start : None if following is None else start + following.start()]
    model = TemplateConfig.model_fields[section].annotation
    assert isinstance(model, type)
    assert issubclass(model, BaseModel)

    missing = [name for name in model.model_fields if not re.search(rf"\b{name}\b", block)]

    assert missing == []


def test_admin_key_refs_and_option_state() -> None:
    cfg = TemplateConfig(
        admin_nodes=["A", "B"], enabled_options=["mqtt"], disabled_options=["serial"]
    )
    state = cfg.option_state()
    assert state["mqtt"] is True
    assert state["serial"] is False


def test_traffic_management_is_a_known_module_option() -> None:
    """Every module section the planner writes is a known template option."""
    template = TemplateConfig(enabled_options=["traffic_management"])
    assert "unknown_option" not in {w.code for w in template.collect_warnings()}


def test_load_template_text_logs_every_collected_warning_at_debug(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="meshprovision.config.template")

    cfg = load_template_text("version: 1\ndisabled_options: [not_a_real_module]\n")

    records = [r for r in caplog.records if r.name == "meshprovision.config.template"]
    assert records
    assert [r.getMessage() for r in records] == [w.message for w in cfg.collect_warnings()]
    assert {r.levelno for r in records} == {logging.DEBUG}


def test_an_empty_option_list_in_yaml_loads_as_no_options() -> None:
    cfg = load_template_text("version: 1\nenabled_options:\ndisabled_options:\n")

    assert cfg.enabled_options == ()
    assert cfg.disabled_options == ()


def test_a_non_mapping_top_level_is_refused() -> None:
    with pytest.raises(TemplateValidationError, match="must be a mapping"):
        load_template_text("- version: 1\n", source="tpl.yaml")


def test_a_triplicated_option_is_named_once() -> None:
    with pytest.raises(TemplateValidationError) as excinfo:
        load_template_text("version: 1\nenabled_options: [mqtt, mqtt, mqtt]\n")

    assert str(excinfo.value).count("mqtt") == 1


def test_region_unset_is_refused_because_it_switches_the_transmitter_off() -> None:
    with pytest.raises(TemplateValidationError) as exc_info:
        TemplateConfig(lora={"region": "unset"})

    assert exc_info.value.field == "lora.region"
    assert "tx_enabled false" in str(exc_info.value)


def test_router_client_is_refused_as_a_role_the_firmware_replaces() -> None:
    with pytest.raises(TemplateValidationError) as exc_info:
        TemplateConfig(device={"role": "ROUTER_CLIENT"})

    assert exc_info.value.field == "device.role"
    assert "stores CLIENT in its place" in str(exc_info.value)
    assert "store_forward.is_server" in str(exc_info.value)


@pytest.mark.parametrize("role", ["ROUTER", "ROUTER_LATE", "REPEATER"])
def test_rebroadcast_none_is_refused_for_a_router_role(role: str) -> None:
    with pytest.raises(TemplateValidationError) as exc_info:
        TemplateConfig(device={"role": role, "rebroadcast_mode": "NONE"})

    assert exc_info.value.field == "device.rebroadcast_mode"


@pytest.mark.parametrize(
    "device",
    [
        pytest.param({"role": "CLIENT", "rebroadcast_mode": "NONE"}, id="client-none"),
        pytest.param({"role": "ROUTER", "rebroadcast_mode": "ALL"}, id="router-all"),
        pytest.param({"role": "REPEATER"}, id="repeater"),
    ],
)
def test_other_roles_and_modes_still_load(device: dict[str, str]) -> None:
    assert TemplateConfig(device=device).device.role == device["role"]


@pytest.mark.parametrize(("precision", "loads"), [(32, True), (33, False)])
def test_position_precision_is_at_most_32_bits(precision: int, loads: bool) -> None:
    text = f"version: 1\ndefault_channel:\n  position_precision: {precision}\n"

    if loads:
        assert load_template_text(text).default_channel.position_precision == precision
    else:
        with pytest.raises(TemplateValidationError):
            load_template_text(text)


@pytest.mark.parametrize("region", ["PL", "poland", "Polska"])
def test_a_polish_region_name_hints_at_eu_868(region: str) -> None:
    with pytest.raises(TemplateValidationError) as exc_info:
        TemplateConfig.model_validate({"lora": {"region": region}})

    assert exc_info.value.hint is not None
    assert exc_info.value.hint.startswith("Poland uses EU_868")
    assert "configuration.md#region-eu_868-not-pl" in exc_info.value.hint


def test_an_unknown_enum_value_lists_every_valid_name_but_unset() -> None:
    with pytest.raises(TemplateValidationError) as exc_info:
        TemplateConfig.model_validate({"lora": {"region": "XX"}})

    message = str(exc_info.value)
    assert "EU_868" in message
    assert "UNSET" not in message


def test_a_misspelled_enum_value_suggests_the_closest_names() -> None:
    with pytest.raises(TemplateValidationError) as exc_info:
        TemplateConfig.model_validate({"lora": {"modem_preset": "LONG_FASTT"}})

    assert exc_info.value.hint is not None
    assert exc_info.value.hint.startswith("Did you mean LONG_FAST")
