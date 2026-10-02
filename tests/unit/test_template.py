"""Tests for meshprovision.config.template."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from meshprovision.config.template import (
    DefaultChannelSection,
    NeighborInfoSection,
    TelemetrySection,
    TemplateConfig,
    load_template,
    load_template_text,
)
from meshprovision.errors import (
    AdminKeyCapacityError,
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


def test_default_channel_section_round_trip() -> None:
    section = DefaultChannelSection(position_precision=12, is_muted=True)
    dumped = section.model_dump()
    assert dumped == {"position_precision": 12, "is_muted": True}


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


def test_four_admin_nodes_raises_capacity_error() -> None:
    with pytest.raises(AdminKeyCapacityError) as exc_info:
        TemplateConfig(admin_nodes=["A1", "A2", "A3", "A4"])
    assert exc_info.value.count == 4
    assert exc_info.value.limit == 3


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


# ---------------------------------------------------------------------------
# Loaders.
# ---------------------------------------------------------------------------


def test_load_template_missing_path_raises_with_hint() -> None:
    with pytest.raises(TemplateValidationError) as exc_info:
        load_template("/nonexistent/path/template.yaml")
    assert "template.example.yaml" in (exc_info.value.hint or "")


def test_load_template_text_malformed_yaml_raises() -> None:
    with pytest.raises(TemplateValidationError):
        load_template_text("key: [unterminated", source="<test>")


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


def test_admin_key_refs_and_option_state() -> None:
    cfg = TemplateConfig(
        admin_nodes=["A", "B"], enabled_options=["mqtt"], disabled_options=["serial"]
    )
    assert cfg.admin_key_refs() == ("A_pub", "B_pub")
    state = cfg.option_state()
    assert state["mqtt"] is True
    assert state["serial"] is False
