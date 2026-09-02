"""Tests for meshprovision.config.template."""

from __future__ import annotations

from pathlib import Path

import pytest

from meshprovision.config.template import (
    BASE36_ALPHABET,
    PatternSpec,
    TemplateConfig,
    check_capacity_utilization,
    ensure_capacity_available,
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


def test_pattern_spec_iter_names_count() -> None:
    spec = PatternSpec.compile("MT{n}{n}", BASE36_ALPHABET, field="short_name_pattern")
    names = list(spec.iter_names(start=1294))
    assert len(names) == 2


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
    ["", "AAB", "A B", "A{B", "A}B"],
)
def test_alphabet_validation_errors(alphabet: str) -> None:
    with pytest.raises(TemplateValidationError):
        PatternSpec.compile("MT{n}", alphabet, field="short_name_pattern")


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


def test_check_capacity_utilization_negative_raises() -> None:
    spec = PatternSpec.compile("MT{n}{n}", BASE36_ALPHABET, field="short_name_pattern")
    with pytest.raises(ValueError, match="negative"):
        check_capacity_utilization(spec, -1)


def test_ensure_capacity_available() -> None:
    spec = PatternSpec.compile("MT{n}{n}", BASE36_ALPHABET, field="short_name_pattern")
    with pytest.raises(NamespaceExhaustedError) as exc_info:
        ensure_capacity_available(spec, 1296)
    assert (
        "widening" in (exc_info.value.hint or "").lower()
        or "widen" in (exc_info.value.hint or "").lower()
    )
    assert ensure_capacity_available(spec, 1295) is None


# ---------------------------------------------------------------------------
# Cross-field validation.
# ---------------------------------------------------------------------------


def test_option_in_both_enabled_and_disabled_raises() -> None:
    with pytest.raises(TemplateValidationError) as exc_info:
        TemplateConfig(enabled_options=["mqtt"], disabled_options=["mqtt"])
    assert exc_info.value.field == "enabled_options"
    assert "mqtt" in str(exc_info.value)


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


def test_load_template_text_empty_document_uses_defaults() -> None:
    cfg = load_template_text("", source="<test>")
    assert cfg.version == 1
    assert cfg.short_name_pattern == "MT{n}{n}"


def test_shipped_example_template_loads_cleanly(repo_root: Path) -> None:
    example = repo_root / "config" / "template.example.yaml"
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
