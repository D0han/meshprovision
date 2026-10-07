"""Tests for meshprovision.termsafe."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from meshprovision.termsafe import json_dumps_safe, terminal_safe

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("raw", "escaped"),
    [
        ("\x1b", "\\x1b"),  # ESC
        ("\x07", "\\x07"),  # BEL
        ("\x7f", "\\x7f"),  # DEL
        ("\x9b", "\\x9b"),  # single-byte CSI (C1)
        ("‮", "\\u202e"),  # right-to-left override (bidi control)
        ("\ud800", "\\ud800"),  # lone high surrogate
        ("\udfff", "\\udfff"),  # lone low surrogate
    ],
)
def test_control_and_bidi_characters_are_escaped(raw: str, escaped: str) -> None:
    result = terminal_safe(f"before{raw}after")
    assert raw not in result
    assert f"before{escaped}after" == result


def test_non_ascii_printable_text_is_unchanged() -> None:
    text = "Zażółć 📡"
    assert terminal_safe(text) == text


def test_newline_and_tab_escaped_by_default() -> None:
    result = terminal_safe("a\nb\tc")
    assert "\n" not in result
    assert "\t" not in result
    assert "\\x0a" in result
    assert "\\x09" in result


def test_newline_and_tab_kept_with_allow_newlines() -> None:
    result = terminal_safe("a\nb\tc", allow_newlines=True)
    assert result == "a\nb\tc"


def test_other_control_characters_still_escaped_with_allow_newlines() -> None:
    result = terminal_safe("a\x1bb\nc", allow_newlines=True)
    assert "\x1b" not in result
    assert "\n" in result
    assert "\\x1b" in result


def test_empty_string_unchanged() -> None:
    assert terminal_safe("") == ""


@pytest.mark.parametrize(
    "codepoint",
    [0x7F, 0x80, 0x9B, 0x9F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)],
    ids=lambda codepoint: f"U+{codepoint:04X}",
)
def test_json_dumps_safe_escapes_del_c1_and_bidi_controls(codepoint: int) -> None:
    assert json_dumps_safe(chr(codepoint)) == f'"\\u{codepoint:04x}"'


@pytest.mark.parametrize("codepoint", [0xD800, 0xDFFF], ids=lambda codepoint: f"U+{codepoint:04X}")
def test_json_dumps_safe_escapes_lone_surrogates(codepoint: int) -> None:
    value = {"name": f"a{chr(codepoint)}b"}
    text = json_dumps_safe(value)
    assert text == f'{{"name": "a\\u{codepoint:04x}b"}}'
    assert text.encode("utf-8")  # printable on a UTF-8 stream; raw, this raises
    assert json.loads(text) == value


def test_json_dumps_safe_round_trips_to_the_same_value() -> None:
    value = {"name": "a\x9b[2J\x7f\u202eb\u2066c\x1b", "nested": ["\u2069", None, 1.5]}
    assert json.loads(json_dumps_safe(value, indent=2)) == value


def test_json_dumps_safe_keeps_non_ascii_printable_text_literal() -> None:
    assert json_dumps_safe("Łódź 😀 日本") == '"Łódź 😀 日本"'


def test_json_dumps_safe_escapes_controls_in_keys() -> None:
    assert json_dumps_safe({"k\x9b\u202e": 1}) == '{"k\\u009b\\u202e": 1}'


def test_json_dumps_safe_escapes_a_control_after_a_literal_backslash() -> None:
    text = json_dumps_safe("\\\x9b")
    assert text == '"\\\\\\u009b"'
    assert json.loads(text) == "\\\x9b"


def test_json_dumps_safe_passes_default_through() -> None:
    assert json_dumps_safe({"path": Path("a/b.ods")}, default=str) == '{"path": "a/b.ods"}'


def test_json_dumps_safe_without_default_raises_type_error() -> None:
    with pytest.raises(TypeError):
        json_dumps_safe({"path": Path("a/b.ods")})
