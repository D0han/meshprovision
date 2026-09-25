"""Tests for meshprovision.termsafe."""

from __future__ import annotations

import pytest

from meshprovision.termsafe import terminal_safe

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("raw", "escaped"),
    [
        ("\x1b", "\\x1b"),  # ESC
        ("\x07", "\\x07"),  # BEL
        ("\x7f", "\\x7f"),  # DEL
        ("\x9b", "\\x9b"),  # single-byte CSI (C1)
        ("‮", "\\u202e"),  # right-to-left override (bidi control)
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
