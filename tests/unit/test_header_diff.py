"""Tests for meshprovision.db.header_diff."""

from __future__ import annotations

import pytest

from meshprovision.db.header_diff import describe_header_mismatch

pytestmark = pytest.mark.unit


def test_missing_trailing_columns_names_them_in_the_hint() -> None:
    message, hint = describe_header_mismatch(
        sheet="Nodes", found=("a", "b", "c"), expected=("a", "b", "c", "d", "e")
    )
    assert "Missing trailing column(s): ('d', 'e')" in hint
    assert "generate_example_db.py" in hint
    assert "3 column(s) expected" not in message  # sanity: footer uses expected's count
    assert "5 column(s) expected, 3 found." in message


def test_empty_header_is_treated_as_all_columns_missing() -> None:
    message, hint = describe_header_mismatch(sheet="Nodes", found=(), expected=("a", "b", "c"))
    assert "Missing trailing column(s): ('a', 'b', 'c')" in hint
    assert "3 column(s) expected, 0 found." in message


def test_reordered_columns_are_recognized() -> None:
    _message, hint = describe_header_mismatch(
        sheet="Nodes", found=("b", "a", "c"), expected=("a", "b", "c")
    )
    assert "wrong order" in hint


def test_single_deleted_column_names_it_and_where_to_reinsert() -> None:
    message, hint = describe_header_mismatch(
        sheet="Nodes", found=("a", "c"), expected=("a", "b", "c")
    )
    assert "'b' looks deleted" in hint
    assert "B1" in hint
    assert "B1" in message
    assert "(no cell)" in message


def test_single_inserted_column_names_it_and_where() -> None:
    message, hint = describe_header_mismatch(
        sheet="Nodes", found=("a", "x", "b"), expected=("a", "b")
    )
    assert "'x'" in hint
    assert "looks inserted" in hint
    assert "B1" in hint
    assert "(no column)" in message


def test_single_renamed_column_names_both_sides() -> None:
    message, hint = describe_header_mismatch(
        sheet="Nodes", found=("a", "z", "c"), expected=("a", "b", "c")
    )
    assert "B1" in hint
    assert "'b'" in hint
    assert "'z'" in hint
    assert "z" in message
    assert "b" in message


def test_unrecognized_shape_gets_generic_fallback_hint() -> None:
    _message, hint = describe_header_mismatch(
        sheet="Nodes", found=("z", "y", "c"), expected=("a", "b", "c")
    )
    assert "doesn't match any of the usual edit patterns" in hint


def test_multiple_separate_changes_also_get_the_generic_fallback_hint() -> None:
    """Two independent single-column changes are not one isolated edit.

    Distinct from the single-replace-of-size-two case above: this
    produces *two* non-equal opcodes, so the diagnosis never even
    reaches the deleted/inserted/renamed checks (each of which only
    looks at a lone opcode).
    """
    _message, hint = describe_header_mismatch(
        sheet="Nodes", found=("a", "x", "c", "y", "e"), expected=("a", "b", "c", "d", "e")
    )
    assert "doesn't match any of the usual edit patterns" in hint


def test_every_hint_ends_with_rollback_instructions() -> None:
    cases = [
        (("a", "b"), ("a", "b", "c")),
        ((), ("a",)),
        (("b", "a"), ("a", "b")),
        (("a", "c"), ("a", "b", "c")),
        (("a", "x", "b"), ("a", "b")),
        (("a", "z", "c"), ("a", "b", "c")),
        (("z", "y", "c"), ("a", "b", "c")),
    ]
    for found, expected in cases:
        _message, hint = describe_header_mismatch(sheet="Nodes", found=found, expected=expected)
        assert "mesh db backup --list" in hint
        assert "mesh db restore" in hint


def test_matching_columns_collapse_to_one_summary_line() -> None:
    message, _hint = describe_header_mismatch(
        sheet="Nodes",
        found=("a", "b", "z", "d"),
        expected=("a", "b", "c", "d"),
    )
    assert "A1-B1   (2 columns match)" in message
    assert "D1      (1 column matches)" in message


def test_long_cell_values_are_truncated_in_the_table() -> None:
    long_name = "x" * 200
    message, _hint = describe_header_mismatch(sheet="Nodes", found=(long_name,), expected=("a",))
    assert long_name not in message
    assert "…" in message
    # every rendered line stays well short of the raw 200-char value
    assert all(len(line) < 120 for line in message.splitlines())


def test_message_opens_with_sheet_name_and_row_reference() -> None:
    message, _hint = describe_header_mismatch(sheet="Keys", found=("a",), expected=("a", "b"))
    assert message.startswith("Keys sheet: the header row (row 1) does not match")
