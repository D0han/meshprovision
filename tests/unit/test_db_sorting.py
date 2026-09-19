"""Tests for meshprovision.db.sorting."""

from __future__ import annotations

import pytest

from meshprovision.db import schema
from meshprovision.db.sorting import natural_key, sorted_rows

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# natural_key
# ---------------------------------------------------------------------------


def test_natural_key_orders_digit_runs_numerically() -> None:
    # Arrange
    values = ["MT11", "MT2", "MT1"]

    # Act
    ordered = sorted(values, key=natural_key)

    # Assert
    assert ordered == ["MT1", "MT2", "MT11"]


def test_natural_key_orders_two_digit_runs_correctly() -> None:
    # Arrange
    values = ["MT10", "MT9"]

    # Act
    ordered = sorted(values, key=natural_key)

    # Assert
    assert ordered == ["MT9", "MT10"]


def test_natural_key_is_case_insensitive() -> None:
    # Arrange
    values = ["beta", "Alpha"]

    # Act
    ordered = sorted(values, key=natural_key)

    # Assert
    assert ordered == ["Alpha", "beta"]


def test_natural_key_handles_pure_text() -> None:
    # Arrange
    values = ["zeta", "alpha", "mu"]

    # Act
    ordered = sorted(values, key=natural_key)

    # Assert
    assert ordered == ["alpha", "mu", "zeta"]


def test_natural_key_handles_pure_digits() -> None:
    # Arrange
    values = ["100", "9", "20"]

    # Act
    ordered = sorted(values, key=natural_key)

    # Assert
    assert ordered == ["9", "20", "100"]


def test_natural_key_handles_empty_string() -> None:
    # Arrange
    values = ["a", ""]

    # Act
    ordered = sorted(values, key=natural_key)

    # Assert
    assert ordered == ["", "a"]


def test_natural_key_handles_mixed_text_and_digit_runs() -> None:
    # Arrange
    values = ["abc12def3", "abc2def30", "abc12def30"]

    # Act
    ordered = sorted(values, key=natural_key)

    # Assert
    assert ordered == ["abc2def30", "abc12def3", "abc12def30"]


# ---------------------------------------------------------------------------
# sorted_rows -- Nodes sheet
# ---------------------------------------------------------------------------


def _node_row(
    node_id: str, long_name: str = "", short_name: str = "", **extra: str
) -> dict[str, str]:
    row = {
        "node_id": node_id,
        "short_name": short_name,
        "long_name": long_name,
        "archived_at": "",
    }
    row.update(extra)
    return row


def test_sorted_rows_orders_nodes_by_long_name_naturally() -> None:
    # Arrange
    rows = [
        _node_row("aaaa0011", long_name="MT11"),
        _node_row("aaaa0002", long_name="MT2"),
        _node_row("aaaa0001", long_name="MT1"),
    ]

    # Act
    result = sorted_rows(schema.NODES_SHEET, rows)

    # Assert
    assert [r["long_name"] for r in result] == ["MT1", "MT2", "MT11"]


def test_sorted_rows_falls_back_to_short_name_when_long_name_blank() -> None:
    # Arrange
    rows = [
        _node_row("aaaa0002", long_name="", short_name="Zeta"),
        _node_row("aaaa0001", long_name="", short_name="Alpha"),
    ]

    # Act
    result = sorted_rows(schema.NODES_SHEET, rows)

    # Assert
    assert [r["node_id"] for r in result] == ["aaaa0001", "aaaa0002"]


def test_sorted_rows_ties_broken_by_node_id() -> None:
    # Arrange
    rows = [
        _node_row("bbbb0002", long_name="Same"),
        _node_row("aaaa0001", long_name="Same"),
    ]

    # Act
    result = sorted_rows(schema.NODES_SHEET, rows)

    # Assert
    assert [r["node_id"] for r in result] == ["aaaa0001", "bbbb0002"]


def test_sorted_rows_places_archived_node_inline_by_name() -> None:
    # Arrange
    rows = [
        _node_row("aaaa0003", long_name="Charlie"),
        _node_row("aaaa0001", long_name="Alpha", archived_at="2026-01-01T00:00:00Z"),
        _node_row("aaaa0002", long_name="Bravo"),
    ]

    # Act
    result = sorted_rows(schema.NODES_SHEET, rows)

    # Assert
    assert [r["long_name"] for r in result] == ["Alpha", "Bravo", "Charlie"]


def test_sorted_rows_is_idempotent_and_stable() -> None:
    # Arrange
    rows = [
        _node_row("aaaa0002", long_name="Bravo"),
        _node_row("aaaa0001", long_name="Alpha"),
    ]

    # Act
    once = sorted_rows(schema.NODES_SHEET, rows)
    twice = sorted_rows(schema.NODES_SHEET, once)

    # Assert
    assert once == twice


# ---------------------------------------------------------------------------
# sorted_rows -- Keys sheet
# ---------------------------------------------------------------------------


def _key_row(key_ref: str, owner_node_id: str = "", key_type: str = "") -> dict[str, str]:
    return {"key_ref": key_ref, "owner_node_id": owner_node_id, "key_type": key_type}


def test_sorted_rows_orders_keys_by_key_ref_naturally() -> None:
    # Arrange
    rows = [
        _key_row("node11_pub"),
        _key_row("node2_pub"),
        _key_row("node1_pub"),
    ]

    # Act
    result = sorted_rows(schema.KEYS_SHEET, rows)

    # Assert
    assert [r["key_ref"] for r in result] == ["node1_pub", "node2_pub", "node11_pub"]


def test_sorted_rows_returns_unknown_sheet_unchanged() -> None:
    # Arrange
    rows = [{"foo": "b"}, {"foo": "a"}]

    # Act
    result = sorted_rows("NotASheet", rows)

    # Assert
    assert result == tuple(rows)
