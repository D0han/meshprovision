"""Tests for meshprovision.firmware's firmware 2.8 node-id gate."""

from __future__ import annotations

import pytest

from meshprovision.firmware import KEY_DERIVED_ID_MIN_FIRMWARE, derives_node_id_from_key

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("raw", "derives"),
    [
        pytest.param("2.8.0.47db0e3", True, id="2.8.0"),
        pytest.param("v2.8.1", True, id="v-prefix"),
        pytest.param("3.0.0", True, id="later-major"),
        pytest.param("2.7.26.54e0d8d", False, id="2.7"),
        pytest.param("2.7.99", False, id="last-2.7"),
        pytest.param("", False, id="empty"),
        pytest.param("unknown", False, id="unparseable"),
    ],
)
def test_derives_node_id_from_key_only_for_parseable_2_8_and_later(raw: str, derives: bool) -> None:
    assert derives_node_id_from_key(raw) is derives


def test_the_gate_starts_at_2_8_0() -> None:
    assert KEY_DERIVED_ID_MIN_FIRMWARE == (2, 8, 0)
