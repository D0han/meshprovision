"""Tests for meshprovision.firmware's firmware 2.8 node-id gate."""

from __future__ import annotations

import pytest

from meshprovision.firmware import (
    BARE_KEY_ROTATION_MIN_FIRMWARE,
    KEY_DERIVED_ID_MIN_FIRMWARE,
    derives_node_id_from_key,
    may_keep_rest_of_bare_key_rotation,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("raw", "derives"),
    [
        pytest.param("2.8.0.47db0e3", True, id="2.8.0"),
        pytest.param("v2.8.1", True, id="v-prefix"),
        pytest.param("2.8.2.4c89b69", True, id="2.8.2-with-hash"),
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


@pytest.mark.parametrize(
    ("raw", "keeps"),
    [
        pytest.param("2.8.0.47db0e3", True, id="2.8.0"),
        pytest.param("v2.8.2", True, id="v-prefix"),
        pytest.param("2.7.99", False, id="last-2.7"),
        pytest.param("", True, id="empty"),
        pytest.param("unknown", True, id="unparseable"),
    ],
)
def test_only_parseable_firmware_before_2_8_applies_a_bare_rotation_in_full(
    raw: str, keeps: bool
) -> None:
    assert may_keep_rest_of_bare_key_rotation(raw) is keeps


def test_the_bare_rotation_gate_starts_at_2_8_0() -> None:
    assert BARE_KEY_ROTATION_MIN_FIRMWARE == (2, 8, 0)
