"""The configuration and operations remote work refuses forever."""

from __future__ import annotations

import pytest
from meshtastic.protobuf import admin_pb2, config_pb2, mesh_pb2

from meshprovision.enums import MODULE_SECTIONS
from meshprovision.provisioning.detect import CHANNEL_SECTIONS, CONFIG_SECTIONS
from meshprovision.remote.refused import (
    MAX_CHANNEL_INDEX_READ,
    REFUSED_CONFIG,
    REFUSED_OPERATIONS,
    refused_config,
)

pytestmark = pytest.mark.unit

_ENTRIES = {
    "lora",
    "lora.override_duty_cycle",
    "default_channel",
    "security",
    "device.role",
    "device.rebroadcast_mode",
    "device.node_info_broadcast_secs",
    "power",
    "network",
    "bluetooth",
    "mqtt",
    "owner.is_licensed",
}
_OPERATIONS = {
    "set_channel",
    "set_ham_mode",
    "begin_edit_settings",
    "commit_edit_settings",
    "reboot_seconds",
    "reboot_ota_seconds",
    "shutdown_seconds",
    "factory_reset_device",
    "factory_reset_config",
    "nodedb_reset",
}


def test_every_forever_refused_item_is_listed() -> None:
    assert set(REFUSED_CONFIG) >= _ENTRIES
    assert set(REFUSED_OPERATIONS) >= _OPERATIONS


def test_a_field_entry_wins_over_its_section() -> None:
    duty = refused_config("lora", "override_duty_cycle")
    hop = refused_config("lora", "hop_limit")

    assert duty is not None
    assert "ETSI" in duty
    assert duty != hop


@pytest.mark.parametrize(
    ("section", "field", "key"),
    [
        pytest.param("lora", "hop_limit", "lora", id="lora-field"),
        pytest.param("lora", "override_duty_cycle", "lora.override_duty_cycle", id="duty"),
        pytest.param("lora", None, "lora", id="lora-section"),
        pytest.param("device", "role", "device.role", id="role"),
        pytest.param("device", "tzdef", None, id="tzdef"),
        pytest.param("telemetry", "device_update_interval", None, id="telemetry"),
        pytest.param("owner", "long_name", None, id="owner-name"),
        pytest.param("owner", "is_licensed", "owner.is_licensed", id="ham"),
        pytest.param("security", "admin_key", "security", id="admin-key"),
    ],
)
def test_refused_config_lookups(section: str, field: str | None, key: str | None) -> None:
    expected = None if key is None else REFUSED_CONFIG[key]

    assert refused_config(section, field) == expected


def test_refused_operations_are_admin_message_variants() -> None:
    variants = {field.name for field in admin_pb2.AdminMessage.DESCRIPTOR.fields}

    assert set(REFUSED_OPERATIONS) <= variants


def test_refused_config_targets_exist() -> None:
    sections = {*CONFIG_SECTIONS, *MODULE_SECTIONS, *CHANNEL_SECTIONS, "owner"}
    messages = {
        "lora": config_pb2.Config.LoRaConfig,
        "device": config_pb2.Config.DeviceConfig,
        "owner": mesh_pb2.User,
    }
    for key in REFUSED_CONFIG:
        section, _, field = key.partition(".")
        assert section in sections, key
        if field:
            names = {f.name for f in messages[section].DESCRIPTOR.fields}
            assert field in names, key


def test_only_the_primary_channel_may_be_read() -> None:
    assert MAX_CHANNEL_INDEX_READ == 0
