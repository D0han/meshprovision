"""The installed meshtastic library is the commit pyproject.toml pins."""

from __future__ import annotations

import importlib

import pytest

pytestmark = pytest.mark.unit


def test_installed_meshtastic_carries_protobufs_v2_8_1() -> None:
    # The pinned commit keeps upstream's version string (2.7.11), so pip may
    # leave an older commit in an existing venv; this fails such a venv loudly.
    mesh_pb2 = importlib.import_module("meshtastic.protobuf.mesh_pb2")
    names = {value.name for value in mesh_pb2.HardwareModel.DESCRIPTOR.values}
    assert "THINKNODE_MX" in names, (
        "meshtastic is older than the commit pyproject.toml pins; reinstall it: "
        'pip install --force-reinstall --no-deps "meshtastic @ '
        'git+https://github.com/meshtastic/python.git@0a1835760c2437314a2d3544bbdd8b6fead559bc"'
    )
    assert mesh_pb2.HardwareModel.Value("THINKNODE_MX") == 150
    importlib.import_module("meshtastic.protobuf.field_metadata_pb2")
