"""``mesh -vv provision`` over BLE keeps the pushed private key off stderr.

The installed ``meshtastic`` BLE interface logs every frame it writes as
``TORADIO write: <hex>`` at DEBUG, which ``-vv`` releases, and its stream
and mesh interfaces log frames as a Python bytes repr and messages in
protobuf text format. The fake connection here logs all three shapes for
each section it is sent, so the real logging pipeline sees the frame that
carries the new private key.
"""

from __future__ import annotations

import base64
import logging
from typing import TYPE_CHECKING

import pytest
from google.protobuf import text_encoding
from meshtastic.protobuf import admin_pb2, localonly_pb2, mesh_pb2

from tests.e2e import conftest as e2e_conftest
from tests.e2e.conftest import FakeMeshInterface, invoke

if TYPE_CHECKING:
    from click.testing import CliRunner

    from tests.e2e.conftest import DeviceBus

pytestmark = pytest.mark.e2e


def _log_each_written_frame(monkeypatch: pytest.MonkeyPatch) -> None:
    """Log every section write the way the ``meshtastic`` interfaces do."""
    real_write = e2e_conftest._FakeConnectionNode.writeConfig
    ble_logger = logging.getLogger("meshtastic.ble_interface")
    stream_logger = logging.getLogger("meshtastic.stream_interface")
    mesh_logger = logging.getLogger("meshtastic.mesh_interface")

    def _write(self: e2e_conftest._FakeConnectionNode, section: str) -> None:
        admin = admin_pb2.AdminMessage()
        if section in localonly_pb2.LocalConfig.DESCRIPTOR.fields_by_name:
            getattr(admin.set_config, section).CopyFrom(getattr(self.localConfig, section))
        else:
            getattr(admin.set_module_config, section).CopyFrom(getattr(self.moduleConfig, section))
        to_radio = mesh_pb2.ToRadio()
        to_radio.packet.decoded.payload = admin.SerializeToString()
        frame = to_radio.SerializeToString()
        ble_logger.debug(f"TORADIO write: {frame.hex()}")
        stream_logger.debug(f"sending header:{frame[:4]!r} b:{frame!r}")
        mesh_logger.debug(f"Sending: {admin}")
        real_write(self, section)

    monkeypatch.setattr(e2e_conftest._FakeConnectionNode, "writeConfig", _write)


def test_vv_provision_over_ble_never_prints_the_pushed_private_key(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus, monkeypatch: pytest.MonkeyPatch
) -> None:
    iface = bus.use(FakeMeshInterface("deadbe01"))
    _log_each_written_frame(monkeypatch)

    result = invoke(
        runner, ["-vv", "provision", "--ble-address", "AA:BB:CC:DD:EE:FF", "--yes"], env
    )

    assert result.exit_code == 0
    private_key = bytes(iface.localNode.localConfig.security.private_key)
    assert len(private_key) == 32
    assert iface.localNode.written_sections[-1] == "security"
    output = result.stdout + result.stderr
    assert "withheld" in result.stderr
    assert private_key.hex() not in output
    assert private_key.hex().upper() not in output
    assert base64.b64encode(private_key).decode("ascii") not in output
    assert repr(private_key)[2:-1] not in output
    assert text_encoding.CEscape(private_key, as_utf8=False) not in output
