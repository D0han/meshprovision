"""Fake ``MeshInterface``/``Node`` doubles shared by the apply-layer unit tests.

Imported by the apply-layer test modules. A plain module (not ``test_*``), so
pytest never collects it; it holds no assertions, so pytest's assertion
rewriting is not needed here.
"""

from __future__ import annotations

import base64
from typing import Final, Self

from meshtastic.protobuf import channel_pb2, localonly_pb2

from meshprovision.config.template import TemplateConfig, load_template_text
from meshprovision.nodeid import NodeId
from tests.conftest import real_write_config_or_exit


def default_primary_channel() -> channel_pb2.Channel:
    ch = channel_pb2.Channel()
    ch.index = 0
    ch.role = channel_pb2.Channel.Role.PRIMARY
    return ch


class FakeLocalNode:
    def __init__(self, iface: FakeIfaceForApply) -> None:
        """Start with default config, one bare primary channel, and empty call logs."""
        self._iface = iface
        self.localConfig = localonly_pb2.LocalConfig()
        self.moduleConfig = localonly_pb2.LocalModuleConfig()
        self.channels: list[channel_pb2.Channel] = [default_primary_channel()]
        self.written_sections: list[str] = []
        self.transaction_calls: list[str] = []
        """Every beginSettingsTransaction()/commitSettingsTransaction() call
        plus every writeConfig() section name, in true chronological order
        -- lets a test assert relative call ORDER, not just that each
        happened. (``written_sections`` stays section-names-only, for
        every existing test that already asserts against it.) A subclass
        that overrides ``writeConfig`` does not necessarily append here
        too -- only the base implementation does."""
        self.begin_error: BaseException | None = None
        """Raised by beginSettingsTransaction() (after recording it) when set."""
        self.commit_error: BaseException | None = None
        """Raised by commitSettingsTransaction() (after recording it) when set."""

    def writeConfig(self, section: str) -> None:  # noqa: N802 -- real MeshInterface method name
        real_write_config_or_exit(section)
        self.written_sections.append(section)
        self.transaction_calls.append(section)

    def getChannelByChannelIndex(  # noqa: N802 -- real method name
        self,
        channelIndex: int,  # noqa: N803 -- real method name
    ) -> channel_pb2.Channel | None:
        if 0 <= channelIndex < len(self.channels):
            return self.channels[channelIndex]
        return None

    def writeChannel(  # noqa: N802 -- real method name
        self,
        channelIndex: int,  # noqa: ARG002, N803 -- real method name
        adminIndex: int = 0,  # noqa: ARG002, N803 -- real method name
    ) -> None:
        self.written_sections.append("default_channel")
        self.transaction_calls.append("default_channel")

    def beginSettingsTransaction(self) -> None:  # noqa: N802 -- real MeshInterface method name
        self.transaction_calls.append("<begin>")
        if self.begin_error is not None:
            raise self.begin_error

    def commitSettingsTransaction(self) -> None:  # noqa: N802 -- real MeshInterface method name
        self.transaction_calls.append("<commit>")
        if self.commit_error is not None:
            raise self.commit_error

    def setOwner(  # noqa: N802 -- real MeshInterface method name
        self,
        long_name: str | None = None,
        short_name: str | None = None,
        is_licensed: bool = False,
        is_unmessagable: bool | None = None,
    ) -> None:
        if short_name is not None:
            self._iface.user["shortName"] = short_name
        if long_name is not None:
            self._iface.user["longName"] = long_name
            self._iface.user["isLicensed"] = is_licensed
        if is_unmessagable is not None:
            self._iface.user["isUnmessagable"] = is_unmessagable


DEFAULT_NODE_NUM: Final = 0xDEADBE01


class FakeIfaceForApply:
    def __init__(self, node_num: int = DEFAULT_NODE_NUM) -> None:
        """Report ``node_num`` as this device's node number."""
        from types import SimpleNamespace

        self.myInfo = SimpleNamespace(my_node_num=node_num)
        self.metadata = SimpleNamespace(hw_model="RAK4631", firmware_version="2.7.11")
        self.user: dict[str, str | bool] = {
            "shortName": "MT00",
            "longName": "Meshtastic MT00",
            "isLicensed": False,
        }
        self.localNode = FakeLocalNode(self)

    def getMyUser(self) -> dict[str, str | bool]:  # noqa: N802 -- real MeshInterface method name
        return dict(self.user)

    def getPublicKey(self) -> str | None:  # noqa: N802 -- real MeshInterface method name
        raw = bytes(self.localNode.localConfig.security.public_key)
        return base64.b64encode(raw).decode("ascii") if raw else None

    def reopened(self, *, node_num: int | None = None) -> Self:
        """Model a fresh connection to the same device (a plain reconnect).

        Pass ``node_num`` only to model a device that reports a different
        node number after the reconnect (E3 3b); the returned interface
        otherwise carries over this one's current config/user state, the
        same way a real reconnect re-reads what the device actually has.
        """
        fresh = type(self)(node_num=self.myInfo.my_node_num if node_num is None else node_num)
        fresh.localNode.localConfig.CopyFrom(self.localNode.localConfig)
        fresh.localNode.moduleConfig.CopyFrom(self.localNode.moduleConfig)
        fresh.localNode.channels = []
        for ch in self.localNode.channels:
            copy = channel_pb2.Channel()
            copy.CopyFrom(ch)
            fresh.localNode.channels.append(copy)
        fresh.user = dict(self.user)
        return fresh


def minimal_template() -> TemplateConfig:
    return load_template_text("version: 1\n")


def fake_node_id() -> NodeId:
    return NodeId.from_hex("deadbe01")


class FakeLocalNodeRaisesOnWrite(FakeLocalNode):
    """Simulates a device/communication failure during a config section write."""

    def __init__(self, iface: FakeIfaceForApply, exc: BaseException) -> None:
        """Raise ``exc`` from every config or channel write."""
        super().__init__(iface)
        self._exc = exc

    def writeConfig(self, section: str) -> None:  # noqa: N802 -- real MeshInterface method name
        real_write_config_or_exit(section)
        self.written_sections.append(section)
        raise self._exc

    def writeChannel(  # noqa: N802 -- real method name
        self,
        channelIndex: int,  # noqa: ARG002, N803 -- real method name
        adminIndex: int = 0,  # noqa: ARG002, N803 -- real method name
    ) -> None:
        self.written_sections.append("default_channel")
        raise self._exc


class FakeIfaceRaisesOnWrite(FakeIfaceForApply):
    """An interface whose config section write always raises ``exc``."""

    def __init__(self, exc: BaseException, node_num: int = DEFAULT_NODE_NUM) -> None:
        """Wire in a local node whose writes raise ``exc``."""
        super().__init__(node_num)
        self.localNode = FakeLocalNodeRaisesOnWrite(self, exc)
