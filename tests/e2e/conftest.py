"""Shared fixtures for the e2e test suite: a fully mocked ``mesh`` environment.

Everything the e2e tests need to drive the real ``mesh`` CLI (via
:class:`click.testing.CliRunner`) against a fake device and a fake pair
of HTTP data sources lives here: :class:`FakeMeshInterface` (the
device -- backed by real protobuf ``LocalConfig``/``LocalModuleConfig``
messages, since ``detect.read_live_config`` walks ``msg.DESCRIPTOR`` and
``apply.write_section`` calls ``setattr`` on real fields), holding the
device's *persisted* state; :class:`FakeConnection` (the host's handle
to one connection, returned by :meth:`FakeMeshInterface.connect` --
holds a *staged*, host-side copy of the config taken at connect time, so
a write that the device-side ``writeConfig`` fails never looks persisted
on the next reconnect); :class:`DeviceBus` (patches all three
:class:`~meshprovision.provisioning.connection.ConnectionBackend`
subclasses' ``connect()`` at the class level, so the real
transport-selection logic in ``connection.select_backend`` still runs);
serial/BLE discovery stubs, a seeded-database fixture, an env-dict
fixture, and a :mod:`respx`-based datasource-mocking fixture.

Everything ``tests/conftest.py`` (owned by the unit-tests group) provides
-- ``repo_root``, ``cli_env``, ``write_template``, ``empty_ods``,
``keypair``, ``keypair_factory``, the import-time ``time.sleep`` stub,
and the autouse chdir-to-``tmp_path``/env-scrub fixture -- is consumed
here, never redefined.
"""

from __future__ import annotations

import errno
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Final

import httpx
import pytest
import respx
from click.testing import CliRunner, Result
from meshtastic.protobuf import localonly_pb2

from meshprovision.cli.main import cli
from meshprovision.datasources.loranet import LORANET_NODES_URL
from meshprovision.datasources.lorastats import LORASTATS_BASE_URL, LORASTATS_NODES_PATH
from meshprovision.db import ods_write
from meshprovision.db.keys import KeyRecord
from meshprovision.db.nodes import NodeRecord
from meshprovision.errors import ConnectionFailedError
from meshprovision.nodeid import NodeId
from meshprovision.provisioning import connection, discovery

if TYPE_CHECKING:
    from meshtastic.mesh_interface import MeshInterface

__all__ = [
    "FAKE_FIRMWARE",
    "FAKE_HW_MODEL",
    "DeviceBus",
    "FakeConnection",
    "FakeMeshInterface",
    "FakeNode",
    "db_fingerprint",
    "invoke",
]

FAKE_HW_MODEL: Final[str] = "RAK4631"
"""Default hardware model reported by every :class:`FakeMeshInterface`."""

FAKE_FIRMWARE: Final[str] = "2.7.11"
"""Default firmware version reported by every :class:`FakeMeshInterface`."""


class FakeNode:
    """The device's own persisted node state (``device.localNode``).

    Wraps real protobuf ``LocalConfig``/``LocalModuleConfig`` messages so
    that :mod:`meshprovision.provisioning.detect` (which walks
    ``msg.DESCRIPTOR``) and :mod:`meshprovision.provisioning.apply`
    (which calls ``setattr`` on real fields) both operate on genuine
    protobuf objects, exactly as they would against a real device.

    Reached only through a :class:`FakeConnection` in production code
    paths (via ``connection.writeConfig``/``setOwner``), but test code
    reads ``device.localNode.localConfig``/``written_sections`` directly
    to assert on what the device actually persisted.
    """

    def __init__(self, iface: FakeMeshInterface) -> None:
        """Initialize a fake node bound to its owning fake interface.

        Args:
            iface: The :class:`FakeMeshInterface` this node belongs to --
                consulted for ``drop_security_keys``/``fail_sections`` and
                to mutate ``iface.user`` from :meth:`setOwner`.
        """
        self._iface = iface
        self.localConfig = localonly_pb2.LocalConfig()
        self.moduleConfig = localonly_pb2.LocalModuleConfig()
        self.written_sections: list[str] = []

    def writeConfig(self, section: str) -> None:  # noqa: N802 -- matches Node's own spelling
        """Record a device-side write attempt, simulating a firmware failure.

        Reached only through :meth:`FakeConnection`/:class:`_FakeConnectionNode`,
        which is responsible for actually persisting the section (and for
        the firmware issue #7449 key-drop simulation) once this call
        returns without raising -- see :meth:`_FakeConnectionNode.writeConfig`.

        Args:
            section: The config or module-config section name being
                written.

        Raises:
            BaseException: If ``section`` is listed in the owning
                interface's ``fail_sections`` -- simulates a device-side
                write failure. The exception type is
                ``RuntimeError(f"simulated device write failure for
                section {section!r}")`` by default, or whatever the
                owning interface's ``fail_exc(section)`` returns when
                set.
        """
        self.written_sections.append(section)
        if section in self._iface.fail_sections:
            if self._iface.fail_exc is not None:
                raise self._iface.fail_exc(section)
            raise RuntimeError(f"simulated device write failure for section {section!r}")

    def setOwner(  # noqa: N802 -- must match meshtastic's own Node.setOwner spelling
        self, long_name: str | None = None, short_name: str | None = None, **kwargs: object
    ) -> None:
        """Record a name change onto the owning interface's ``user`` dict.

        Args:
            long_name: The new long name, or ``None`` to leave it
                unchanged.
            short_name: The new short name, or ``None`` to leave it
                unchanged.
            **kwargs: Ignored; accepted for signature compatibility with
                the real ``Node.setOwner``.
        """
        del kwargs
        if short_name is not None:
            self._iface.user["shortName"] = short_name
        if long_name is not None:
            self._iface.user["longName"] = long_name


class FakeMeshInterface:
    """A stand-in for ``meshtastic``'s ``MeshInterface``.

    Exposes exactly the surface :mod:`meshprovision.provisioning.detect`
    and :mod:`meshprovision.provisioning.apply` read/write: ``myInfo``,
    ``metadata``, ``getMyNodeInfo()``, ``getMyUser()``, ``getPublicKey()``,
    ``localNode`` (a :class:`FakeNode`), and ``close()``.
    """

    def __init__(
        self,
        node_id: str = "deadbe01",
        *,
        short_name: str | None = None,
        long_name: str | None = None,
        hw_model: str = FAKE_HW_MODEL,
        firmware_version: str = FAKE_FIRMWARE,
        drop_security_keys: bool = False,
        fail_sections: frozenset[str] = frozenset(),
        fail_exc: Callable[[str], BaseException] | None = None,
        fail_reads_after_write: bool = False,
    ) -> None:
        """Initialize a fake device at factory or custom naming defaults.

        Args:
            node_id: The device's node id, in any form
                :meth:`~meshprovision.nodeid.NodeId.from_hex` accepts.
            short_name: The device's ``short_name``. Defaults to the
                firmware factory form: the node id's last 4 hex digits.
            long_name: The device's ``long_name``. Defaults to the
                firmware factory form: ``"Meshtastic " + <last 4 hex
                digits>"``.
            hw_model: Hardware model reported by ``metadata``/``user``.
            firmware_version: Firmware version reported by ``metadata``.
            drop_security_keys: When ``True``, writing the ``"security"``
                section clears the just-written key material, simulating
                firmware issue #7449.
            fail_sections: Section names whose write raises, simulating a
                device-side write failure.
            fail_exc: A factory from a failing section name to the
                exception to raise for it. Defaults to ``None``, which
                keeps today's ``RuntimeError(f"simulated device write
                failure for section {section!r}")``. Set this to exercise
                a real device I/O exception type (BLE, ``MeshInterface``,
                serial, ...) -- see the ``device_io_error`` fixture.
            fail_reads_after_write: When ``True``, ``getMyUser()`` raises
                ``RuntimeError`` once at least one section has been
                written -- simulating a flaky serial read during the
                post-write verify reconnect. Gated on a write having
                already happened so the *initial* detection pass (before
                any write) is unaffected.
        """
        self.nid = NodeId.from_hex(node_id)
        self.drop_security_keys = drop_security_keys
        self.fail_sections = fail_sections
        self.fail_exc = fail_exc
        self.fail_reads_after_write = fail_reads_after_write
        self.closed = 0

        self.myInfo = SimpleNamespace(my_node_num=self.nid.num)
        self.metadata = SimpleNamespace(hw_model=hw_model, firmware_version=firmware_version)

        resolved_short = short_name if short_name is not None else self.nid.hex[-4:]
        resolved_long = long_name if long_name is not None else f"Meshtastic {self.nid.hex[-4:]}"
        self.user: dict[str, str] = {
            "shortName": resolved_short,
            "longName": resolved_long,
            "hwModel": hw_model,
        }

        self.localNode = FakeNode(self)

    def getMyNodeInfo(self) -> dict[str, int]:  # noqa: N802 -- matches MeshInterface's spelling
        """Return this device's node info, as the real interface would.

        Returns:
            ``{"num": <node number>}``.
        """
        return {"num": self.nid.num}

    def getMyUser(self) -> dict[str, str]:  # noqa: N802 -- matches MeshInterface's spelling
        """Return a copy of this device's user/identity dict.

        Returns:
            A shallow copy of :attr:`user`, so a caller can never mutate
            this interface's own state through the returned mapping.

        Raises:
            RuntimeError: If :attr:`fail_reads_after_write` is set and at
                least one config section has already been written --
                simulates a flaky serial read during the post-write
                verify reconnect.
        """
        if self.fail_reads_after_write and self.localNode.written_sections:
            raise RuntimeError("serial read timed out")
        return dict(self.user)

    def getPublicKey(self) -> str | None:  # noqa: N802 -- matches MeshInterface's spelling
        """Return the device's public key, base64-encoded (the real shape).

        Returns:
            The base64 encoding of ``localConfig.security.public_key``,
            or ``None`` when that field is empty.
        """
        raw = bytes(self.localNode.localConfig.security.public_key)
        if not raw:
            return None
        import base64

        return base64.b64encode(raw).decode("ascii")

    def close(self) -> None:
        """Record a close call."""
        self.closed += 1

    def connect(self) -> FakeConnection:
        """Build a fresh connection view staged from this device's persisted state.

        Returns:
            A new :class:`FakeConnection`. Its ``localNode.localConfig``/
            ``moduleConfig`` are deep copies of this device's current
            persisted config, taken now -- a later persisted change made
            through a *different* connection is never visible on this
            one.
        """
        return FakeConnection(self)

    @property
    def security(self) -> localonly_pb2.LocalConfig.security.__class__:  # type: ignore[name-defined]
        """Convenience accessor for ``localNode.localConfig.security``.

        Returns:
            The live ``SecurityConfig`` protobuf message.
        """
        return self.localNode.localConfig.security

    @property
    def admin_keys(self) -> tuple[bytes, ...]:
        """The device's currently authorized admin public keys.

        Returns:
            A tuple of raw public-key bytes, in device order.
        """
        return tuple(bytes(key) for key in self.security.admin_key)


class _FakeConnectionNode:
    """A :class:`FakeConnection`'s staged, host-side view of ``localNode``.

    Deep-copies the device's persisted ``localConfig``/``moduleConfig``
    at connect time, so a field change the host stages here (the same
    way ``apply.write_section`` does, via ``setattr``) is visible to
    *this* connection immediately but reaches the device -- and so any
    other connection -- only once :meth:`writeConfig` actually persists
    it.
    """

    def __init__(self, connection: FakeConnection) -> None:
        """Initialize a staged node view for one connection.

        Args:
            connection: The owning :class:`FakeConnection`, consulted
                for the device to stage from and to persist into.
        """
        self._connection = connection
        device = connection._device
        self.localConfig = localonly_pb2.LocalConfig()
        self.localConfig.CopyFrom(device.localNode.localConfig)
        self.moduleConfig = localonly_pb2.LocalModuleConfig()
        self.moduleConfig.CopyFrom(device.localNode.moduleConfig)

    def writeConfig(self, section: str) -> None:  # noqa: N802 -- matches Node's own spelling
        """Push this connection's staged ``section`` to the device, if it accepts it.

        Args:
            section: The config or module-config section name to write.

        Raises:
            OSError: If this connection was already closed.
            BaseException: Propagated from :meth:`FakeNode.writeConfig`
                when ``section`` is listed in the device's
                ``fail_sections`` -- nothing is persisted in that case.
        """
        if self._connection.closed:
            raise OSError(errno.EBADF, "fake connection is closed")

        device = self._connection._device
        # Records the write attempt and raises the simulated device-side
        # failure, if any -- exactly what a real writeConfig() call does
        # before this fake decides whether to persist anything.
        device.localNode.writeConfig(section)

        is_config = section in localonly_pb2.LocalConfig.DESCRIPTOR.fields_by_name
        staged_root = self.localConfig if is_config else self.moduleConfig
        persisted_node = device.localNode
        persisted_root = persisted_node.localConfig if is_config else persisted_node.moduleConfig
        getattr(persisted_root, section).CopyFrom(getattr(staged_root, section))

        if device.drop_security_keys and section == "security":
            # Simulate firmware issue #7449: a freshly *persisted* key is
            # silently discarded on the device -- this connection's own
            # staged copy (just written above, and what getPublicKey()
            # reads) is unaffected.
            device.localNode.localConfig.security.private_key = b""
            device.localNode.localConfig.security.public_key = b""

    def setOwner(  # noqa: N802 -- must match meshtastic's own Node.setOwner spelling
        self, long_name: str | None = None, short_name: str | None = None, **kwargs: object
    ) -> None:
        """Push an owner (name) write straight to the device -- these persist immediately.

        Args:
            long_name: The new long name, or ``None`` to leave it
                unchanged.
            short_name: The new short name, or ``None`` to leave it
                unchanged.
            **kwargs: Ignored; accepted for signature compatibility with
                the real ``Node.setOwner``.

        Raises:
            OSError: If this connection was already closed.
        """
        if self._connection.closed:
            raise OSError(errno.EBADF, "fake connection is closed")
        self._connection._device.localNode.setOwner(
            long_name=long_name, short_name=short_name, **kwargs
        )


class FakeConnection:
    """The host's handle to one connection to a :class:`FakeMeshInterface` device.

    Returned by :meth:`FakeMeshInterface.connect` (reached, in turn,
    through the ``bus`` fixture's patched ``ConnectionBackend.connect()``
    -- see :func:`bus`). Exposes exactly the production surface
    :mod:`meshprovision.provisioning.detect` and
    :mod:`meshprovision.provisioning.apply` read/write: ``myInfo``,
    ``metadata``, ``getMyNodeInfo()``, ``getMyUser()``, ``getPublicKey()``,
    ``localNode.{localConfig,moduleConfig,writeConfig,setOwner}`` and
    ``close()``.

    Deliberately does not model the real library's connect-time nodeDB
    cache: a stale in-place nodeDB would change ``--no-reconnect``
    outcomes, which is a product question outside this fixture's scope.
    """

    def __init__(self, device: FakeMeshInterface) -> None:
        """Initialize a connection staged from ``device``'s current persisted state.

        Args:
            device: The device this connection is to.
        """
        self._device = device
        self.closed = False
        self.localNode = _FakeConnectionNode(self)

    @property
    def myInfo(self) -> SimpleNamespace:  # noqa: N802 -- matches MeshInterface's spelling
        """Delegate to the device's ``myInfo``."""
        return self._device.myInfo

    @property
    def metadata(self) -> SimpleNamespace:
        """Delegate to the device's ``metadata``."""
        return self._device.metadata

    def getMyNodeInfo(self) -> dict[str, int]:  # noqa: N802 -- matches MeshInterface's spelling
        """Delegate to the device's ``getMyNodeInfo()``."""
        return self._device.getMyNodeInfo()

    def getMyUser(self) -> dict[str, str]:  # noqa: N802 -- matches MeshInterface's spelling
        """Delegate to the device's ``getMyUser()`` (including its flaky-read gate)."""
        return self._device.getMyUser()

    def getPublicKey(self) -> str | None:  # noqa: N802 -- matches MeshInterface's spelling
        """Return this connection's staged public key, base64-encoded.

        Returns:
            The base64 encoding of this connection's staged
            ``localConfig.security.public_key``, or ``None`` when that
            field is empty. Deliberately reads the staged copy, not the
            device's persisted one -- today's behavior, preserved.
        """
        raw = bytes(self.localNode.localConfig.security.public_key)
        if not raw:
            return None
        import base64

        return base64.b64encode(raw).decode("ascii")

    def close(self) -> None:
        """Mark this connection closed, then close the underlying device.

        Looks up the device's ``close`` attribute dynamically (a plain
        method call), so a test that monkeypatches ``close`` onto the
        device *after* this connection was constructed still takes
        effect -- see ``test_e2e_adopt.py``'s slow-close test.
        """
        self.closed = True
        self._device.close()


@dataclass
class DeviceBus:
    """Records every connection attempt made through a patched backend.

    Attributes:
        current: The :class:`FakeMeshInterface` a patched ``connect()``
            call should return, or ``None`` to simulate no device being
            reachable.
        connections: Every ``(transport, target)`` pair a patched
            ``connect()`` call recorded, in call order.
        timeouts: Every patched ``connect()`` call's backend's
            ``timeout`` attribute, in call order -- lets a test prove
            ``--timeout`` actually reached the backend construction.
        served: The node hex of the device each ``connect()`` call
            returned, or ``None`` for a refused connect, in call order.
    """

    current: FakeMeshInterface | None = None
    connections: list[tuple[str, str]] = field(default_factory=list)
    timeouts: list[float] = field(default_factory=list)
    served: list[str | None] = field(default_factory=list)
    _queue: list[FakeMeshInterface | None] = field(default_factory=list)

    def use(self, iface: FakeMeshInterface) -> FakeMeshInterface:
        """Set the interface the next ``connect()`` call should return.

        Clears any devices queued by :meth:`then`.

        Args:
            iface: The fake interface to return.

        Returns:
            ``iface``, unchanged, for convenient chaining.
        """
        self.current = iface
        self._queue = []
        return iface

    def then(self, *ifaces: FakeMeshInterface | None) -> None:
        """Queue devices to serve on the connects that follow the current one.

        Counts **connects**, not refreshes. A factory provision on the
        example template connects three times: open, a mid-plan refresh
        after the rebooting ``lora`` section, and the final verify. Tests
        should assert :attr:`served` to make their count assumption
        visible.

        ``bus.use(a); bus.then(b)``: connect #1 returns ``a``, #2 onward
        returns ``b``. ``bus.use(a); bus.then(a, b)``: #1 and #2 return
        ``a``, #3 onward returns ``b``. A queued ``None`` makes every
        connect from that point on raise :class:`ConnectionFailedError`,
        until a later queued device is reached.

        Args:
            ifaces: Devices (or ``None``, for a refused connect) to serve
                on subsequent connects, in order.
        """
        self._queue.extend(ifaces)

    @property
    def targets(self) -> tuple[str, ...]:
        """Every recorded connection's target, in call order.

        Returns:
            A tuple of target strings.
        """
        return tuple(target for _transport, target in self.connections)

    @property
    def transports(self) -> tuple[str, ...]:
        """Every recorded connection's transport, in call order.

        Returns:
            A tuple of transport names.
        """
        return tuple(transport for transport, _target in self.connections)


@pytest.fixture
def bus(monkeypatch: pytest.MonkeyPatch) -> DeviceBus:
    """Patch all three connection backends' ``connect()`` at the class level.

    Patching the class (rather than ``cli.provision.resolve_backend``)
    keeps the real transport-selection logic under test.

    Args:
        monkeypatch: The pytest monkeypatch fixture.

    Returns:
        The :class:`DeviceBus` that records every connection attempt.
    """
    device_bus = DeviceBus()

    def _connect(self: connection.SerialBackend) -> MeshInterface:
        device_bus.connections.append((self.transport, self.target))
        device_bus.timeouts.append(self.timeout)
        serving = device_bus.current
        device_bus.served.append(serving.nid.hex if serving is not None else None)
        if device_bus._queue:
            device_bus.current = device_bus._queue.pop(0)
        if serving is None:
            raise ConnectionFailedError(
                f"no fake device configured for {self.transport} {self.target}",
                transport=self.transport,
                target=self.target,
            )
        return serving.connect()  # type: ignore[return-value]

    monkeypatch.setattr(connection.SerialBackend, "connect", _connect)
    monkeypatch.setattr(connection.BLEBackend, "connect", _connect)
    monkeypatch.setattr(connection.TCPBackend, "connect", _connect)
    return device_bus


@pytest.fixture
def fake_serial_ports(monkeypatch: pytest.MonkeyPatch) -> Callable[..., None]:
    """Patch serial-port discovery, defaulting to zero ports found.

    Args:
        monkeypatch: The pytest monkeypatch fixture.

    Returns:
        A ``set_ports(*devices)`` function that re-patches discovery to
        report the given device paths.
    """

    def set_ports(*devices: str) -> None:
        ports = tuple(
            discovery.SerialPortInfo(device=d, vid=0x239A, pid=0x80F2, description="Fake")
            for d in devices
        )
        monkeypatch.setattr(discovery, "discover_serial_ports", lambda **_kw: ports)

    set_ports()
    return set_ports


@pytest.fixture
def fake_ble_devices(monkeypatch: pytest.MonkeyPatch) -> Callable[..., None]:
    """Patch BLE discovery, defaulting to zero devices found.

    Args:
        monkeypatch: The pytest monkeypatch fixture.

    Returns:
        A ``set_devices(*addresses)`` function that re-patches discovery
        to report the given BLE addresses.
    """

    def set_devices(*addresses: str) -> None:
        devices = tuple(
            discovery.BleDeviceInfo(address=a, name=f"Meshtastic_{a[-4:]}", rssi=-60)
            for a in addresses
        )
        monkeypatch.setattr(discovery, "discover_ble_devices", lambda **_kw: devices)

    set_devices()
    return set_devices


@pytest.fixture
def db_path(empty_ods: Path) -> Path:
    """Alias the shared ``empty_ods`` fixture under a stable local name.

    Args:
        empty_ods: The empty-database path fixture owned by
            ``tests/conftest.py``.

    Returns:
        The same path as ``empty_ods``.
    """
    return empty_ods


@pytest.fixture
def seed_db(db_path: Path) -> Callable[..., Path]:
    """Build a callable that seeds ``db_path`` with node and key rows.

    Args:
        db_path: The database path to seed.

    Returns:
        A ``seed(nodes=(), keys=()) -> Path`` function that writes the
        given records (via ``ods_write.write_database(..., backup=False)``) and
        returns ``db_path``.
    """

    def _seed(nodes: Sequence[NodeRecord] = (), keys: Sequence[KeyRecord] = ()) -> Path:
        ods_write.write_database(
            db_path,
            nodes=[record.to_row() for record in nodes],
            keys=[record.to_row() for record in keys],
            backup=False,
        )
        return db_path

    return _seed


@pytest.fixture
def env(
    cli_env: dict[str, str], db_path: Path, write_template: Callable[..., Path]
) -> dict[str, str]:
    """Build the full environment mapping for a ``mesh`` CLI invocation.

    Args:
        cli_env: The base CLI environment fixture owned by
            ``tests/conftest.py``.
        db_path: The seeded (or empty) database path.
        write_template: The template-writing fixture owned by
            ``tests/conftest.py``.

    Returns:
        ``cli_env`` plus ``MESHPROVISION_DB_PATH`` and
        ``MESHPROVISION_TEMPLATE_PATH`` pointing at ``db_path`` and an
        unmodified example template, respectively.
    """
    result = dict(cli_env)
    result["MESHPROVISION_DB_PATH"] = str(db_path)
    result["MESHPROVISION_TEMPLATE_PATH"] = str(write_template())
    return result


@pytest.fixture
def runner() -> CliRunner:
    """Build a fresh :class:`click.testing.CliRunner`.

    Returns:
        A new :class:`CliRunner`.
    """
    return CliRunner()


def invoke(
    runner: CliRunner, args: Sequence[str], env: Mapping[str, str], *, input: str | None = None
) -> Result:
    """Invoke the ``mesh`` CLI, always with ``catch_exceptions=False``.

    Args:
        runner: The :class:`CliRunner` to invoke through.
        args: The CLI arguments, for example ``["provision", "--yes"]``.
        env: The environment mapping to run under.
        input: Simulated stdin text, for an interactive prompt.

    Returns:
        The invocation :class:`~click.testing.Result`.
    """
    return runner.invoke(cli, list(args), env=dict(env), input=input, catch_exceptions=False)


def _to_lorastats_record(hex_id: str, fields: Mapping[str, object]) -> dict[str, object]:
    """Derive a lorastats-shaped record from a loranet-shaped fixture entry.

    Args:
        hex_id: The node's hex id.
        fields: The loranet-shaped fields supplied to :func:`mock_sources`.

    Returns:
        A ``Nodes/JSON``-shaped record: always carries ``NodeId``, plus
        ``ShortName``/``LongName`` when present in ``fields`` and a
        ``LastSeen`` derived from an explicit ``last_seen_iso`` override
        or from the maximum epoch in a ``seenBy`` mapping.
    """
    record: dict[str, object] = {"NodeId": hex_id}
    if "shortName" in fields:
        record["ShortName"] = fields["shortName"]
    if "longName" in fields:
        record["LongName"] = fields["longName"]
    last_seen = fields.get("last_seen_iso")
    if last_seen is None:
        seen_by = fields.get("seenBy")
        if isinstance(seen_by, Mapping) and seen_by:
            epochs = [v for v in seen_by.values() if isinstance(v, int)]
            if epochs:
                last_seen = (
                    datetime.fromtimestamp(max(epochs), tz=UTC)
                    .isoformat(timespec="seconds")
                    .replace("+00:00", "Z")
                )
    if last_seen is not None:
        record["LastSeen"] = last_seen
    return record


@pytest.fixture
def mock_sources() -> Callable[..., respx.MockRouter]:
    """Build a factory for a respx router mocking both loranet and lorastats.

    Returns:
        A ``mock(nodes=None, *, lorastats_body=None, lorastats_status=200,
        region="PL") -> respx.MockRouter`` factory. ``nodes`` maps hex
        node id to a mapping of loranet-shaped raw fields (``shortName``,
        ``longName``, ``seenBy``, ``chUtil``, ...); the loranet route
        returns a JSON object keyed by *decimal* node id (built via
        ``NodeId.from_hex(hex_id).decimal``, never by hand), and the
        lorastats route filters by the ``?node=<hex>`` query parameter,
        returning records derived via :func:`_to_lorastats_record`.
        Passing ``lorastats_body`` makes the lorastats route return that
        text as an ``html`` response with the given status instead
        (used to simulate lorastats.pl's soft-404). The router is built
        with ``assert_all_called=False`` so a source-restricted run never
        fails for not calling every registered route.
    """

    def _mock(
        nodes: Mapping[str, Mapping[str, object]] | None = None,
        *,
        lorastats_body: str | None = None,
        lorastats_status: int = 200,
        region: str = "PL",
    ) -> respx.MockRouter:
        router = respx.MockRouter(assert_all_called=False)
        node_map = nodes or {}

        dump = {
            NodeId.from_hex(hex_id).decimal: dict(fields) for hex_id, fields in node_map.items()
        }
        router.get(LORANET_NODES_URL).mock(return_value=httpx.Response(200, json=dump))

        def _lorastats_handler(request: httpx.Request) -> httpx.Response:
            if lorastats_body is not None:
                return httpx.Response(lorastats_status, html=lorastats_body)
            queried = request.url.params.get("node")
            records = [
                _to_lorastats_record(hex_id, fields)
                for hex_id, fields in node_map.items()
                if queried is None or hex_id == queried
            ]
            return httpx.Response(200, json=records)

        lorastats_url = f"{LORASTATS_BASE_URL}{LORASTATS_NODES_PATH.format(region=region)}"
        router.get(url__startswith=lorastats_url).mock(side_effect=_lorastats_handler)
        return router

    return _mock


def db_fingerprint(path: Path) -> tuple[int, str]:
    """Build the read-only / not-written assertion primitive for one file.

    Args:
        path: The file to fingerprint.

    Returns:
        ``(mtime_ns, sha256_hexdigest)``: identical values across two
        calls prove the file was never touched in between.
    """
    return path.stat().st_mtime_ns, __import__("hashlib").sha256(path.read_bytes()).hexdigest()
