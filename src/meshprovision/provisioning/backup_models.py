"""The parsed-backup value types: what :mod:`meshprovision.provisioning.backup_parse` builds.

Split out of :mod:`meshprovision.provisioning.backup` for size, with no change
in behavior; that module re-exports every name here unchanged. Pure data: no
parsing, no filesystem access. Secret hygiene: :class:`ProfileBackup` never
exposes its private key except wrapped in
:class:`~meshprovision.crypto.redact.SecretBytes`, and no ``__repr__`` here
prints raw public key or PSK bytes.

Import contract: only the standard library plus
:mod:`meshprovision.crypto.redact` and :mod:`meshprovision.nodeid`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from meshprovision.crypto.redact import SecretBytes, fingerprint, redact
from meshprovision.nodeid import NodeId

__all__ = [
    "BackupBundle",
    "BackupFormat",
    "ChannelInfo",
    "FixedPosition",
    "NodeDbBackup",
    "NodeDbEntry",
    "ProfileBackup",
]


class BackupFormat(StrEnum):
    """Which of the three supported backup shapes a file was sniffed as."""

    PROFILE_CFG = "profile_cfg"
    PROFILE_YAML = "profile_yaml"
    NODEDB_JSON = "nodedb_json"


@dataclass(frozen=True, slots=True)
class FixedPosition:
    """A decoded ``DeviceProfile.fixed_position``.

    Attributes:
        latitude: Decimal degrees.
        longitude: Decimal degrees.
        altitude: Meters, or ``None`` if the profile did not set one.
    """

    latitude: float
    longitude: float
    altitude: int | None = None


@dataclass(frozen=True, slots=True)
class ChannelInfo:
    """A decoded primary channel from a ``channel_url``.

    Attributes:
        name: The channel's name, or ``""`` if unset (the default
            channel name is implied by firmware, not carried in the URL).
        psk: The raw PSK bytes, in whatever length the app encoded: ``0``
            (no encryption), ``1`` (a "default" preset PSK, an index into
            a firmware-side table -- not a real key), ``16`` (AES128), or
            ``32`` (AES256). Only the 32-byte form is real, standalone
            key material this project's ``Keys`` sheet can hold -- see
            :mod:`meshprovision.cli.adopt_backup`.
    """

    name: str
    psk: bytes

    def __repr__(self) -> str:
        """Return a repr that never exposes raw PSK bytes.

        Returns:
            :attr:`name` unredacted, :attr:`psk` replaced by its length
            and, when non-empty, its fingerprint.
        """
        psk_label = f"<{len(self.psk)}B:{fingerprint(self.psk)}>" if self.psk else "<empty>"
        return f"ChannelInfo(name={self.name!r}, psk={psk_label})"


@dataclass(frozen=True, slots=True)
class ProfileBackup:
    """A parsed ``.cfg``/``.yaml`` ``DeviceProfile`` backup.

    Carries the raw ``LocalConfig``/``LocalModuleConfig`` protobuf
    messages internally so :func:`live_config_from_backup` can build a
    full :class:`~meshprovision.provisioning.detect.LiveConfig` from them
    once a node id is known -- external callers should treat
    :attr:`local_config`/:attr:`module_config` as opaque and never read
    fields off them directly; every field this project cares about is
    already exposed on this dataclass or reachable through
    :func:`live_config_from_backup`.

    Attributes:
        source: The backup file's path, for error messages.
        long_name: The device's ``long_name``, as exported.
        short_name: The device's ``short_name``, as exported.
        public_key: The node's own public key, or ``None`` if unset.
        private_key: The node's own private key, wrapped in
            :class:`~meshprovision.crypto.redact.SecretBytes`, or
            ``None`` if unset.
        channel: The decoded primary channel, or ``None`` if
            ``channel_url`` was empty or undecodable.
        fixed_position: The decoded fixed position, or ``None`` if unset.
        local_config: The raw ``LocalConfig`` protobuf message. Internal.
        module_config: The raw ``LocalModuleConfig`` protobuf message.
            Internal.
        warnings: Non-fatal findings about the file itself -- for
            example, a non-empty ``channel_url`` that failed to decode
            (distinct from a genuinely absent one, which warns about
            nothing: see :func:`decode_channel_url`).
    """

    source: str
    long_name: str
    short_name: str
    public_key: bytes | None
    private_key: SecretBytes | None
    channel: ChannelInfo | None
    fixed_position: FixedPosition | None
    local_config: Any = field(repr=False)
    module_config: Any = field(repr=False)
    warnings: tuple[str, ...] = ()

    def __repr__(self) -> str:
        """Return a repr that never exposes raw key bytes.

        Returns:
            A redacted representation with :attr:`public_key` replaced
            by its fingerprint; :attr:`private_key` is already safe
            (:class:`~meshprovision.crypto.redact.SecretBytes` redacts
            its own repr).
        """
        public = redact(self.public_key) if self.public_key else "None"
        return (
            f"ProfileBackup(source={self.source!r}, long_name={self.long_name!r}, "
            f"short_name={self.short_name!r}, public_key={public}, "
            f"private_key={self.private_key!r}, channel={self.channel!r}, "
            f"fixed_position={self.fixed_position!r})"
        )


@dataclass(frozen=True, slots=True)
class NodeDbEntry:
    """One node's entry from a node-db JSON export.

    Attributes:
        num: The node's raw (unsigned 32-bit) node number.
        node_id: :attr:`num` as a :class:`~meshprovision.nodeid.NodeId`,
            or ``None`` if it did not parse.
        long_name: The node's ``longName``, when non-empty.
        short_name: The node's ``shortName``, when non-empty.
        hw_model: The node's ``hwModel`` name string, when non-empty.
        role: The node's ``role`` name string, when non-empty.
        public_key: The node's base64-decoded ``publicKey``, when
            present and valid base64.
        firmware_version: ``metadata.firmwareVersion``, when non-empty.
    """

    num: int
    node_id: NodeId | None
    long_name: str | None
    short_name: str | None
    hw_model: str | None
    role: str | None
    public_key: bytes | None
    firmware_version: str | None

    def __repr__(self) -> str:
        """Return a repr that never exposes raw public key bytes.

        Returns:
            :attr:`public_key` replaced by its fingerprint; every other
            field unredacted.
        """
        public = redact(self.public_key) if self.public_key else "None"
        return (
            f"NodeDbEntry(num={self.num!r}, node_id={self.node_id!r}, "
            f"long_name={self.long_name!r}, short_name={self.short_name!r}, "
            f"hw_model={self.hw_model!r}, role={self.role!r}, public_key={public}, "
            f"firmware_version={self.firmware_version!r})"
        )


@dataclass(frozen=True, slots=True)
class NodeDbBackup:
    """A parsed node-db JSON export.

    Attributes:
        source: The backup file's path, for error messages.
        my_node_num: The exporting device's own ``myNodeNum``, or
            ``None`` if absent or not an integer.
        entries: Every node entry found in ``nodes``, in file order.
        warnings: Non-fatal findings about the file itself (for example,
            an unrecognized ``schemaVersion``).
    """

    source: str
    my_node_num: int | None
    entries: tuple[NodeDbEntry, ...]
    warnings: tuple[str, ...] = ()

    def own_entry(self) -> NodeDbEntry | None:
        """Find the entry matching :attr:`my_node_num`.

        This is the entry a real export always has: the app writes
        ``myNodeNum`` and includes the connected node's own view of
        itself among ``nodes``.

        Returns:
            The matching entry, or ``None`` if :attr:`my_node_num` is
            unset or matches no entry.
        """
        if self.my_node_num is None:
            return None
        for entry in self.entries:
            if entry.num == self.my_node_num:
                return entry
        return None


def _first_nonempty(*values: str | None) -> str:
    """Return the first non-``None``, non-empty string, or ``""``.

    Args:
        *values: Candidate strings, in preference order.

    Returns:
        The first value that is neither ``None`` nor ``""``, else ``""``.
    """
    for value in values:
        if value:
            return value
    return ""


@dataclass(frozen=True, slots=True)
class BackupBundle:
    """The merged view of one or two backup files, ready to resolve and adopt.

    A ``.cfg``/``.yaml`` profile and a node-db export are complementary
    (see the module docstring); either may be supplied alone.

    Attributes:
        profile: The parsed profile backup, or ``None`` if none was
            supplied.
        nodedb_entry: The node-db export's own entry (see
            :meth:`NodeDbBackup.own_entry`), or ``None`` if no node-db
            backup was supplied, or its ``myNodeNum`` matched no entry.
        warnings: Non-fatal findings from merging, surfaced by the CLI
            alongside :class:`~meshprovision.provisioning.adopt.AdoptionReport.warnings`.
    """

    profile: ProfileBackup | None
    nodedb_entry: NodeDbEntry | None
    warnings: tuple[str, ...] = ()

    @property
    def long_name(self) -> str:
        """The best available ``long_name``, preferring the profile's.

        Returns:
            The profile's ``long_name`` when non-empty; otherwise the
            node-db entry's; otherwise ``""``.
        """
        return _first_nonempty(
            self.profile.long_name if self.profile is not None else None,
            self.nodedb_entry.long_name if self.nodedb_entry is not None else None,
        )

    @property
    def short_name(self) -> str:
        """The best available ``short_name``, preferring the profile's.

        Returns:
            The profile's ``short_name`` when non-empty; otherwise the
            node-db entry's; otherwise ``""``.
        """
        return _first_nonempty(
            self.profile.short_name if self.profile is not None else None,
            self.nodedb_entry.short_name if self.nodedb_entry is not None else None,
        )

    @property
    def public_key(self) -> bytes | None:
        """The node's own public key, from whichever backup carries it.

        Returns:
            The profile's public key when set; otherwise the node-db
            entry's; otherwise ``None``.
        """
        if self.profile is not None and self.profile.public_key is not None:
            return self.profile.public_key
        if self.nodedb_entry is not None and self.nodedb_entry.public_key is not None:
            return self.nodedb_entry.public_key
        return None

    @property
    def channel(self) -> ChannelInfo | None:
        """The decoded primary channel, when a profile supplied one.

        Returns:
            :attr:`ProfileBackup.channel`, or ``None`` if no profile was
            supplied.
        """
        return self.profile.channel if self.profile is not None else None

    @property
    def fixed_position(self) -> FixedPosition | None:
        """The decoded fixed position, when a profile supplied one.

        Returns:
            :attr:`ProfileBackup.fixed_position`, or ``None`` if no
            profile was supplied.
        """
        return self.profile.fixed_position if self.profile is not None else None
