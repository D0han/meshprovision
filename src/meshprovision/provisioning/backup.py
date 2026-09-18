"""Parse a Meshtastic app config backup into a normalized live-config shape.

This is the file-based counterpart to :mod:`meshprovision.provisioning.detect`:
where ``detect.py`` reads a live device's protobuf state off a connected
``MeshInterface``, this module reads the same shape of protobuf state out
of a file the operator exported earlier -- typically from the Meshtastic
Android app, so a node that cannot currently be reached (deployed
remotely, lent out, on a roof) can still be recorded with ``mesh adopt
--from-backup``. See :func:`live_config_from_backup` for the bridge back
into :class:`~meshprovision.provisioning.detect.LiveConfig`.

Three file shapes are recognized, auto-detected by content
(:func:`sniff_format`), verified against ``meshtastic/Meshtastic-Android``
and the installed ``meshtastic==2.7.11`` protobufs:

- **A ``.cfg`` profile** -- Radio Config -> Backup & Restore -> Export in
  the app. A raw ``clientonly_pb2.DeviceProfile`` protobuf: names,
  ``channel_url``, the full ``LocalConfig``/``LocalModuleConfig``
  (including ``security.public_key``/``private_key``/``admin_key``), the
  BLE PIN, region, role, and an optional fixed position. Carries no node
  id, hw model, or firmware version.
- **A ``.yaml`` profile** -- ``meshtastic --export-config``'s YAML output
  (the Python CLI, not the app). Same content as a ``.cfg``, with
  ``owner``/``owner_short``/``location`` at the top level and key bytes
  prefixed ``"base64:"``.
- **A node-db JSON export** -- Settings -> Export node database in the
  app (``Meshtastic_nodedb_<SHORT>_<ts>.json``). Carries ``myNodeNum``
  and, for the node's own entry, ``id``/``hwModel``/``role``/``publicKey``
  (base64)/``metadata.firmwareVersion`` -- exactly what a ``.cfg`` is
  missing. Carries no private key, admin keys, region, or channel.

:func:`load_backup` is the only function here that touches the
filesystem; everything else is a pure ``bytes``/``str`` -> value parser,
mirroring the ``load_template``/``load_template_text`` split in
:mod:`meshprovision.config.template`. Node identity is never inferred by
this module -- :func:`live_config_from_backup` takes the resolved
``node_id`` as an explicit argument; deciding what that id *is* belongs
to the CLI layer (``mesh adopt --from-backup``), which alone has database
and network access to cross-check it.

Secret hygiene: :class:`ProfileBackup` never exposes its private key
except wrapped in :class:`~meshprovision.crypto.redact.SecretBytes`, and
its ``__repr__`` never prints raw public key or PSK bytes.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from google.protobuf import json_format
from google.protobuf.message import DecodeError
from meshtastic.protobuf import apponly_pb2, clientonly_pb2, localonly_pb2

from meshprovision import enums
from meshprovision.crypto.redact import SecretBytes, fingerprint
from meshprovision.errors import BackupParseError
from meshprovision.nodeid import NodeId
from meshprovision.provisioning import detect

if TYPE_CHECKING:
    from collections.abc import Mapping

    from meshprovision.datasources.models import NodeObservation

__all__ = [
    "BackupBundle",
    "BackupFormat",
    "ChannelInfo",
    "FixedPosition",
    "NodeDbBackup",
    "NodeDbEntry",
    "ProfileBackup",
    "decode_channel_url",
    "live_config_from_backup",
    "load_backup",
    "merge_backups",
    "parse_nodedb_json",
    "parse_profile_cfg",
    "parse_profile_yaml",
    "sniff_format",
    "suggest_node_ids_by_name",
]

_NODEDB_MARKER_KEYS: frozenset[str] = frozenset({"nodes", "schemaVersion"})
"""Top-level keys whose presence identifies a node-db JSON export."""

_PROFILE_YAML_MARKER_KEYS: frozenset[str] = frozenset(
    {"owner", "owner_short", "ownerShort", "channel_url", "channelUrl", "config", "module_config"}
)
"""Top-level keys whose presence identifies a ``--export-config`` YAML profile."""

_B64_PREFIX: str = "base64:"
"""The Meshtastic CLI YAML export's marker for a base64-encoded bytes field."""


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
            :mod:`meshprovision.cli.adopt`.
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

    def __repr__(self) -> str:
        """Return a repr that never exposes raw key bytes.

        Returns:
            A redacted representation with :attr:`public_key` replaced
            by its fingerprint; :attr:`private_key` is already safe
            (:class:`~meshprovision.crypto.redact.SecretBytes` redacts
            its own repr).
        """
        public = f"<redacted:{fingerprint(self.public_key)}>" if self.public_key else "None"
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
        public = f"<redacted:{fingerprint(self.public_key)}>" if self.public_key else "None"
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


def merge_backups(
    profile: ProfileBackup | None = None, nodedb: NodeDbBackup | None = None
) -> BackupBundle:
    """Merge a profile backup and/or a node-db backup into one bundle.

    Args:
        profile: A parsed ``.cfg``/``.yaml`` profile, or ``None``.
        nodedb: A parsed node-db JSON export, or ``None``.

    Returns:
        The merged :class:`BackupBundle`.

    Raises:
        BackupParseError: If both arguments are ``None``, or if both are
            supplied and disagree about which node they describe
            (conflicting non-empty ``long_name``, ``short_name``, or
            public key).
    """
    if profile is None and nodedb is None:
        raise BackupParseError("At least one backup file is required.")

    warnings: list[str] = list(nodedb.warnings) if nodedb is not None else []
    entry = nodedb.own_entry() if nodedb is not None else None
    if nodedb is not None and entry is None:
        warnings.append(
            f"{nodedb.source}: myNodeNum ({nodedb.my_node_num!r}) was not found among its "
            "own node entries; hw_model, firmware_version, and role from this file could "
            "not be recovered."
        )

    nodedb_source = nodedb.source if nodedb is not None else ""
    if profile is not None and entry is not None:
        if profile.long_name and entry.long_name and profile.long_name != entry.long_name:
            raise BackupParseError(
                f"Conflicting long_name between backups: {profile.source} says "
                f"{profile.long_name!r}, {nodedb_source} says {entry.long_name!r}. These "
                "backups may not be for the same node.",
                source=nodedb_source,
            )
        if profile.short_name and entry.short_name and profile.short_name != entry.short_name:
            raise BackupParseError(
                f"Conflicting short_name between backups: {profile.source} says "
                f"{profile.short_name!r}, {nodedb_source} says {entry.short_name!r}. These "
                "backups may not be for the same node.",
                source=nodedb_source,
            )
        if (
            profile.public_key is not None
            and entry.public_key is not None
            and profile.public_key != entry.public_key
        ):
            raise BackupParseError(
                f"Conflicting public key between {profile.source} and {nodedb_source}: "
                "these backups appear to be for different nodes.",
                source=nodedb_source,
            )

    return BackupBundle(profile=profile, nodedb_entry=entry, warnings=tuple(warnings))


def decode_channel_url(url: str) -> ChannelInfo | None:
    """Decode a ``https://meshtastic.org/e/#...`` channel URL's primary channel.

    Degrades to ``None`` on any malformed input rather than raising --
    the same degrade-not-crash convention
    :mod:`meshprovision.provisioning.detect` applies to malformed device
    data, since a channel URL is optional context, never load-bearing for
    node identity.

    Args:
        url: A full channel URL, or just its fragment.

    Returns:
        The first (primary) channel's :class:`ChannelInfo`, or ``None``
        if ``url`` has no ``#`` fragment, the fragment is not valid
        base64url, it does not decode to a ``ChannelSet`` protobuf, or
        the decoded ``ChannelSet`` has no channels.
    """
    fragment = url.split("#", 1)[1] if "#" in url else url
    fragment = fragment.strip()
    if not fragment:
        return None
    padded = fragment + "=" * (-len(fragment) % 4)
    try:
        data = base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError):
        return None
    channel_set = apponly_pb2.ChannelSet()
    try:
        channel_set.ParseFromString(data)
    except DecodeError:
        return None
    if not channel_set.settings:
        return None
    primary = channel_set.settings[0]
    return ChannelInfo(name=primary.name, psk=bytes(primary.psk))


def sniff_format(raw: bytes) -> BackupFormat | None:
    """Detect which of the three supported backup shapes ``raw`` is.

    Pure and never raises. Tries UTF-8 JSON first, then UTF-8 YAML, then
    falls back to a ``DeviceProfile`` protobuf parse -- verified against
    the installed protobufs that a JSON or YAML document's bytes make
    ``DeviceProfile.ParseFromString`` raise (never silently succeed), and
    that empty input raises too, so this ordering cannot misclassify a
    text file as a profile. A successfully parsed protobuf is further
    required to have at least one field set (:meth:`ListFields`
    non-empty) -- arbitrary bytes must not be accepted as a valid, merely
    empty, profile.

    Args:
        raw: The file's raw bytes.

    Returns:
        The detected format, or ``None`` if ``raw`` matches none of the
        three shapes.
    """
    text: str | None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = None

    if text is not None:
        stripped = text.strip()
        if stripped.startswith("{"):
            try:
                doc = json.loads(stripped)
            except json.JSONDecodeError:
                doc = None
            if isinstance(doc, dict) and _NODEDB_MARKER_KEYS & doc.keys():
                return BackupFormat.NODEDB_JSON
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            doc = None
        if isinstance(doc, dict) and _PROFILE_YAML_MARKER_KEYS & doc.keys():
            return BackupFormat.PROFILE_YAML

    profile = clientonly_pb2.DeviceProfile()
    try:
        profile.ParseFromString(raw)
    except (DecodeError, NotImplementedError):
        return None
    if not profile.ListFields():
        return None
    return BackupFormat.PROFILE_CFG


def parse_profile_cfg(raw: bytes, *, source: str) -> ProfileBackup:
    """Parse a binary ``.cfg`` ``DeviceProfile`` export.

    Args:
        raw: The file's raw bytes.
        source: A label for the file, used in error messages.

    Returns:
        The parsed :class:`ProfileBackup`.

    Raises:
        BackupParseError: If ``raw`` does not parse as a ``DeviceProfile``
            protobuf.
    """
    profile = clientonly_pb2.DeviceProfile()
    try:
        profile.ParseFromString(raw)
    except (DecodeError, NotImplementedError) as exc:
        raise BackupParseError(
            f"{source}: not a valid DeviceProfile (.cfg) file: {exc}", source=source
        ) from exc
    return _profile_backup_from_message(profile, source=source)


def _profile_backup_from_message(
    profile: clientonly_pb2.DeviceProfile, *, source: str
) -> ProfileBackup:
    """Build a :class:`ProfileBackup` from an already-parsed ``DeviceProfile``.

    Args:
        profile: The parsed protobuf message.
        source: A label for the file, used in error messages.

    Returns:
        The constructed :class:`ProfileBackup`.
    """
    sec = profile.config.security
    public_key = bytes(sec.public_key) or None
    private_key = bytes(sec.private_key) or None
    channel = decode_channel_url(profile.channel_url) if profile.channel_url else None

    fixed_position: FixedPosition | None = None
    if profile.HasField("fixed_position"):
        fp = profile.fixed_position
        fixed_position = FixedPosition(
            latitude=fp.latitude_i / 1e7,
            longitude=fp.longitude_i / 1e7,
            altitude=fp.altitude or None,
        )

    return ProfileBackup(
        source=source,
        long_name=profile.long_name,
        short_name=profile.short_name,
        public_key=public_key,
        private_key=SecretBytes(private_key) if private_key else None,
        channel=channel,
        fixed_position=fixed_position,
        local_config=profile.config,
        module_config=profile.module_config,
    )


def _strip_base64_prefix(value: object) -> object:
    """Recursively strip the Meshtastic CLI YAML export's ``"base64:"`` marker.

    Args:
        value: A JSON-like value: a string, list, dict, or scalar.

    Returns:
        ``value`` with every string starting with :data:`_B64_PREFIX`
        having that prefix removed, recursively through lists and dicts.
        Non-string, non-container values are returned unchanged.
    """
    if isinstance(value, str):
        return value[len(_B64_PREFIX) :] if value.startswith(_B64_PREFIX) else value
    if isinstance(value, list):
        return [_strip_base64_prefix(item) for item in value]
    if isinstance(value, dict):
        return {key: _strip_base64_prefix(item) for key, item in value.items()}
    return value


def _apply_yaml_section(section: object, target: Any, *, source: str, name: str) -> None:
    """Parse one YAML ``config``/``module_config`` section into a protobuf message.

    Args:
        section: The section's decoded YAML value, expected to be a
            mapping.
        target: The ``LocalConfig``/``LocalModuleConfig`` message to
            populate in place.
        source: A label for the file, used in error messages.
        name: The section's key, for error messages (``"config"`` or
            ``"module_config"``).

    Raises:
        BackupParseError: If ``section`` is not a mapping, or its
            contents do not match the target message's shape.
    """
    if not isinstance(section, dict):
        raise BackupParseError(f"{source}: {name!r} must be a mapping.", source=source)
    cleaned = {key: _strip_base64_prefix(item) for key, item in section.items()}
    try:
        json_format.ParseDict(cleaned, target, ignore_unknown_fields=True)
    except json_format.ParseError as exc:
        raise BackupParseError(f"{source}: invalid {name!r} section: {exc}", source=source) from exc


def parse_profile_yaml(text: str, *, source: str) -> ProfileBackup:
    """Parse a ``meshtastic --export-config`` YAML profile.

    Deliberately does not call into ``meshtastic.__main__``'s own
    ``_read_profile``/``_profile_from_yaml`` -- private, unstable
    functions of a console-script module, not a supported import surface.
    This function is this project's own, narrower reimplementation of
    just the fields it cares about, using the public
    ``google.protobuf.json_format.ParseDict`` as the actual protobuf
    decoder.

    Args:
        text: The file's decoded text.
        source: A label for the file, used in error messages.

    Returns:
        The parsed :class:`ProfileBackup`.

    Raises:
        BackupParseError: If ``text`` is not valid YAML, its top level is
            not a mapping, or a ``config``/``module_config`` section does
            not match the expected protobuf shape.
    """
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise BackupParseError(f"{source}: invalid YAML: {exc}", source=source) from exc
    if not isinstance(doc, dict):
        raise BackupParseError(
            f"{source}: expected a YAML mapping at the top level.", source=source
        )

    long_name = str(doc.get("owner") or "")
    short_name = str(doc.get("owner_short") or doc.get("ownerShort") or "")
    channel_url = str(doc.get("channel_url") or doc.get("channelUrl") or "")

    local_config = localonly_pb2.LocalConfig()
    module_config = localonly_pb2.LocalModuleConfig()

    config_section = doc.get("config")
    if config_section is not None:
        _apply_yaml_section(config_section, local_config, source=source, name="config")
    module_section = doc.get("module_config")
    if module_section is not None:
        _apply_yaml_section(module_section, module_config, source=source, name="module_config")

    channel = decode_channel_url(channel_url) if channel_url else None

    fixed_position: FixedPosition | None = None
    location = doc.get("location")
    if isinstance(location, dict):
        lat = float(location.get("lat") or 0)
        lon = float(location.get("lon") or 0)
        alt = location.get("alt")
        if lat or lon:
            fixed_position = FixedPosition(
                latitude=lat, longitude=lon, altitude=int(alt) if alt else None
            )

    sec = local_config.security
    public_key = bytes(sec.public_key) or None
    private_key = bytes(sec.private_key) or None

    return ProfileBackup(
        source=source,
        long_name=long_name,
        short_name=short_name,
        public_key=public_key,
        private_key=SecretBytes(private_key) if private_key else None,
        channel=channel,
        fixed_position=fixed_position,
        local_config=local_config,
        module_config=module_config,
    )


def _clean_str(value: object) -> str | None:
    """Coerce a JSON value to a non-empty string, or ``None``.

    Args:
        value: A candidate JSON value.

    Returns:
        ``value`` itself if it is a non-empty ``str``; ``None`` for
        anything else (including an empty string).
    """
    return value if isinstance(value, str) and value else None


def parse_nodedb_json(raw: bytes, *, source: str) -> NodeDbBackup:
    """Parse a ``Meshtastic_nodedb_<SHORT>_<ts>.json`` node-db export.

    Args:
        raw: The file's raw bytes.
        source: A label for the file, used in error messages.

    Returns:
        The parsed :class:`NodeDbBackup`. A malformed individual entry
        (missing/non-numeric ``num``) is skipped rather than failing the
        whole file, mirroring
        :meth:`~meshprovision.datasources.loranet.LoranetSource.fetch_all`'s
        one-bad-entry tolerance.

    Raises:
        BackupParseError: If ``raw`` is not valid UTF-8 JSON, or its top
            level is not an object with a ``"nodes"`` array.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BackupParseError(f"{source}: not valid UTF-8: {exc}", source=source) from exc
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BackupParseError(f"{source}: invalid JSON: {exc}", source=source) from exc
    if not isinstance(doc, dict):
        raise BackupParseError(f"{source}: expected a JSON object at the top level.", source=source)
    nodes = doc.get("nodes")
    if not isinstance(nodes, list):
        raise BackupParseError(f'{source}: missing or invalid "nodes" array.', source=source)

    warnings: list[str] = []
    schema_version = doc.get("schemaVersion")
    if schema_version is not None and schema_version != 1:
        warnings.append(
            f"{source}: unrecognized schemaVersion {schema_version!r} (expected 1); "
            "parsing anyway, on a best-effort basis."
        )

    raw_my_node_num = doc.get("myNodeNum")
    my_node_num = int(raw_my_node_num) if isinstance(raw_my_node_num, int | float) else None

    entries: list[NodeDbEntry] = []
    for item in nodes:
        if not isinstance(item, dict):
            continue
        num = item.get("num")
        if not isinstance(num, int | float):
            continue
        num_int = int(num)

        public_key: bytes | None = None
        raw_public_key = item.get("publicKey")
        if isinstance(raw_public_key, str) and raw_public_key:
            try:
                public_key = base64.b64decode(raw_public_key, validate=True)
            except (binascii.Error, ValueError):
                public_key = None

        metadata = item.get("metadata")
        firmware_version = (
            _clean_str(metadata.get("firmwareVersion")) if isinstance(metadata, dict) else None
        )

        entries.append(
            NodeDbEntry(
                num=num_int,
                node_id=NodeId.try_parse(num_int),
                long_name=_clean_str(item.get("longName")),
                short_name=_clean_str(item.get("shortName")),
                hw_model=_clean_str(item.get("hwModel")),
                role=_clean_str(item.get("role")),
                public_key=public_key,
                firmware_version=firmware_version,
            )
        )

    return NodeDbBackup(
        source=source, my_node_num=my_node_num, entries=tuple(entries), warnings=tuple(warnings)
    )


def load_backup(path: Path) -> ProfileBackup | NodeDbBackup:
    """Read and parse one backup file, auto-detecting its format.

    The only function in this module that touches the filesystem.

    Args:
        path: Path to the backup file.

    Returns:
        A :class:`ProfileBackup` or :class:`NodeDbBackup`, depending on
        the detected format.

    Raises:
        BackupParseError: If ``path`` cannot be read, or its content
            matches none of the three supported formats (or matches one
            but fails that format's own validation).
    """
    source = str(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise BackupParseError(f"{source}: could not be read: {exc}", source=source) from exc

    fmt = sniff_format(raw)
    if fmt is None:
        raise BackupParseError(
            f"{source}: not a recognized backup format (tried node-db JSON, DeviceProfile "
            "YAML, and DeviceProfile protobuf).",
            source=source,
            hint=(
                "Export a .cfg or node-db .json from the Meshtastic app's Backup & Restore / "
                "Export node database screens, or a YAML file from `meshtastic --export-config`."
            ),
        )
    if fmt is BackupFormat.NODEDB_JSON:
        return parse_nodedb_json(raw, source=source)
    if fmt is BackupFormat.PROFILE_YAML:
        return parse_profile_yaml(raw.decode("utf-8"), source=source)
    return parse_profile_cfg(raw, source=source)


def live_config_from_backup(bundle: BackupBundle, *, node_id: NodeId) -> detect.LiveConfig:
    """Build a :class:`~meshprovision.provisioning.detect.LiveConfig` from a backup bundle.

    The file-based counterpart to
    :func:`meshprovision.provisioning.detect.read_live_config`: builds the
    exact same normalized shape, so every downstream consumer (``mesh
    adopt``'s report, weak-key auditing, name-pattern checking) works
    identically regardless of whether the live state came from a
    connected device or a backup file.

    Copies the profile's protobuf messages before handing them to
    :func:`~meshprovision.provisioning.detect.live_config_from_protobufs`
    (rather than mutating ``bundle.profile``'s own messages in place),
    so this function has no side effect on ``bundle`` and is safe to call
    more than once.

    Args:
        bundle: The merged backup bundle.
        node_id: The already-resolved node id (see
            :mod:`meshprovision.cli.adopt`'s ``resolve_node_id`` --
            never inferred here).

    Returns:
        The normalized :class:`~meshprovision.provisioning.detect.LiveConfig`.
    """
    if bundle.profile is not None:
        local_config = localonly_pb2.LocalConfig()
        local_config.CopyFrom(bundle.profile.local_config)
        module_config = localonly_pb2.LocalModuleConfig()
        module_config.CopyFrom(bundle.profile.module_config)
    else:
        local_config = localonly_pb2.LocalConfig()
        module_config = localonly_pb2.LocalModuleConfig()

    entry = bundle.nodedb_entry
    if entry is not None and entry.public_key and not bytes(local_config.security.public_key):
        local_config.security.public_key = entry.public_key
    if entry is not None and entry.role:
        role_value = enums.role_table().try_value(entry.role)
        if role_value is not None:
            local_config.device.role = role_value

    hw_model_raw = entry.hw_model if entry is not None else None
    hw_model = (enums.hw_model_table().try_name(hw_model_raw) or "") if hw_model_raw else ""
    firmware_version = (entry.firmware_version if entry is not None else "") or ""

    return detect.live_config_from_protobufs(
        local_config,
        module_config,
        node_id=node_id,
        short_name=bundle.short_name,
        long_name=bundle.long_name,
        hw_model=hw_model,
        hw_model_raw=hw_model_raw,
        firmware_version=firmware_version,
    )


def suggest_node_ids_by_name(
    observations: Mapping[NodeId, NodeObservation], *, long_name: str
) -> tuple[NodeId, ...]:
    """Find every observed node whose ``long_name`` matches, case/whitespace-insensitively.

    Pure: the caller (``mesh adopt --from-backup``) is responsible for
    fetching ``observations`` (typically from
    :meth:`~meshprovision.datasources.loranet.LoranetSource.fetch_all`,
    the only name-searchable source -- see the CLI's docstring for why
    lorastats cannot be searched by name). This is advisory only: the CLI
    must never adopt using a name match alone, only offer it as a
    ``--node-id`` hint.

    Args:
        observations: Every observed node to search, keyed by id.
        long_name: The backup's ``long_name`` to match against. An empty
            (after stripping) value always yields no matches.

    Returns:
        Every matching node id, sorted ascending by numeric value (for
        deterministic output; a node renamed to collide with another's
        old name is a real, if rare, possibility this project does not
        try to rank).
    """
    target = long_name.strip().casefold()
    if not target:
        return ()
    matches = [
        node_id
        for node_id, obs in observations.items()
        if (obs.long_name or "").strip().casefold() == target
    ]
    return tuple(sorted(matches, key=int))
