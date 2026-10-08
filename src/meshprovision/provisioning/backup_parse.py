"""Backup-file parsers: sniff a file's format and parse it into the backup value types.

Split out of :mod:`meshprovision.provisioning.backup` for size, with no change
in behavior; that module re-exports every public name here unchanged (see its
docstring for the three recognized file shapes). :func:`load_backup` is the only
function here that touches the filesystem; everything else is a pure
``bytes``/``str`` -> value parser.

Import contract: the standard library, ``yaml``, ``google.protobuf`` and
``meshtastic.protobuf``, plus :mod:`meshprovision.crypto.keys`,
:mod:`meshprovision.crypto.redact`, :mod:`meshprovision.errors`,
:mod:`meshprovision.nodeid` and :mod:`meshprovision.provisioning.backup_models`.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
from pathlib import Path
from typing import Any

import yaml
from google.protobuf import json_format
from google.protobuf.message import DecodeError
from meshtastic.protobuf import apponly_pb2, clientonly_pb2, localonly_pb2

from meshprovision.crypto.keys import X25519_KEY_SIZE
from meshprovision.crypto.redact import SecretBytes
from meshprovision.errors import BackupParseError
from meshprovision.nodeid import NodeId
from meshprovision.provisioning.backup_models import (
    BackupFormat,
    ChannelInfo,
    FixedPosition,
    NodeDbBackup,
    NodeDbEntry,
    ProfileBackup,
)

__all__ = [
    "decode_channel_url",
    "load_backup",
    "parse_nodedb_json",
    "parse_profile_cfg",
    "parse_profile_yaml",
    "sniff_format",
]

_NODEDB_MARKER_KEYS: frozenset[str] = frozenset({"nodes", "schemaVersion"})
"""Top-level keys whose presence identifies a node-db JSON export."""

_PROFILE_YAML_MARKER_KEYS: frozenset[str] = frozenset(
    {"owner", "owner_short", "ownerShort", "channel_url", "channelUrl", "config", "module_config"}
)
"""Top-level keys whose presence identifies a ``--export-config`` YAML profile."""

_B64_PREFIX: str = "base64:"
"""The Meshtastic CLI YAML export's marker for a base64-encoded bytes field."""

_NODE_NUM_MAX: int = 0xFFFFFFFF
"""The largest node number: Meshtastic node numbers are unsigned 32-bit."""

_LATITUDE_LIMIT: int = 90
"""The largest latitude magnitude, in decimal degrees."""

_LONGITUDE_LIMIT: int = 180
"""The largest longitude magnitude, in decimal degrees."""

_ALTITUDE_LIMIT: int = 2**31 - 1
"""The largest altitude magnitude, in meters: ``Position.altitude`` is an ``int32``."""

_NOT_UNICODE: str = "is not valid Unicode text (it holds a lone UTF-16 surrogate)"
"""Why a backup text field holding a lone surrogate is refused (profile) or dropped (node-db)."""


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
            protobuf, or its fixed position is out of range.
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
    warnings: tuple[str, ...] = ()
    if profile.channel_url and channel is None:
        warnings = (
            f"{source}: channel_url was present but could not be decoded; no channel PSK "
            "will be recorded.",
        )

    fixed_position: FixedPosition | None = None
    if profile.HasField("fixed_position"):
        fp = profile.fixed_position
        fixed_position = FixedPosition(
            latitude=_location_number(
                fp.latitude_i / 1e7,
                field="fixed_position.latitude_i",
                source=source,
                limit=_LATITUDE_LIMIT,
            ),
            longitude=_location_number(
                fp.longitude_i / 1e7,
                field="fixed_position.longitude_i",
                source=source,
                limit=_LONGITUDE_LIMIT,
            ),
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
        warnings=warnings,
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
            not a mapping, ``owner``/``owner_short`` holds a lone UTF-16
            surrogate (decoded from a YAML escape), a ``config``/
            ``module_config`` section does not match the expected
            protobuf shape, or a ``location`` value is not a number in
            range.
    """
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        # str(exc) calls MarkedYAMLError.get_snippet(), which quotes the
        # offending source line -- if that line is `privateKey: base64:...`,
        # the snippet echoes a fragment of the key into the error message.
        # Build the message from the structured problem/mark fields instead,
        # which carry no source text, and raise `from None` so the original
        # exception (and its snippet) never reaches a DEBUG traceback either.
        problem = getattr(exc, "problem", None) or type(exc).__name__
        context = getattr(exc, "context", None)
        detail = f"{context}; {problem}" if context else problem
        mark = getattr(exc, "problem_mark", None)
        if mark is not None:
            detail = f"{detail} (line {mark.line + 1}, column {mark.column + 1})"
        raise BackupParseError(f"{source}: invalid YAML: {detail}", source=source) from None
    if not isinstance(doc, dict):
        raise BackupParseError(
            f"{source}: expected a YAML mapping at the top level.", source=source
        )

    long_name = str(doc.get("owner") or "")
    short_name = str(doc.get("owner_short") or doc.get("ownerShort") or "")
    for key, name in (("owner", long_name), ("owner_short", short_name)):
        if _has_lone_surrogate(name):
            raise BackupParseError(f"{source}: {key} {_NOT_UNICODE}.", source=source)
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
    warnings: tuple[str, ...] = ()
    if channel_url and channel is None:
        warnings = (
            f"{source}: channel_url was present but could not be decoded; no channel PSK "
            "will be recorded.",
        )

    fixed_position = _yaml_fixed_position(doc.get("location"), source=source)

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
        warnings=warnings,
    )


def _location_number(value: object, *, field: str, source: str, limit: int) -> float:
    """Convert one position value to a finite float within ``[-limit, limit]``.

    Args:
        value: The raw value: a number, or a string holding one (a quoted
            YAML scalar). An absent or empty value means 0, as it always has.
        field: The value's name in the file, for the error message.
        source: A label for the file, used in error messages.
        limit: The largest magnitude allowed.

    Returns:
        The converted value.

    Raises:
        BackupParseError: If ``value`` is not a number (a boolean included),
            is ``NaN`` or infinite, or lies outside ``[-limit, limit]``.
    """
    if not value:
        return 0.0
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        raise BackupParseError(
            f"{source}: {field} must be a number, not {type(value).__name__}.", source=source
        )
    try:
        number = float(value)
    except (OverflowError, ValueError):
        raise BackupParseError(
            f"{source}: {field} {value!r} is not a number.", source=source
        ) from None
    if not math.isfinite(number):
        raise BackupParseError(
            f"{source}: {field} {value!r} is not a finite number.", source=source
        )
    if abs(number) > limit:
        raise BackupParseError(
            f"{source}: {field} {value!r} is outside the range -{limit}..{limit}.", source=source
        )
    return number


def _yaml_fixed_position(location: object, *, source: str) -> FixedPosition | None:
    """Build a YAML profile's fixed position from its ``location`` mapping.

    Args:
        location: The document's ``location`` value (``None`` when absent).
        source: A label for the file, used in error messages.

    Returns:
        The position, or ``None`` when ``location`` is not a mapping or
        both coordinates are 0. A fractional altitude is truncated to
        whole meters, as before.

    Raises:
        BackupParseError: If a coordinate or the altitude is not a
            number in range.
    """
    if not isinstance(location, dict):
        return None
    lat = _location_number(
        location.get("lat"), field="location.lat", source=source, limit=_LATITUDE_LIMIT
    )
    lon = _location_number(
        location.get("lon"), field="location.lon", source=source, limit=_LONGITUDE_LIMIT
    )
    if not (lat or lon):
        return None
    alt = _location_number(
        location.get("alt"), field="location.alt", source=source, limit=_ALTITUDE_LIMIT
    )
    return FixedPosition(latitude=lat, longitude=lon, altitude=int(alt) if alt else None)


def _node_number(value: object, *, field: str, source: str) -> int | None:
    """Convert a node-db JSON node number, refusing one that cannot be a node.

    Args:
        value: The raw JSON value.
        field: The value's name in the file, for the error message.
        source: A label for the file, used in error messages.

    Returns:
        The node number, or ``None`` when ``value`` is absent or not a
        number at all (a boolean included), which callers treat as missing.

    Raises:
        BackupParseError: If ``value`` is a number but not a whole one
            (``NaN`` and ``Infinity`` included), or lies outside
            ``0..0xFFFFFFFF``.
    """
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    if isinstance(value, float) and not (math.isfinite(value) and value.is_integer()):
        raise BackupParseError(f"{source}: {field} {value!r} is not a whole number.", source=source)
    number = int(value)
    if not 0 <= number <= _NODE_NUM_MAX:
        raise BackupParseError(
            f"{source}: {field} {value!r} is outside the 32-bit node-number range.", source=source
        )
    return number


def _clean_str(value: object) -> str | None:
    """Coerce a JSON value to a non-empty string, or ``None``.

    Args:
        value: A candidate JSON value.

    Returns:
        ``value`` itself if it is a non-empty ``str``; ``None`` for
        anything else (including an empty string).
    """
    return value if isinstance(value, str) and value else None


def _has_lone_surrogate(text: str) -> bool:
    """Return whether ``text`` holds a lone UTF-16 surrogate (U+D800-U+DFFF).

    A JSON escape, or a YAML double-quoted one, can decode to such a
    character. No UTF-8 stream or file can encode it, and
    :class:`~meshprovision.db.nodes.NodeRecord` rejects it, so a name
    holding one would crash the adopt that tries to record it.

    Args:
        text: The decoded string to check.

    Returns:
        True if ``text`` can't be encoded as UTF-8.
    """
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return True
    return False


def _entry_str(entry: dict[str, Any], key: str, *, node: str, warnings: list[str]) -> str | None:
    """Read one node-db entry's text field like :func:`_clean_str`, dropping a lone surrogate.

    A node-db export lists every node the device has heard, under the
    names those nodes report for themselves, so one broken name is
    dropped with a warning (like a malformed ``publicKey``) instead of
    refusing the whole file. The warning never echoes the value.

    Args:
        entry: The entry (or its ``metadata`` object).
        key: The field to read, e.g. ``"longName"``.
        node: Names the node in the warning, e.g. ``"<source>: node
            a0c4ddc5's"``.
        warnings: Collects the warning when the value is dropped.

    Returns:
        :func:`_clean_str` of ``entry[key]``, or ``None`` when that holds
        a lone surrogate.
    """
    text = _clean_str(entry.get(key))
    if text is not None and _has_lone_surrogate(text):
        warnings.append(f"{node} {key} {_NOT_UNICODE}; treating it as absent.")
        return None
    return text


def parse_nodedb_json(raw: bytes, *, source: str) -> NodeDbBackup:
    """Parse a ``Meshtastic_nodedb_<SHORT>_<ts>.json`` node-db export.

    Args:
        raw: The file's raw bytes.
        source: A label for the file, used in error messages.

    Returns:
        The parsed :class:`NodeDbBackup`. An individual entry that is not
        an object, or whose ``num`` is missing or not a number, is skipped
        rather than failing the whole file, mirroring
        :meth:`~meshprovision.datasources.loranet.LoranetSource.fetch_all`'s
        one-bad-entry tolerance.

    Raises:
        BackupParseError: If ``raw`` is not valid UTF-8 JSON, its top
            level is not an object with a ``"nodes"`` array, or
            ``myNodeNum`` or any entry's ``num`` is a number that cannot
            be a node number (fractional, ``NaN``/``Infinity``, or outside
            ``0..0xFFFFFFFF``) -- a node's identity is never guessed, so
            the whole file is refused.
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

    my_node_num = _node_number(doc.get("myNodeNum"), field="myNodeNum", source=source)

    entries: list[NodeDbEntry] = []
    for index, item in enumerate(nodes):
        if not isinstance(item, dict):
            continue
        num_int = _node_number(item.get("num"), field=f"nodes[{index}].num", source=source)
        if num_int is None:
            continue

        public_key: bytes | None = None
        raw_public_key = item.get("publicKey")
        if isinstance(raw_public_key, str) and raw_public_key:
            try:
                decoded_public_key = base64.b64decode(raw_public_key, validate=True)
            except (binascii.Error, ValueError):
                decoded_public_key = None
                warnings.append(
                    f"{source}: node {num_int:08x}'s publicKey is not valid base64; "
                    "treating it as absent."
                )
            if decoded_public_key is not None and len(decoded_public_key) == X25519_KEY_SIZE:
                public_key = decoded_public_key
            elif decoded_public_key is not None:
                # Valid base64, wrong length -- a truncated or corrupt
                # field. Treating this as present-but-wrong-length would
                # otherwise raise a misleading "these backups appear to
                # be for different nodes" conflict against a paired
                # profile's genuinely correct key, and would silently be
                # dropped downstream anyway (LiveSecurity.has_public_key
                # rejects anything not exactly 32 bytes). Surface it
                # instead of guessing.
                warnings.append(
                    f"{source}: node {num_int:08x}'s publicKey decoded to "
                    f"{len(decoded_public_key)} byte(s), not the expected "
                    f"{X25519_KEY_SIZE}; treating it as absent."
                )

        node = f"{source}: node {num_int:08x}'s"
        metadata = item.get("metadata")
        firmware_version = (
            _entry_str(metadata, "firmwareVersion", node=node, warnings=warnings)
            if isinstance(metadata, dict)
            else None
        )

        entries.append(
            NodeDbEntry(
                num=num_int,
                node_id=NodeId.try_parse(num_int),
                long_name=_entry_str(item, "longName", node=node, warnings=warnings),
                short_name=_entry_str(item, "shortName", node=node, warnings=warnings),
                hw_model=_entry_str(item, "hwModel", node=node, warnings=warnings),
                role=_entry_str(item, "role", node=node, warnings=warnings),
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
