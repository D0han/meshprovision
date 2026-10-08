"""Read-only device inspection: live config capture and node classification.

This is the **only** file in the project that knows protobuf field and
enum mechanics for *reading* a connected device. :func:`read_live_config`
pulls everything meshprovision cares about off a live ``MeshInterface``
and normalizes it into a plain, immutable :class:`LiveConfig` -- no
protobuf object escapes this module. :mod:`meshprovision.provisioning.plan`
and :mod:`meshprovision.provisioning.apply` both consume :class:`LiveConfig`
instead of ever touching a protobuf directly (writing is confined to
``apply.py``).

:func:`classify` turns a :class:`LiveConfig` plus an optional database
entry into a :class:`Detection`: is this node one we already provisioned
(:attr:`NodeState.PROVISIONED`), a brand-new device still at firmware
defaults (:attr:`NodeState.FACTORY`), or somebody else's node
(:attr:`NodeState.FOREIGN`)? A node listed in our ODS is ours even if it
was factory-reset -- that is drift to repair, not a re-classification; a
node we have never seen that already carries someone's admin keys is
FOREIGN even if its names are still default. The full decision table is
documented on :func:`classify`.

Verified against the installed ``meshtastic==2.7.11`` protobufs
(``meshtastic.protobuf.localonly_pb2``, ``config_pb2``,
``module_config_pb2``) directly in ``.venv``: ``LocalConfig``'s fields are
:data:`CONFIG_SECTIONS` plus ``version``, ``LocalModuleConfig``'s fields are a
superset of :data:`MODULE_SECTIONS` restricted to the names
``Node.writeConfig`` accepts (``tests/unit/test_writable_sections_contract.py``
checks both lists against the pinned library's own ``Node.writeConfig``),
``Config.SecurityConfig.admin_key`` is
``repeated bytes`` field 3 (snake_case on the generated Python class --
``adminKey`` is only the JSON/CLI spelling and does not exist as a Python
attribute), and ``ModuleConfig.TelemetryConfig`` has no ``enabled`` field.

The Meshtastic factory-default naming convention encoded in
:func:`is_factory_short_name`/:func:`is_factory_long_name` (short name =
last 4 hex digits of the node id; long name = ``"Meshtastic "`` + those 4
digits, from firmware ``NodeDB::installDefaultDeviceState``) was not
re-verified against firmware source during this build. Both the strict
form (exact match against the node id) and a looser regex form (any
4-hex-digit short name, any ``"Meshtastic "``-prefixed long name whose
remainder is 4 hex digits) are implemented and OR'd together, so the
check stays robust even if the exact convention differs on some hardware.
"""

from __future__ import annotations

import logging
import re
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final

from meshprovision import enums
from meshprovision.crypto.redact import SecretBytes
from meshprovision.enums import MODULE_SECTIONS
from meshprovision.errors import DetectionError, NodeIdError
from meshprovision.nodeid import NodeId
from meshprovision.provisioning.detect_types import (
    CHANNEL_SECTIONS,
    CONFIG_SECTIONS,
    SECRET_FIELDS,
    Detection,
    LiveConfig,
    LiveSecurity,
    NodeState,
    SectionKind,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from meshtastic.mesh_interface import MeshInterface

    from meshprovision.db.nodes import NodeRecord

__all__ = [
    "CHANNEL_SECTIONS",
    "CONFIG_SECTIONS",
    "FACTORY_LONG_NAME_PREFIX",
    "MODULE_SECTIONS",
    "SECRET_FIELDS",
    "Detection",
    "LiveConfig",
    "LiveSecurity",
    "NodeState",
    "SectionKind",
    "classify",
    "is_factory_long_name",
    "is_factory_short_name",
    "live_config_from_protobufs",
    "read_live_config",
    "read_node_id",
]

_logger = logging.getLogger(__name__)

FACTORY_LONG_NAME_PREFIX: Final[str] = "Meshtastic "
"""Prefix of the firmware's factory-default ``long_name``."""

_FACTORY_SHORT_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{4}$")
"""Matches any 4-hex-digit short name -- the loose form of a factory default."""


def is_factory_short_name(short_name: str, node_id: NodeId) -> bool:
    """Decide whether a ``short_name`` looks like the firmware factory default.

    An empty ``short_name`` counts as factory (a never-named device). The
    strict form checks a case-insensitive match against the node id's
    last 4 hex digits; the loose form accepts any 4-hex-digit string.

    Args:
        short_name: The live ``short_name`` to check.
        node_id: The device's node id.

    Returns:
        ``True`` if ``short_name`` matches either form.
    """
    if not short_name:
        return True
    expected = node_id.hex[-4:]
    if short_name.casefold() == expected.casefold():
        return True
    return bool(_FACTORY_SHORT_RE.fullmatch(short_name))


def is_factory_long_name(long_name: str, node_id: NodeId) -> bool:
    """Decide whether a ``long_name`` looks like the firmware factory default.

    An empty ``long_name`` counts as factory (a never-named device). The
    strict form checks a case-insensitive match against
    ``"Meshtastic " + <last 4 hex digits>``; the loose form accepts any
    ``"Meshtastic "``-prefixed string whose remainder is 4 hex digits.

    Args:
        long_name: The live ``long_name`` to check.
        node_id: The device's node id.

    Returns:
        ``True`` if ``long_name`` matches either form.
    """
    if not long_name:
        return True
    expected = FACTORY_LONG_NAME_PREFIX + node_id.hex[-4:]
    if long_name.casefold() == expected.casefold():
        return True
    if long_name.startswith(FACTORY_LONG_NAME_PREFIX):
        remainder = long_name[len(FACTORY_LONG_NAME_PREFIX) :]
        return bool(_FACTORY_SHORT_RE.fullmatch(remainder))
    return False


def _enum_field_name(msg: Any, field: str) -> str:
    """Resolve one protobuf enum-typed field to its canonical value name.

    Args:
        msg: A protobuf message carrying ``field``.
        field: The enum-typed field's name on ``msg``.

    Returns:
        The enum value's name, or ``str(raw)`` if the raw number is not a
        recognized member (matching :func:`_message_fields`'s own
        fallback behavior for an unrecognized enum number).
    """
    raw = getattr(msg, field)
    enum_value = msg.DESCRIPTOR.fields_by_name[field].enum_type.values_by_number.get(raw)
    return enum_value.name if enum_value is not None else str(raw)


def _message_fields(msg: Any) -> dict[str, object]:
    """Coerce one protobuf config/module-config message into a plain dict.

    Every scalar field is emitted -- protobuf scalars always carry a
    default, so a returned mapping never has a missing key for a field
    that exists on the message. Repeated fields, ``bytes`` fields, and
    nested-message fields are skipped entirely: only ``security``,
    handled separately, carries ``bytes`` that matter here; and none of
    :mod:`meshprovision.config.template`'s diffed fields live inside a
    nested submessage (the only two such fields in the sections this
    module reads are ``network.ipv4_config`` and
    ``mqtt.map_report_settings``, neither of which
    :mod:`meshprovision.provisioning.plan` ever diffs). Skipping them
    here is what keeps every value reachable from a :class:`LiveConfig` a
    plain Python scalar -- never a protobuf message object.

    Args:
        msg: A protobuf config or module-config section message (for
            example ``local_config.device``).

    Returns:
        ``{field_name: value}`` for every scalar field. An enum-typed
        field is stored as its canonical value-name string (falling back
        to ``str(number)`` for an unrecognized number); every other
        scalar is stored as its plain Python value.
    """
    from google.protobuf.descriptor import FieldDescriptor

    result: dict[str, object] = {}
    for descriptor in msg.DESCRIPTOR.fields:
        if descriptor.is_repeated or descriptor.type in (
            FieldDescriptor.TYPE_BYTES,
            FieldDescriptor.TYPE_MESSAGE,
            FieldDescriptor.TYPE_GROUP,
        ):
            continue
        if descriptor.type == FieldDescriptor.TYPE_ENUM:
            result[descriptor.name] = _enum_field_name(msg, descriptor.name)
        else:
            result[descriptor.name] = getattr(msg, descriptor.name)
    return result


def _read_default_channel(iface: MeshInterface) -> Mapping[str, object]:
    """Read the primary (index-0) channel's ``ModuleSettings``, if any.

    Returns:
        ``{}`` when channel 0 is absent or reports ``role == DISABLED``
        -- never meaningless zero-value defaults surfaced as real device
        state; the planner reads ``{}`` as "no writable primary channel"
        and skips ``default_channel`` with a warning. Otherwise, the
        channel's ``ModuleSettings`` fields via :func:`_message_fields`
        (both ``position_precision``/``is_muted`` are plain scalars, so
        no special-casing is needed) -- every scalar, so never ``{}``.
    """
    from meshtastic.protobuf import channel_pb2

    channel = iface.localNode.getChannelByChannelIndex(0)
    if channel is None or channel.role == channel_pb2.Channel.Role.DISABLED:
        return MappingProxyType({})
    return MappingProxyType(_message_fields(channel.settings.module_settings))


def _has_enabled_field(msg: Any) -> bool:
    """Check whether a module-config message declares an ``enabled`` field.

    Args:
        msg: A protobuf module-config section message.

    Returns:
        ``True`` if the message's descriptor has a field named
        ``"enabled"``.
    """
    return any(descriptor.name == "enabled" for descriptor in msg.DESCRIPTOR.fields)


def live_config_from_protobufs(
    local_config: Any,
    module_config: Any,
    *,
    node_id: NodeId,
    short_name: str = "",
    long_name: str = "",
    is_unmessagable: bool | None = None,
    is_licensed: bool = False,
    hw_model: str = "",
    hw_model_raw: str | None = None,
    role_raw: str | None = None,
    firmware_version: str = "",
    default_channel: Mapping[str, object] = MappingProxyType({}),
) -> LiveConfig:
    """Build a :class:`LiveConfig` from already-read protobuf config messages.

    Args:
        local_config: A ``meshtastic.protobuf.localonly_pb2.LocalConfig``.
        module_config: A
            ``meshtastic.protobuf.localonly_pb2.LocalModuleConfig``.
        node_id: The device's node id.
        short_name: The device's current ``short_name``.
        long_name: The device's current ``long_name``.
        is_unmessagable: See :attr:`LiveConfig.is_unmessagable`.
        is_licensed: See :attr:`LiveConfig.is_licensed`.
        hw_model: Canonical ``HardwareModel`` enum name, or ``""``.
        hw_model_raw: The raw value ``hw_model`` was resolved from, or
            ``None`` if the device reported nothing. See
            :attr:`LiveConfig.hw_model_raw`.
        role_raw: See :attr:`LiveConfig.role_raw`. ``None`` for a normal
            live-device read.
        firmware_version: Firmware version string.
        default_channel: See :attr:`LiveConfig.default_channel`. The
            actual channel read happens in the caller (mirrors how
            ``hw_model``/``firmware_version`` are resolved by the caller
            and threaded in) -- this function stays a pure "protobufs in,
            :class:`LiveConfig` out" transform.

    Returns:
        The normalized, immutable :class:`LiveConfig`. Every mapping
        attribute is wrapped in :class:`types.MappingProxyType`.
    """
    sections: dict[str, Mapping[str, object]] = {}
    for name in CONFIG_SECTIONS:
        if name == "security":
            continue
        sections[name] = MappingProxyType(_message_fields(getattr(local_config, name)))

    module_sections: dict[str, Mapping[str, object]] = {}
    module_enabled: dict[str, bool | None] = {}
    for name in MODULE_SECTIONS:
        msg = getattr(module_config, name)
        module_sections[name] = MappingProxyType(_message_fields(msg))
        module_enabled[name] = bool(msg.enabled) if _has_enabled_field(msg) else None

    sec = local_config.security
    public_key_bytes = bytes(sec.public_key)
    private_key_bytes = bytes(sec.private_key)
    security = LiveSecurity(
        public_key=public_key_bytes or None,
        private_key=SecretBytes(private_key_bytes) if private_key_bytes else None,
        admin_keys=tuple(bytes(k) for k in sec.admin_key),
        is_managed=bool(sec.is_managed),
        admin_channel_enabled=bool(sec.admin_channel_enabled),
        serial_enabled=bool(sec.serial_enabled),
        debug_log_api_enabled=bool(sec.debug_log_api_enabled),
        packet_signature_policy=_enum_field_name(sec, "packet_signature_policy"),
    )

    return LiveConfig(
        node_id=node_id,
        short_name=short_name,
        long_name=long_name,
        is_unmessagable=is_unmessagable,
        is_licensed=is_licensed,
        hw_model=hw_model,
        hw_model_raw=hw_model_raw,
        role_raw=role_raw,
        firmware_version=firmware_version,
        security=security,
        sections=MappingProxyType(sections),
        module_sections=MappingProxyType(module_sections),
        module_enabled=MappingProxyType(module_enabled),
        default_channel=MappingProxyType(dict(default_channel)),
    )


def read_node_id(iface: MeshInterface) -> NodeId:
    """Read a connected device's node id, without any other config.

    The identity-only prologue of :func:`read_live_config`, split out so
    a caller that only needs to confirm *which* device answered a
    reconnect (see :func:`~meshprovision.provisioning.apply.apply_plan`'s
    reconnect identity check) does not need a full live-config read to do
    it. :func:`read_live_config` calls this function itself, so this
    module stays the only reader of ``myInfo``/``getMyNodeInfo()``.

    Args:
        iface: A connected, already-handshaked ``MeshInterface``.

    Returns:
        The device's node id.

    Raises:
        DetectionError: If the device did not report its node id, or if
            probing the interface fails in an expected way (a missing
            attribute, a malformed value, a node number that is not a
            valid node id). Unexpected exception types are
            not caught and propagate as-is.
    """
    try:
        if iface.myInfo is not None:
            return NodeId.from_int(iface.myInfo.my_node_num)
        info = iface.getMyNodeInfo()
        if not info:
            raise DetectionError(
                "Device did not report its node id",
                hint="Reconnect; the config handshake may not have completed.",
            )
        return NodeId.parse(info["num"])
    except DetectionError:
        raise
    except (AttributeError, TypeError, ValueError, KeyError, NodeIdError) as exc:
        raise DetectionError(
            f"Failed to read the device's node id: {exc}",
            hint="Reconnect; the config handshake may not have completed.",
        ) from exc


def read_live_config(iface: MeshInterface) -> LiveConfig:
    """Read the complete live configuration off a connected device.

    Read-only: this function issues no writes. It only reads attributes
    already populated on ``iface`` by the meshtastic library's own config
    handshake (``iface.myInfo``, ``iface.metadata``,
    ``iface.localNode.localConfig``/``moduleConfig``); it never blocks
    waiting for one.

    Args:
        iface: A connected, already-handshaked ``MeshInterface``.

    Returns:
        The normalized :class:`LiveConfig`.

    Raises:
        DetectionError: If the device did not report its node id, or if
            probing the interface fails in an expected way (a missing
            attribute, a malformed value, a node number that is not a
            valid node id). Unexpected exception types are
            not caught and propagate as-is.
    """
    node_id = read_node_id(iface)
    try:
        user = iface.getMyUser() or {}
        short_name = str(user.get("shortName", ""))
        long_name = str(user.get("longName", ""))
        is_unmessagable_source = user.get("isUnmessagable")
        is_unmessagable = (
            bool(is_unmessagable_source) if is_unmessagable_source is not None else None
        )
        is_licensed = bool(user.get("isLicensed", False))

        hw_model_source = user.get("hwModel")
        if hw_model_source:
            hw_model_raw: str | None = str(hw_model_source)
            hw_model = enums.hw_model_table().try_name(hw_model_source) or ""
        else:
            metadata_hw_model = getattr(iface.metadata, "hw_model", None)
            hw_model_raw = str(metadata_hw_model) if metadata_hw_model is not None else None
            hw_model = (
                enums.hw_model_table().try_name(metadata_hw_model)
                if metadata_hw_model is not None
                else None
            ) or ""

        firmware_version = getattr(iface.metadata, "firmware_version", "") or ""
        default_channel = _read_default_channel(iface)

        live = live_config_from_protobufs(
            iface.localNode.localConfig,
            iface.localNode.moduleConfig,
            node_id=node_id,
            short_name=short_name,
            long_name=long_name,
            is_unmessagable=is_unmessagable,
            is_licensed=is_licensed,
            hw_model=hw_model,
            hw_model_raw=hw_model_raw,
            firmware_version=firmware_version,
            default_channel=default_channel,
        )
        _logger.debug(
            "Read live config from %s: hw_model=%s (raw=%s) firmware=%s",
            node_id.display,
            hw_model or "?",
            hw_model_raw,
            firmware_version or "?",
        )
        return live
    except DetectionError:
        raise
    except (AttributeError, TypeError, ValueError, KeyError) as exc:
        raise DetectionError(
            f"Failed to read live configuration from device: {exc}",
            hint="Reconnect; the config handshake may not have completed.",
        ) from exc


def classify(live: LiveConfig, *, db_entry: NodeRecord | None) -> Detection:
    """Classify a connected node as FACTORY, PROVISIONED, or FOREIGN.

    Decision table, evaluated in this order:

    - **In the database** -> :attr:`NodeState.PROVISIONED`. A node we
      already provisioned is ours even if it was factory-reset in the
      field -- that is drift for ``mesh provision`` to repair, not a
      re-classification. Reasons: ``"in_database"``, plus
      ``"factory_defaults_restored"`` when the live names look factory,
      plus ``"no_admin_keys"`` when the device reports none.
    - **Not in the database, but locked** (``security.is_managed``) ->
      :attr:`NodeState.FOREIGN`, regardless of names or reported admin
      keys. A factory-fresh device can never report ``is_managed=True``
      -- this is always someone else's locked node, even if its admin
      keys happen to be unreadable or empty right now (a partial or
      failed key rotation, for example) and even if its names still look
      factory-default. Reasons: ``"not_in_database"``, ``"is_managed"``,
      plus ``"custom_names"``/``"admin_keys_present"`` as below.
    - **Not in the database, factory-default names, no admin keys, not
      locked** -> :attr:`NodeState.FACTORY`. Reasons:
      ``"not_in_database"``, ``"factory_default_names"``,
      ``"no_admin_keys"``.
    - **Everything else** -> :attr:`NodeState.FOREIGN`. A node we have
      never seen that already carries someone's admin keys is foreign
      even if its names are still default -- admin keys are the signal
      that someone else already owns it. Reasons: ``"not_in_database"``,
      plus ``"custom_names"`` when the names are not factory-default,
      plus ``"admin_keys_present"`` when the device reports any.

    Args:
        live: The device's normalized live configuration.
        db_entry: The matching ``Nodes`` sheet row, or ``None`` if this
            node id was not found in the database.

    Returns:
        The classification, with its :attr:`Detection.reasons` set per
        the table above.
    """
    in_database = db_entry is not None
    factory_short = is_factory_short_name(live.short_name, live.node_id)
    factory_long = is_factory_long_name(live.long_name, live.node_id)
    factory_names = factory_short and factory_long
    admin_present = len(live.security.admin_keys) > 0

    reasons: list[str]
    if in_database:
        state = NodeState.PROVISIONED
        reasons = ["in_database"]
        if factory_names:
            reasons.append("factory_defaults_restored")
        if not admin_present:
            reasons.append("no_admin_keys")
    elif live.security.is_managed:
        state = NodeState.FOREIGN
        reasons = ["not_in_database", "is_managed"]
        if not factory_names:
            reasons.append("custom_names")
        if admin_present:
            reasons.append("admin_keys_present")
    elif factory_names and not admin_present:
        state = NodeState.FACTORY
        reasons = ["not_in_database", "factory_default_names", "no_admin_keys"]
    else:
        state = NodeState.FOREIGN
        reasons = ["not_in_database"]
        if not factory_names:
            reasons.append("custom_names")
        if admin_present:
            reasons.append("admin_keys_present")

    return Detection(
        state=state,
        node_id=live.node_id,
        in_database=in_database,
        factory_short_name=factory_short,
        factory_long_name=factory_long,
        admin_keys_present=admin_present,
        reasons=tuple(reasons),
    )
