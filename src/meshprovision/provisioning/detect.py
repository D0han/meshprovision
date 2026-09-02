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
exactly :data:`CONFIG_SECTIONS`, ``LocalModuleConfig``'s fields are a
superset of :data:`MODULE_SECTIONS` restricted to the names
``Node.writeConfig`` accepts, ``Config.SecurityConfig.admin_key`` is
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

import re
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final

from meshprovision import enums
from meshprovision.crypto.redact import SecretBytes, fingerprint
from meshprovision.errors import DetectionError, PlanConflictError
from meshprovision.nodeid import NodeId

if TYPE_CHECKING:
    from collections.abc import Mapping

    from meshtastic.mesh_interface import MeshInterface

    from meshprovision.db.nodes import NodeRecord

__all__ = [
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
]

FACTORY_LONG_NAME_PREFIX: Final[str] = "Meshtastic "
"""Prefix of the firmware's factory-default ``long_name``."""

_FACTORY_SHORT_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-fA-F]{4}$")
"""Matches any 4-hex-digit short name -- the loose form of a factory default."""


class SectionKind(StrEnum):
    """Which of a live device's two ``write*Config`` surfaces a section belongs to.

    The single source of truth for this classification, shared by
    :meth:`LiveConfig.kind_of` and
    :attr:`meshprovision.provisioning.plan.SectionChange.kind` -- both
    used to describe exactly the same two-value outcome and previously
    declared as independent, un-linked ``Literal`` types.
    """

    CONFIG = "config"
    MODULE_CONFIG = "module_config"


CONFIG_SECTIONS: Final[tuple[str, ...]] = (
    "device",
    "position",
    "power",
    "network",
    "display",
    "lora",
    "bluetooth",
    "security",
)
"""Exactly the ``LocalConfig`` field names ``Node.writeConfig`` accepts."""

MODULE_SECTIONS: Final[tuple[str, ...]] = (
    "mqtt",
    "serial",
    "external_notification",
    "store_forward",
    "range_test",
    "telemetry",
    "canned_message",
    "audio",
    "remote_hardware",
    "neighbor_info",
    "ambient_lighting",
    "detection_sensor",
    "paxcounter",
    "traffic_management",
)
"""Exactly the ``LocalModuleConfig`` field names ``Node.writeConfig`` accepts."""

SECRET_FIELDS: Final[frozenset[tuple[str, str]]] = frozenset(
    {
        ("bluetooth", "fixed_pin"),
        ("security", "private_key"),
        ("security", "public_key"),
        ("security", "admin_key"),
    }
)
"""``(section, field)`` pairs that must never be rendered unredacted."""

_REASON_TEXT: Final[Mapping[str, str]] = MappingProxyType(
    {
        "in_database": "in database",
        "factory_defaults_restored": "factory defaults restored",
        "no_admin_keys": "no admin keys",
        "not_in_database": "not in database",
        "factory_default_names": "factory default names",
        "custom_names": "custom names",
        "admin_keys_present": "admin keys present",
        "is_managed": "locked (is_managed) by an admin key not on hand",
    }
)
"""Human-readable phrase for each :attr:`Detection.reasons` code.

Used by :meth:`Detection.summary`.
"""


class NodeState(StrEnum):
    """A connected node's provisioning state, as decided by :func:`classify`."""

    FACTORY = "factory"
    PROVISIONED = "provisioned"
    FOREIGN = "foreign"


@dataclass(frozen=True, slots=True)
class LiveSecurity:
    """The live ``config.security`` section, normalized out of protobuf form.

    Key material fields are wrapped or kept as ``bytes`` rather than
    exposed as base64 text, so nothing here is ever accidentally
    interpolated into a string. Route any human-facing mention through
    :func:`meshprovision.crypto.redact.fingerprint`.

    Attributes:
        public_key: The device's current X25519 public key, or ``None``
            when the device reports an empty key.
        private_key: The device's current X25519 private key, wrapped in
            :class:`~meshprovision.crypto.redact.SecretBytes`, or ``None``
            when the device reports an empty key.
        admin_keys: The public keys currently authorized in
            ``security.admin_key``, in the device's own order.
        is_managed: Whether the device is locked into admin-managed mode.
        admin_channel_enabled: Whether the legacy admin channel is active.
        serial_enabled: Whether the serial console/API is enabled, or
            ``None`` if not read.
        debug_log_api_enabled: Whether verbose debug logging is exposed
            over the API, or ``None`` if not read.
    """

    public_key: bytes | None = None
    private_key: SecretBytes | None = None
    admin_keys: tuple[bytes, ...] = ()
    is_managed: bool = False
    admin_channel_enabled: bool = False
    serial_enabled: bool | None = None
    debug_log_api_enabled: bool | None = None

    @property
    def has_private_key(self) -> bool:
        """Whether a real (non-empty, non-all-zero) private key is present.

        Returns:
            ``True`` when :attr:`private_key` is set, is exactly 32
            bytes, and contains at least one nonzero byte.
        """
        if self.private_key is None or len(self.private_key) != 32:
            return False
        return any(b != 0 for b in self.private_key.reveal())

    @property
    def has_public_key(self) -> bool:
        """Whether a real (non-empty, non-all-zero) public key is present.

        Returns:
            ``True`` when :attr:`public_key` is set, is exactly 32
            bytes, and contains at least one nonzero byte.
        """
        if self.public_key is None or len(self.public_key) != 32:
            return False
        return any(b != 0 for b in self.public_key)

    def admin_fingerprints(self) -> tuple[str, ...]:
        """Redacted fingerprint labels for every authorized admin key.

        Returns:
            One :func:`~meshprovision.crypto.redact.fingerprint` string
            per entry of :attr:`admin_keys`, in the same order.
        """
        return tuple(fingerprint(key) for key in self.admin_keys)

    def __repr__(self) -> str:
        """Return a repr that never exposes raw key bytes.

        ``@dataclass`` leaves a class-supplied ``__repr__`` untouched, so
        this override replaces the auto-generated one, which would
        otherwise print :attr:`public_key` and :attr:`admin_keys` as raw
        ``bytes`` literals. :attr:`private_key` is already safe: it is a
        :class:`~meshprovision.crypto.redact.SecretBytes`, whose own
        ``__repr__`` is redacted.

        Returns:
            A redacted representation with :attr:`public_key` and each
            entry of :attr:`admin_keys` replaced by a fingerprint label.
        """
        public = (
            f"<redacted:{fingerprint(self.public_key)}>" if self.public_key is not None else "None"
        )
        admin = "(" + ", ".join(f"<redacted:{fingerprint(k)}>" for k in self.admin_keys) + ")"
        return (
            f"LiveSecurity(public_key={public}, private_key={self.private_key!r}, "
            f"admin_keys={admin}, is_managed={self.is_managed!r}, "
            f"admin_channel_enabled={self.admin_channel_enabled!r}, "
            f"serial_enabled={self.serial_enabled!r}, "
            f"debug_log_api_enabled={self.debug_log_api_enabled!r})"
        )


@dataclass(frozen=True, slots=True)
class LiveConfig:
    """The full live device state, normalized out of protobuf form.

    Every value reachable from this object is a plain Python scalar
    (``str``, ``bool``, ``int``, ``float``) or one of this module's own
    types -- never a protobuf message or enum wrapper. Enum-valued fields
    are stored as their canonical name string (for example
    ``"LONG_FAST"``), the same form :mod:`meshprovision.config.template`
    validates against, so :mod:`meshprovision.provisioning.plan` can diff
    template and live values with plain ``==``.

    Attributes:
        node_id: This device's node id.
        short_name: The device's current ``short_name``.
        long_name: The device's current ``long_name``.
        hw_model: Canonical ``HardwareModel`` enum name, or ``""`` when
            unknown.
        firmware_version: Firmware version string as reported by the
            device.
        security: The live ``config.security`` section.
        sections: ``{section_name: {field_name: value}}`` for every
            non-``security`` name in :data:`CONFIG_SECTIONS` the device
            reported. Keys are a subset of :data:`CONFIG_SECTIONS`
            (``"security"`` is deliberately absent -- its content lives
            in :attr:`security` instead).
        module_sections: ``{section_name: {field_name: value}}`` for
            every name in :data:`MODULE_SECTIONS`.
        module_enabled: ``{section_name: enabled_or_none}`` for every
            name in :data:`MODULE_SECTIONS`. ``None`` marks a module
            message with no ``enabled`` field at all (for example
            ``telemetry``), distinct from an ``enabled`` field that is
            simply ``False``.
    """

    node_id: NodeId
    short_name: str = ""
    long_name: str = ""
    hw_model: str = ""
    firmware_version: str = ""
    security: LiveSecurity = field(default_factory=LiveSecurity)
    sections: Mapping[str, Mapping[str, object]] = field(
        default_factory=lambda: MappingProxyType({})
    )
    module_sections: Mapping[str, Mapping[str, object]] = field(
        default_factory=lambda: MappingProxyType({})
    )
    module_enabled: Mapping[str, bool | None] = field(default_factory=lambda: MappingProxyType({}))

    def section(self, name: str) -> Mapping[str, object]:
        r"""Look up one section's fields, trying config then module config.

        Args:
            name: A section name, typically from :data:`CONFIG_SECTIONS`
                or :data:`MODULE_SECTIONS`.

        Returns:
            :attr:`sections`\\ ``[name]`` when present; otherwise
            :attr:`module_sections`\\ ``[name]`` when present; otherwise
            an empty mapping.
        """
        if name in self.sections:
            return self.sections[name]
        if name in self.module_sections:
            return self.module_sections[name]
        return MappingProxyType({})

    def value(self, section: str, field: str) -> object | None:
        """Look up one field's current live value.

        Args:
            section: The section name to look in.
            field: The field name within that section.

        Returns:
            The field's value, or ``None`` if the section or field is
            not present.
        """
        return self.section(section).get(field)

    def kind_of(self, section: str) -> SectionKind:
        """Classify a section name as belonging to config or module config.

        Args:
            section: The section name to classify.

        Returns:
            :attr:`SectionKind.CONFIG` for a name in
            :data:`CONFIG_SECTIONS`; :attr:`SectionKind.MODULE_CONFIG`
            for a name in :data:`MODULE_SECTIONS`.

        Raises:
            PlanConflictError: If ``section`` is neither.
        """
        if section in CONFIG_SECTIONS:
            return SectionKind.CONFIG
        if section in MODULE_SECTIONS:
            return SectionKind.MODULE_CONFIG
        raise PlanConflictError(f"Unknown config section: {section!r}", field=section)


@dataclass(frozen=True, slots=True)
class Detection:
    """The result of classifying one connected node.

    Attributes:
        state: The decided :class:`NodeState`.
        node_id: The classified node's id.
        in_database: Whether this node id was found in the ODS.
        factory_short_name: Whether the live ``short_name`` matches the
            firmware factory default.
        factory_long_name: Whether the live ``long_name`` matches the
            firmware factory default.
        admin_keys_present: Whether the device reports any
            ``security.admin_key`` entries.
        reasons: Machine-readable codes explaining the decision, in a
            fixed order. See :func:`classify` for the exact codes used
            per state.
    """

    state: NodeState
    node_id: NodeId
    in_database: bool
    factory_short_name: bool
    factory_long_name: bool
    admin_keys_present: bool
    reasons: tuple[str, ...] = ()

    @property
    def is_factory(self) -> bool:
        """Whether this node was classified as :attr:`NodeState.FACTORY`.

        Returns:
            ``True`` if :attr:`state` is :attr:`NodeState.FACTORY`.
        """
        return self.state is NodeState.FACTORY

    def summary(self) -> str:
        """Render a one-line, operator-facing summary of this detection.

        Returns:
            For example
            ``"!a0cb5cc4 FACTORY (not in database; factory default names; no admin keys)"``.
        """
        header = f"{self.node_id.display} {self.state.value.upper()}"
        if not self.reasons:
            return header
        phrases = "; ".join(_REASON_TEXT.get(code, code) for code in self.reasons)
        return f"{header} ({phrases})"


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
        raw = getattr(msg, descriptor.name)
        if descriptor.type == FieldDescriptor.TYPE_ENUM:
            enum_value = descriptor.enum_type.values_by_number.get(raw)
            result[descriptor.name] = enum_value.name if enum_value is not None else str(raw)
        else:
            result[descriptor.name] = raw
    return result


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
    hw_model: str = "",
    firmware_version: str = "",
) -> LiveConfig:
    """Build a :class:`LiveConfig` from already-read protobuf config messages.

    Args:
        local_config: A ``meshtastic.protobuf.localonly_pb2.LocalConfig``.
        module_config: A
            ``meshtastic.protobuf.localonly_pb2.LocalModuleConfig``.
        node_id: The device's node id.
        short_name: The device's current ``short_name``.
        long_name: The device's current ``long_name``.
        hw_model: Canonical ``HardwareModel`` enum name, or ``""``.
        firmware_version: Firmware version string.

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
    )

    return LiveConfig(
        node_id=node_id,
        short_name=short_name,
        long_name=long_name,
        hw_model=hw_model,
        firmware_version=firmware_version,
        security=security,
        sections=MappingProxyType(sections),
        module_sections=MappingProxyType(module_sections),
        module_enabled=MappingProxyType(module_enabled),
    )


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
            attribute, a malformed value). Unexpected exception types are
            not caught and propagate as-is.
    """
    try:
        if iface.myInfo is not None:
            node_id = NodeId.from_int(iface.myInfo.my_node_num)
        else:
            info = iface.getMyNodeInfo()
            if not info:
                raise DetectionError(
                    "Device did not report its node id",
                    hint="Reconnect; the config handshake may not have completed.",
                )
            node_id = NodeId.parse(info["num"])

        user = iface.getMyUser() or {}
        short_name = str(user.get("shortName", ""))
        long_name = str(user.get("longName", ""))

        hw_model_raw = user.get("hwModel")
        if hw_model_raw:
            hw_model = enums.hw_model_table().try_name(str(hw_model_raw)) or ""
        else:
            metadata_hw_model = getattr(iface.metadata, "hw_model", None)
            hw_model = (
                enums.hw_model_table().try_name(metadata_hw_model)
                if metadata_hw_model is not None
                else None
            ) or ""

        firmware_version = getattr(iface.metadata, "firmware_version", "") or ""

        return live_config_from_protobufs(
            iface.localNode.localConfig,
            iface.localNode.moduleConfig,
            node_id=node_id,
            short_name=short_name,
            long_name=long_name,
            hw_model=hw_model,
            firmware_version=firmware_version,
        )
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
