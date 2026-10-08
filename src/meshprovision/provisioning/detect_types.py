"""Detection value types: section names, node states, and the live-config snapshot.

Split out of :mod:`meshprovision.provisioning.detect` for size, with no
change in behavior; that module re-exports every public name here
unchanged. Pure data: this module imports only the standard library plus
:mod:`meshprovision.crypto.redact`, :mod:`meshprovision.enums`,
:mod:`meshprovision.errors` and :mod:`meshprovision.nodeid`, and never
touches a device.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from meshprovision.crypto.redact import SecretBytes, redact
from meshprovision.enums import MODULE_SECTIONS
from meshprovision.errors import PlanConflictError
from meshprovision.nodeid import NodeId

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = [
    "CHANNEL_SECTIONS",
    "CONFIG_SECTIONS",
    "SECRET_FIELDS",
    "Detection",
    "LiveConfig",
    "LiveSecurity",
    "NodeState",
    "SectionKind",
]


class SectionKind(StrEnum):
    """Which of a live device's three write surfaces a section belongs to.

    The single source of truth for this classification, shared by
    :meth:`LiveConfig.kind_of` and
    :attr:`meshprovision.provisioning.plan.SectionChange.kind` -- both
    used to describe exactly the same outcome and previously declared as
    independent, un-linked ``Literal`` types.
    """

    CONFIG = "config"
    MODULE_CONFIG = "module_config"
    CHANNEL = "channel"


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

CHANNEL_SECTIONS: Final[tuple[str, ...]] = ("default_channel",)
"""Section names backed by ``iface.localNode.channels`` rather than
``LocalConfig``/``LocalModuleConfig``, written through ``Node.writeChannel``
rather than ``Node.writeConfig``."""

SECRET_FIELDS: Final[frozenset[tuple[str, str]]] = frozenset(
    {
        ("bluetooth", "fixed_pin"),
        ("security", "private_key"),
        ("security", "public_key"),
        ("security", "admin_key"),
        ("network", "wifi_psk"),
        ("mqtt", "password"),
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
        packet_signature_policy: Firmware 2.8's XEdDSA packet-signing
            policy, as its canonical enum value name, or ``None`` if not
            read.
    """

    public_key: bytes | None = None
    private_key: SecretBytes | None = None
    admin_keys: tuple[bytes, ...] = ()
    is_managed: bool = False
    admin_channel_enabled: bool = False
    serial_enabled: bool | None = None
    debug_log_api_enabled: bool | None = None
    packet_signature_policy: str | None = None

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

    @property
    def real_public_key(self) -> bytes | None:
        """:attr:`public_key` when :attr:`has_public_key`, else ``None``.

        Returns:
            The device's real public key, or ``None``.
        """
        return self.public_key if self.has_public_key else None

    @property
    def real_private_key(self) -> SecretBytes | None:
        """:attr:`private_key` when :attr:`has_private_key`, else ``None``.

        Returns:
            The device's real private key, still wrapped, or ``None``.
        """
        return self.private_key if self.has_private_key else None

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
        public = redact(self.public_key) if self.public_key is not None else "None"
        admin = "(" + ", ".join(redact(k) for k in self.admin_keys) + ")"
        return (
            f"LiveSecurity(public_key={public}, private_key={self.private_key!r}, "
            f"admin_keys={admin}, is_managed={self.is_managed!r}, "
            f"admin_channel_enabled={self.admin_channel_enabled!r}, "
            f"serial_enabled={self.serial_enabled!r}, "
            f"debug_log_api_enabled={self.debug_log_api_enabled!r}, "
            f"packet_signature_policy={self.packet_signature_policy!r})"
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
        is_unmessagable: The device's current ``User.is_unmessagable``
            ("infrastructure node" -- never a target for direct
            messages), or ``None`` when the device did not report it.
            Written through the same admin message as
            :attr:`short_name`/:attr:`long_name` (``Node.setOwner``).
        is_licensed: The device's current ``User.is_licensed`` (amateur
            radio operator status). Defaults to ``False`` when the
            device did not report it, matching the protobuf's own
            default. meshprovision has no control surface over this
            field -- it is read only so the owner-phase write can echo
            it back unchanged instead of resetting it (``Node.setOwner``
            defaults ``is_licensed`` to ``False`` whenever ``long_name``
            is set, which this project's owner-phase write always does).
        hw_model: Canonical ``HardwareModel`` enum name, or ``""`` when
            unknown.
        hw_model_raw: The device-reported hw_model value ``hw_model``
            was resolved from (``user["hwModel"]`` or
            ``metadata.hw_model``, whichever was used), before enum
            lookup -- ``None`` only when the device reported nothing at
            all. Distinguishes "not reported" from "reported but not a
            name :func:`~meshprovision.enums.hw_model_table` recognizes"
            -- both collapse to ``hw_model == ""``, but only the latter
            is a call for :func:`~meshprovision.provisioning.adopt.
            build_adoption_report` to warn about, mirroring how it
            already handles an unmappable live ``region``/``role``.
        role_raw: The device-reported ``role`` value, before enum lookup,
            for a source that cannot represent "unrecognized" any other
            way -- only ever set by
            :func:`~meshprovision.provisioning.backup.live_config_from_backup`
            for a node-db-export ``role`` string this build's
            :func:`~meshprovision.enums.role_table` does not recognize
            (a live device's *own* unmappable role instead falls out of
            ``sections``'s ``str(raw_number)`` fallback, since a real
            protobuf enum number can always be represented; a JSON
            string that matches no known member cannot). ``None`` in
            every other case, including a normal live-device read.
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
        default_channel: ``{"position_precision": int, "is_muted": bool}``
            read from the primary (index-0) channel's ``ModuleSettings``,
            when that channel exists and its role is not ``DISABLED``;
            ``{}`` when channel 0 is absent or ``DISABLED``, or was not
            read at all (a backup-derived config, see
            :func:`live_config_from_protobufs`). An enabled channel always
            yields every ``ModuleSettings`` scalar, so ``{}`` read from a
            device is an exact "no writable primary channel" signal --
            :mod:`meshprovision.provisioning.plan` relies on it to skip
            ``default_channel``. Deliberately not folded into
            :attr:`sections`/:attr:`module_sections` -- those are typed
            strictly around :data:`CONFIG_SECTIONS`/:data:`MODULE_SECTIONS`,
            and this is backed by a structurally different container
            (``iface.localNode.channels``, not
            ``LocalConfig``/``LocalModuleConfig``).

    :attr:`sections` and :attr:`module_sections` hold some plaintext
    secrets (``network.wifi_psk``, ``mqtt.password``,
    ``bluetooth.fixed_pin`` -- see :data:`SECRET_FIELDS`) alongside
    ordinary diagnostics, so this class' ``repr`` is overridden to render
    every :data:`SECRET_FIELDS` entry as ``"<redacted>"``. The field
    values themselves are untouched -- use :meth:`value` or
    :attr:`sections`/:attr:`module_sections` directly to read them.
    """

    node_id: NodeId
    short_name: str = ""
    long_name: str = ""
    is_unmessagable: bool | None = None
    is_licensed: bool = False
    hw_model: str = ""
    hw_model_raw: str | None = None
    role_raw: str | None = None
    firmware_version: str = ""
    security: LiveSecurity = field(default_factory=LiveSecurity)
    sections: Mapping[str, Mapping[str, object]] = field(
        default_factory=lambda: MappingProxyType({})
    )
    module_sections: Mapping[str, Mapping[str, object]] = field(
        default_factory=lambda: MappingProxyType({})
    )
    module_enabled: Mapping[str, bool | None] = field(default_factory=lambda: MappingProxyType({}))
    default_channel: Mapping[str, object] = field(default_factory=lambda: MappingProxyType({}))

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
            for a name in :data:`MODULE_SECTIONS`;
            :attr:`SectionKind.CHANNEL` for a name in
            :data:`CHANNEL_SECTIONS`.

        Raises:
            PlanConflictError: If ``section`` is none of the above.
        """
        if section in CONFIG_SECTIONS:
            return SectionKind.CONFIG
        if section in MODULE_SECTIONS:
            return SectionKind.MODULE_CONFIG
        if section in CHANNEL_SECTIONS:
            return SectionKind.CHANNEL
        raise PlanConflictError(f"Unknown config section: {section!r}", field=section)

    def __repr__(self) -> str:
        """Return a repr that never exposes :data:`SECRET_FIELDS` values.

        ``@dataclass`` leaves a class-supplied ``__repr__`` untouched, so
        this override replaces the auto-generated one, which would
        otherwise print ``sections``/``module_sections`` entries like
        ``network.wifi_psk``, ``mqtt.password``, and
        ``bluetooth.fixed_pin`` in plaintext. :attr:`security` is already
        safe -- it delegates to :meth:`LiveSecurity.__repr__`.

        Returns:
            A redacted representation with every :data:`SECRET_FIELDS`
            entry in :attr:`sections`/:attr:`module_sections` replaced by
            the literal ``"<redacted>"``.
        """
        return (
            f"LiveConfig(node_id={self.node_id!r}, short_name={self.short_name!r}, "
            f"long_name={self.long_name!r}, hw_model={self.hw_model!r}, "
            f"hw_model_raw={self.hw_model_raw!r}, role_raw={self.role_raw!r}, "
            f"firmware_version={self.firmware_version!r}, security={self.security!r}, "
            f"sections={_redacted_sections(self.sections)!r}, "
            f"module_sections={_redacted_sections(self.module_sections)!r}, "
            f"module_enabled={dict(self.module_enabled)!r}, "
            f"default_channel={dict(self.default_channel)!r})"
        )


def _redacted_sections(
    mapping: Mapping[str, Mapping[str, object]],
) -> dict[str, dict[str, object]]:
    """Copy a ``{section: {field: value}}`` mapping, redacting secret fields.

    Args:
        mapping: A :attr:`LiveConfig.sections`- or
            :attr:`LiveConfig.module_sections`-shaped mapping.

    Returns:
        A plain ``dict`` copy with every value whose ``(section, field)``
        pair is in :data:`SECRET_FIELDS` replaced by the literal
        ``"<redacted>"``.
    """
    return {
        section: {
            field_name: "<redacted>" if (section, field_name) in SECRET_FIELDS else value
            for field_name, value in fields.items()
        }
        for section, fields in mapping.items()
    }


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
