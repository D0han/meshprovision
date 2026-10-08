"""Adoption logic: an already-deployed device's live state -> a record of it.

The bulk of the ``mesh adopt`` command (see :mod:`meshprovision.cli.adopt`),
which connects to a device that is already configured and already in
service and records its *actual* live state into the database -- the
opposite of ``mesh provision``: no desired-state diff against a template
(unlike :mod:`meshprovision.provisioning.plan`), and no device write
anywhere in this package. :func:`build_adoption_report` turns an
already-read :class:`~meshprovision.provisioning.detect.LiveConfig`, an
optional existing :class:`~meshprovision.db.nodes.NodeRecord`, a
``{key_ref: material}`` map, and an already-loaded
:class:`~meshprovision.config.template.TemplateConfig` into an
:class:`AdoptionReport` -- a full, read-only inventory of what the device
is currently carrying, ready to display. :func:`adopted_record` turns
that report into the :class:`~meshprovision.db.nodes.NodeRecord` to
persist, and :func:`persist_adoption` performs that persistence --
upserting the device's own keypair, its channel PSK, and its observed
admin keys, then the node row itself -- against already-open
:class:`~meshprovision.db.keys.KeyRepository`/
:class:`~meshprovision.db.nodes.NodeRepository` sessions.

Nothing here touches a :class:`~meshprovision.cli.common.CliContext`, a
click prompt, or a console; and nothing here reads the clock --
:func:`adopted_record` and :func:`persist_adoption` both take ``now`` as
an explicit argument, exactly like
:meth:`~meshprovision.db.nodes.NodeRecord.touched` already does. Unlike
the rest of this module, :func:`persist_adoption` is not side-effect
free -- it is the write phase, kept here (rather than in the CLI layer)
so it stays unit-testable against in-memory repositories, the same
convention as :func:`meshprovision.provisioning.persist.persist_result`.

Secret hygiene: nothing here ever prints or logs raw key bytes or the raw
BLE PIN. Admin-key identification goes through
:func:`meshprovision.crypto.redact.fingerprint`, exactly as in
:mod:`meshprovision.provisioning.pipeline`; :meth:`AdoptionReport.describe`
never renders key material or PIN digits, and
:meth:`AdoptionReport.to_json_dict` renders raw key material only for a
key that is not registered anywhere in the ``Keys`` sheet, and never
renders the BLE PIN itself under any parameter value -- only whether one
was captured.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING

from meshprovision import enums
from meshprovision.crypto import keys as crypto_keys
from meshprovision.crypto import redact, weakkeys
from meshprovision.db import schema
from meshprovision.db.keys import KeyRecord
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import BLE_PIN_LENGTH, KeyOrigin, KeyType, ManagementMode
from meshprovision.errors import AdoptionRefusedError, KeyMaterialError
from meshprovision.provisioning import detect, pipeline
from meshprovision.provisioning.key_registry import adopt_canonical_ref, register_observed_key

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from meshprovision.config.template import TemplateConfig
    from meshprovision.db.keys import KeyRepository
    from meshprovision.db.nodes import NodeRepository
    from meshprovision.nodeid import NodeId
    from meshprovision.provisioning.backup import ChannelInfo

__all__ = [
    "AdoptionReport",
    "LiveAdminKey",
    "adopted_record",
    "build_adoption_report",
    "capture_ble_pin",
    "check_name_pattern_fit",
    "check_stale_private_key",
    "classify_live_admin_keys",
    "persist_adoption",
]


@dataclass(frozen=True, slots=True)
class LiveAdminKey:
    """One admin public key currently authorized on a live device.

    Attributes:
        material: The raw 32-byte public key, as reported live.
        fingerprint: A redacted fingerprint label for ``material``.
        refs: Every ``Keys`` sheet reference whose material matches this
            key, sorted per
            :func:`meshprovision.provisioning.pipeline.match_admin_key_refs`'s
            deterministic ``PREFERRED`` order. Empty when this key is not
            registered under any reference.
        preferred_ref: ``refs[0]``, or ``None`` when ``refs`` is empty.
    """

    material: bytes
    fingerprint: str
    refs: tuple[str, ...]
    preferred_ref: str | None

    def __repr__(self) -> str:
        """Return a repr that never exposes :attr:`material`'s raw bytes.

        Returns:
            The default-shaped dataclass repr, with :attr:`material`
            replaced by its already-computed :attr:`fingerprint`.
        """
        return (
            f"LiveAdminKey(material=<redacted:{self.fingerprint}>, "
            f"fingerprint={self.fingerprint!r}, refs={self.refs!r}, "
            f"preferred_ref={self.preferred_ref!r})"
        )


def classify_live_admin_keys(
    live: detect.LiveConfig, public_keys: Mapping[str, bytes]
) -> tuple[LiveAdminKey, ...]:
    """Match every live admin key against the ``Keys`` sheet's public keys.

    A single public key may legitimately be filed under more than one
    reference (``mesh admin bootstrap --ref LABEL`` deliberately files one
    key under both ``<node_id>_pub`` and ``<LABEL>_pub``), so every
    matching reference is collected, not just the first.

    Args:
        live: The device's normalized live configuration.
        public_keys: ``{key_ref: raw public key}``, as returned by
            :meth:`~meshprovision.db.keys.KeyRepository.public_key_map`.

    Returns:
        One :class:`LiveAdminKey` per entry of ``live.security.admin_keys``,
        in the same (device-reported) order -- never reordered or
        deduplicated, so a device that reports the same key twice yields
        two entries.
    """
    result: list[LiveAdminKey] = []
    for material in live.security.admin_keys:
        matching_refs = pipeline.match_admin_key_refs(material, public_keys)
        result.append(
            LiveAdminKey(
                material=material,
                fingerprint=redact.fingerprint(material),
                refs=matching_refs,
                preferred_ref=matching_refs[0] if matching_refs else None,
            )
        )
    return tuple(result)


def check_name_pattern_fit(
    template: TemplateConfig, *, short_name: str, long_name: str
) -> tuple[str, ...]:
    """Check a device's live names against the template's name patterns.

    An empty name trivially fails to fit and is reported the same as any
    other non-fitting name -- an un-named device is unusual but not an
    error here.

    Args:
        template: The provisioning template supplying the name patterns.
        short_name: The device's live ``short_name``.
        long_name: The device's live ``long_name``.

    Returns:
        Zero, one, or two human-readable warning strings: one for
        ``short_name`` and one for ``long_name``, each only when that name
        does not fit its configured pattern.
    """
    findings: list[str] = []
    if template.short_name_spec().parse_index(short_name) is None:
        findings.append(
            f"short_name {short_name!r} does not match the configured pattern "
            f"{template.short_name_pattern!r} -- recorded as-is."
        )
    if template.long_name_spec().parse_index(long_name) is None:
        findings.append(
            f"long_name {long_name!r} does not match the configured pattern "
            f"{template.long_name_pattern!r} -- recorded as-is."
        )
    return tuple(findings)


def capture_ble_pin(live: detect.LiveConfig) -> str | None:
    """Capture a device's fixed BLE pairing PIN, when one is set.

    Never raises: any value that does not cleanly match the expected
    shape (wrong bluetooth mode, wrong type, out of range) is treated as
    "not capturable" rather than an error.

    Args:
        live: The device's normalized live configuration.

    Returns:
        The PIN, zero-padded to :data:`~meshprovision.db.schema.BLE_PIN_LENGTH`
        digits, when ``bluetooth.mode`` is ``"FIXED_PIN"`` and
        ``bluetooth.fixed_pin`` is an ``int`` in ``(0, 999999]``.
        Otherwise ``None``.
    """
    if live.value("bluetooth", "mode") != "FIXED_PIN":
        return None
    pin = live.value("bluetooth", "fixed_pin")
    if not isinstance(pin, int) or isinstance(pin, bool) or not (0 < pin <= 999999):
        return None
    return str(pin).zfill(BLE_PIN_LENGTH)


@dataclass(frozen=True, slots=True)
class AdoptionReport:
    """A complete, read-only inventory of one device's live state, for ``mesh adopt``.

    Beyond the fields the design brief specifies, this carries the raw
    live ``short_name``/``long_name``/``hw_model``/``firmware_version``
    and the already-validated live ``region``/``role`` (empty string when
    the live value did not map to a known enum -- never a fabricated
    fallback). They exist so :func:`adopted_record` can build the
    persisted row from this report alone, without re-reading ``live`` or
    ``template``: that keeps :func:`adopted_record`'s signature simple,
    matches the "the report is the complete, display-and-persist-ready
    summary of one adoption" model, and guarantees :meth:`describe` and
    :func:`adopted_record` can never disagree about what was actually
    captured, since both read the same already-validated fields.

    Attributes:
        node_id: The device's node id.
        state: This node's classification, from
            :func:`meshprovision.provisioning.detect.classify`.
        existing: The node's existing ``Nodes`` sheet row, or ``None`` if
            this node id was not found in the database.
        short_name: The device's live ``short_name``, recorded as-is.
        long_name: The device's live ``long_name``, recorded as-is.
        hw_model: The device's live ``hw_model``, recorded as-is.
        firmware_version: The device's live firmware version, recorded
            as-is.
        region: The device's live LoRa region, when it maps to a known
            :func:`~meshprovision.enums.region_table` name; ``""``
            otherwise (see :attr:`warnings`).
        role: The device's live device role, when it maps to a known
            :func:`~meshprovision.enums.role_table` name; ``""``
            otherwise (see :attr:`warnings`).
        admin_keys: Every admin key the device currently reports, matched
            against the ``Keys`` sheet, in device order.
        firmware_vulnerable: Whether the live firmware version falls
            inside the CVE-2025-52464 window (see
            :func:`meshprovision.crypto.weakkeys.is_vulnerable_firmware`).
            ``False`` when the version is missing or unparseable too --
            that is NOT the same as confirmed-safe; see :attr:`warnings`
            for the distinction.
        is_managed: Whether the device is locked into admin-managed mode
            (``security.is_managed``).
        ble_pin: The captured fixed BLE PIN, or ``None``. Never rendered
            by :meth:`describe` or :meth:`to_json_dict`.
        warnings: Non-fatal findings, in a fixed order: name-pattern-fit
            warnings, then one weak-key-audit warning per flagged live
            admin key (device order), then a firmware-version warning (if
            any), then an unmappable-region warning (if any), then an
            unmappable-role warning (if any).
        gps_lat: A fixed-position latitude to record, or ``None`` if the
            source carried none (never clears an existing recorded
            value). Set only by ``mesh adopt --from-backup``, whose
            ``DeviceProfile.fixed_position`` is outside
            :class:`~meshprovision.provisioning.detect.LiveConfig`'s
            ``config.position`` section entirely -- a live device adopt
            leaves this ``None``.
        gps_lon: Companion to :attr:`gps_lat`.
        gps_alt: Companion to :attr:`gps_lat`, in meters.
        own_public_key_captured: Whether the device reports its own
            public key, so adopting will write a ``<node_id>_pub`` row.
            Same presence-only convention as :attr:`ble_pin` -- never the
            key material itself, which is already public information
            anyway, just whether the write will happen.
        own_private_key_captured: Whether the device reports its own
            private key *and* it cryptographically derives the reported
            public key, so adopting will write a ``<node_id>_priv`` row.
            A live device normally never exposes a private key at all
            (only a ``--from-backup`` ``.cfg``/``.yaml`` does), so this is
            ordinarily ``False`` for a device adopt. A reported private
            key that does not derive the reported public key leaves this
            ``False`` too -- see :attr:`warnings` -- and only the public
            half is recorded.
        channel_name_to_record: The channel name a
            ``--from-backup``-decoded 32-byte AES256 PSK will be recorded
            under (a ``<node_id>_psk`` row), or ``None`` when no channel
            PSK will be recorded this adopt. Only ever set by the CLI
            layer, which alone knows the decoded channel -- never PSK
            bytes, which are never rendered anywhere in this report.
        source: Where this report's data came from: ``"device"`` for a
            live connection (the default), or a label naming the backup
            file(s) for ``mesh adopt --from-backup``. Rendered by
            :meth:`describe`/:meth:`to_json_dict` only when not
            ``"device"``, so an ordinary device adopt's output is
            unchanged.
    """

    node_id: NodeId
    state: detect.NodeState
    existing: NodeRecord | None
    short_name: str
    long_name: str
    hw_model: str
    firmware_version: str
    region: str
    role: str
    admin_keys: tuple[LiveAdminKey, ...]
    firmware_vulnerable: bool
    is_managed: bool
    ble_pin: str | None = field(repr=False)
    warnings: tuple[str, ...]
    gps_lat: float | None = None
    gps_lon: float | None = None
    gps_alt: int | None = None
    own_public_key_captured: bool = False
    own_private_key_captured: bool = False
    channel_name_to_record: str | None = None
    source: str = "device"

    def describe(self) -> tuple[str, ...]:
        """Render this report as ready-to-print inventory lines.

        Returns:
            One line per finding, never including raw key material or the
            raw BLE PIN.
        """
        lines: list[str] = []
        if self.existing is not None:
            lines.append(
                f"node {self.node_id.display}: already in database "
                f"(management={self.existing.management.value})"
            )
        else:
            lines.append(f"node {self.node_id.display}: not yet in database")

        for key in self.admin_keys:
            if key.refs:
                lines.append(f"admin key {key.fingerprint}: registered as {', '.join(key.refs)}")
            else:
                lines.append(f"admin key {key.fingerprint}: not registered in the Keys sheet")

        if self.firmware_vulnerable:
            lines.append(
                f"firmware {self.firmware_version} is inside the CVE-2025-52464 window "
                "[2.5.0, 2.6.11); the node's keypair is presumptively compromised "
                "regardless of its contents"
            )

        if self.is_managed:
            lines.append(
                "local config writes are rejected; enrolling requires an authorized admin key"
            )

        if self.ble_pin is not None:
            lines.append("a fixed BLE PIN was captured and will be preserved on enrollment")
        else:
            lines.append("no fixed BLE PIN captured; enrolling this node will set a new one")

        if self.own_public_key_captured:
            pub_ref = schema.ref_for(self.node_id.hex, KeyType.ADMIN_PUBLIC)
            lines.append(f"own public key will be recorded as {pub_ref}")
        if self.own_private_key_captured:
            priv_ref = schema.ref_for(self.node_id.hex, KeyType.ADMIN_PRIVATE)
            lines.append(f"own private key will be recorded as {priv_ref}")
        if self.channel_name_to_record is not None:
            lines.append(
                f"channel {self.channel_name_to_record!r} PSK will be recorded as "
                f"{self.node_id.hex}_psk"
            )

        lines.extend(self.warnings)

        if self.source != "device":
            lines.append(f"source: {self.source}")

        return tuple(lines)

    def to_json_dict(self, *, show_key_material: bool = False) -> dict[str, object]:
        """Render this report as a JSON-safe, deterministic dict.

        Args:
            show_key_material: When ``True``, include the base64-encoded
                raw public key for every *unregistered* admin key
                (``refs == ()``). A registered key's material is already
                discoverable via ``mesh admin list``/the ``Keys`` sheet,
                so it is never included here regardless of this flag.
                When the material is not exactly 32 bytes -- reachable
                from a device reporting malformed data, since
                ``detect.py`` applies no length check -- ``"material"``
                is omitted and ``"material_error"`` is set instead,
                rather than emitting a silently-wrong encoding or
                raising and aborting the whole report.

        Returns:
            The report as a plain dict. ``"ble_pin_captured"`` is always a
            boolean and the raw PIN never appears anywhere in the result,
            under any value of ``show_key_material``.
        """
        admin_keys: list[dict[str, object]] = []
        for key in self.admin_keys:
            entry: dict[str, object] = {"fingerprint": key.fingerprint, "refs": list(key.refs)}
            if show_key_material and not key.refs:
                try:
                    entry["material"] = crypto_keys.encode_key(key.material)
                except KeyMaterialError as exc:
                    entry["material_error"] = f"malformed key material: {exc.reason}"
            admin_keys.append(entry)

        return {
            "node_id": self.node_id.hex,
            "state": self.state.value,
            "existing_management": (
                self.existing.management.value if self.existing is not None else None
            ),
            "admin_keys": admin_keys,
            "firmware_vulnerable": self.firmware_vulnerable,
            "is_managed": self.is_managed,
            "ble_pin_captured": self.ble_pin is not None,
            "own_public_key_captured": self.own_public_key_captured,
            "own_private_key_captured": self.own_private_key_captured,
            "channel_name_to_record": self.channel_name_to_record,
            "warnings": list(self.warnings),
            "source": self.source,
        }


def _own_private_key_proven(live: detect.LiveConfig) -> bool:
    """Whether the device reports a private key that derives its reported public key.

    The single proof behind :attr:`AdoptionReport.own_private_key_captured`
    (and so behind :func:`persist_adoption` writing ``<node_id>_priv``)
    and :func:`check_stale_private_key`'s exemption -- one function, so
    the two can never disagree about whether ``_priv`` is about to be
    replaced.

    Args:
        live: The device's normalized live configuration.

    Returns:
        ``True`` only when both halves are present and
        :func:`~meshprovision.crypto.keys.public_key_matches` confirms
        them; ``False`` for absent or malformed material.
    """
    if not live.security.has_private_key:
        return False
    node_private = live.security.private_key
    node_public = live.security.public_key
    if node_private is None or node_public is None:
        return False
    try:
        return crypto_keys.public_key_matches(node_private, node_public)
    except KeyMaterialError:
        return False


def _refuse_stale_private_key(keys: KeyRepository, *, node_id: NodeId, node_public: bytes) -> None:
    """Refuse when ``<node_id>_priv`` exists but does not derive ``node_public``.

    Only meaningful when this adopt will record ``node_public`` without a
    proven private key of its own: the existing ``_priv`` row would then
    survive beside a ``_pub`` it does not belong to -- ``mesh db verify``
    reports that as an inconsistent keypair, and ``private_key_ref`` would
    point at the wrong key. The row is never deleted or overwritten here:
    it may be the only copy of that private key anywhere.

    Args:
        keys: The open :class:`~meshprovision.db.keys.KeyRepository`.
        node_id: The adopted node's id.
        node_public: The public key this adopt is about to record.

    Raises:
        AdoptionRefusedError: If the ``_priv`` row exists and is malformed
            or derives a different public key. Its hint names no override
            flag: there is none.
    """
    ref = schema.ref_for(node_id.hex, KeyType.ADMIN_PRIVATE)
    existing = keys.find(ref)
    if existing is None:
        return
    try:
        derived = crypto_keys.public_from_private(existing.secret())
    except KeyMaterialError:
        problem = f"{ref} holds malformed key material"
    else:
        if derived == node_public:
            return
        problem = (
            f"{ref} holds the private key of a different public key "
            f"({redact.fingerprint(derived)}) than the one {node_id.display} now reports "
            f"({redact.fingerprint(node_public)})"
        )
    raise AdoptionRefusedError(
        f"{problem}, and this adopt has no proven private key to replace it with. "
        "Recording only the new public key would leave the old private key attached to "
        "this node and the Keys sheet inconsistent.",
        node_id=node_id.display,
        hint=(
            "There is no override flag. If the old key is no longer needed, back up the "
            f"database (`mesh db backup`), delete the {ref} row from the Keys sheet by hand "
            "(keep its value if it may still be needed -- it may be the only copy), and "
            "re-run; or adopt from a source that reports the device's matching private key "
            "(a live connection, or a --from-backup profile that includes it)."
        ),
    )


def check_stale_private_key(keys: KeyRepository, live: detect.LiveConfig) -> None:
    """Refuse an adopt that would strand a non-matching ``<node_id>_priv`` row.

    :func:`persist_adoption` records the device's public key always, but
    its private key only with proof (:func:`_own_private_key_proven`).
    Without that proof an existing ``_priv`` row is left as-is, so it must
    already derive the public key being recorded. Called by ``mesh adopt``
    before any output, so ``--dry-run`` refuses too; ``persist_adoption``
    re-checks the same invariant before writing.

    Args:
        keys: The open :class:`~meshprovision.db.keys.KeyRepository`.
        live: The device's (or backup's) normalized live configuration.

    Raises:
        AdoptionRefusedError: See :func:`_refuse_stale_private_key`. Never
            raised when the device reports no public key (nothing is
            recorded), when no ``_priv`` row exists, or when the device's
            own private key is proven and will replace the row.
    """
    node_public = live.security.real_public_key
    if node_public is None:
        return
    if _own_private_key_proven(live):
        return
    _refuse_stale_private_key(keys, node_id=live.node_id, node_public=node_public)


def build_adoption_report(
    live: detect.LiveConfig,
    *,
    existing: NodeRecord | None,
    public_keys: Mapping[str, bytes],
    template: TemplateConfig,
    known_bad: frozenset[bytes],
) -> AdoptionReport:
    """Build the full read-only inventory of one device's live state.

    Deliberately does not check the live names against any *other* node
    in the database -- this function only ever sees one device's live
    config and one ``existing`` record, with no visibility into the rest
    of the ``Nodes`` sheet. A cross-node duplicate-name check belongs in
    the CLI layer, which has full :class:`~meshprovision.db.nodes.NodeRepository`
    access.

    Args:
        live: The device's normalized live configuration.
        existing: The node's existing ``Nodes`` sheet row, or ``None``.
        public_keys: ``{key_ref: raw public key}``, as returned by
            :meth:`~meshprovision.db.keys.KeyRepository.public_key_map`.
        template: The provisioning template supplying the name patterns
            this device's live names are checked against.
        known_bad: The loaded weak-key blocklist, checked against every
            live admin key (see :attr:`AdoptionReport.warnings`).

    Returns:
        The constructed :class:`AdoptionReport`. ``hw_model``/``region``/
        ``role`` are the live values only when they map to a known enum
        name -- an unmappable value is never silently defaulted, only
        warned about via :attr:`AdoptionReport.warnings`.
    """
    state = detect.classify(live, db_entry=existing).state
    admin_keys = classify_live_admin_keys(live, public_keys)

    warnings: list[str] = list(
        check_name_pattern_fit(template, short_name=live.short_name, long_name=live.long_name)
    )

    for key in admin_keys:
        label = key.preferred_ref or key.fingerprint
        try:
            audit = weakkeys.audit_public_key(
                key.material, key_ref=key.preferred_ref, known_bad=known_bad
            )
        except KeyMaterialError as exc:
            warnings.append(f"admin key {label} is malformed key material: {exc.reason}.")
            continue
        if audit.findings:
            warnings.append(f"admin key {label} failed the weak-key audit: {audit.summary()}")

    if not live.firmware_version.strip():
        firmware_vulnerable = False
        warnings.append(
            "no firmware version reported; CVE-2025-52464 status is unknown, not confirmed safe."
        )
    else:
        parsed_firmware = weakkeys.parse_firmware_version(live.firmware_version)
        if parsed_firmware is None:
            firmware_vulnerable = False
            warnings.append(
                f"firmware version {live.firmware_version!r} could not be parsed; "
                "CVE-2025-52464 status is unknown, not confirmed safe."
            )
        else:
            firmware_vulnerable = weakkeys.is_vulnerable_firmware(parsed_firmware)

    if live.hw_model_raw is not None and not live.hw_model:
        warnings.append(
            f"live hw_model {live.hw_model_raw!r} is not a recognized hardware model; "
            "recorded without a hw_model value rather than guessing."
        )

    live_region = live.value("lora", "region")
    region = ""
    if live_region:
        region_name = str(live_region)
        if region_name in enums.region_table().name_to_value:
            region = region_name
        else:
            warnings.append(
                f"live region {region_name!r} is not a recognized LoRa region; recorded "
                "without a region value rather than guessing."
            )

    role = ""
    if live.role_raw is not None:
        # Only ever set by a --from-backup node-db export whose role string
        # this build's role_table doesn't recognize -- the protobuf field
        # itself was deliberately left at its default (there is no numeric
        # value to assign), so live.value("device", "role") would otherwise
        # read back as the recognized-but-wrong default name.
        warnings.append(
            f"live role {live.role_raw!r} is not a recognized device role; recorded "
            "without a role value rather than guessing."
        )
    else:
        live_role = live.value("device", "role")
        if live_role:
            role_name = str(live_role)
            if role_name in enums.role_table().name_to_value:
                role = role_name
            else:
                warnings.append(
                    f"live role {role_name!r} is not a recognized device role; recorded "
                    "without a role value rather than guessing."
                )

    own_private_key_captured = _own_private_key_proven(live)
    if live.security.has_private_key and not own_private_key_captured:
        warnings.append(
            "device-reported private key does not derive its public key; recording public key only"
        )

    return AdoptionReport(
        node_id=live.node_id,
        state=state,
        existing=existing,
        short_name=live.short_name,
        long_name=live.long_name,
        hw_model=live.hw_model,
        firmware_version=live.firmware_version,
        region=region,
        role=role,
        admin_keys=admin_keys,
        firmware_vulnerable=firmware_vulnerable,
        is_managed=live.security.is_managed,
        ble_pin=capture_ble_pin(live),
        warnings=tuple(warnings),
        own_public_key_captured=live.security.has_public_key,
        own_private_key_captured=own_private_key_captured,
    )


def adopted_record(
    report: AdoptionReport,
    *,
    now: datetime,
    observed_refs: Mapping[bytes, str] = MappingProxyType({}),
) -> NodeRecord:
    """Build the ``Nodes`` sheet row an adoption intends to persist.

    ``authorized_admin_keys`` is a **full replace**, deliberately unlike
    :mod:`meshprovision.provisioning.plan`'s narrow-only admin-key rule:
    it is set to exactly the currently-recognized (``preferred_ref is not
    None``) live keys on every call, dropping any ref that is not
    currently live. An observed row has no template-driven desired state
    to preserve against -- its whole purpose is to mirror live reality --
    so re-adopting a node after a key was removed from the device
    correctly drops that ref too, rather than keeping stale last-known
    state the way a template-managed row does.

    Every live admin key ends up with a real ``Keys`` sheet ref, resolved
    via ``observed_refs`` in preference to the key's own ``preferred_ref``
    -- built by the caller (``cli/adopt.py``) calling
    :func:`~meshprovision.provisioning.key_registry.register_observed_key`
    for *every* live admin key *after* this run's own-keypair registration
    and ``adopt_canonical_ref`` reconciliation, since minting or
    re-resolving a ``Keys`` row is a repository-aware operation this pure
    module cannot perform itself. This is deliberately not "``preferred_ref``
    first": ``preferred_ref`` is classified from a snapshot taken *before*
    the write phase runs, and can point at an ``observed-*`` ref that
    ``adopt_canonical_ref`` has since deleted -- e.g. when a node reports
    its own public key on its own ``security.adminKey`` and some other
    node was adopted first under a synthetic ref for that same key.
    ``key.preferred_ref`` remains the fallback for a caller that passes a
    partial (or, by default, empty) ``observed_refs`` map, so a direct
    caller that has not registered every live key still gets today's
    best-known ref rather than losing information. ``unregistered_admin_keys``
    is therefore only ever populated by a key ``observed_refs`` has no
    entry for *and* which also has no ``preferred_ref`` -- material that
    failed to mint a ref at all (not exactly 32 bytes; unreachable from a
    device reporting well-formed data, but ``detect.py`` applies no length
    check).

    Args:
        report: The adoption report to persist.
        now: Timestamp for the touch. Supplied by the caller -- this
            module never reads the clock itself.
        observed_refs: ``{material: key_ref}`` for every live admin key
            the caller has already resolved -- registered under a
            synthetic ``observed-*`` ref, found already registered under
            one from an earlier adopt, or (now) resolved to a real ref
            such as this node's own ``<node_id>_pub``. Defaults to empty,
            in which case every key falls back to its own
            ``preferred_ref``.

    Returns:
        A new :class:`~meshprovision.db.nodes.NodeRecord`, built from
        ``report.existing`` (or a fresh record for ``report.node_id`` when
        ``existing`` is ``None``), with ``management`` set to
        :attr:`~meshprovision.db.schema.ManagementMode.OBSERVED`.
        On a **re-adopt** (``report.existing`` was not ``None``),
        ``hw_model``/``firmware_version``/``role``/``region`` are only
        overwritten when the corresponding :class:`AdoptionReport`
        attribute is non-empty -- otherwise the existing recorded value
        is left untouched, since an empty value here means "this source
        did not report one" (a ``mesh adopt --from-backup`` profile alone
        carries neither ``hw_model`` nor ``firmware_version`` at all;
        an unmapped live ``role``/``region`` behaves the same way), not
        "clear what we already know." On a **first-time adopt**
        (``report.existing`` is ``None``), all four are always set
        explicitly to the report's value -- including the empty string
        when unreported/unmapped -- so a first-time gap is recorded as
        genuinely unknown rather than silently picking up
        :class:`~meshprovision.db.nodes.NodeRecord`'s template-oriented
        ``"CLIENT"``/``"EU_868"`` class defaults as if they had been
        observed.
        ``ble_pin`` is only overwritten when
        :attr:`AdoptionReport.ble_pin` is not ``None``; likewise
        ``gps_lat``/``gps_lon``/``gps_alt`` are only overwritten when the
        corresponding :attr:`AdoptionReport.gps_lat`/:attr:`gps_lon`/
        :attr:`gps_alt` is not ``None`` (set only by a backup adopt whose
        profile carried a fixed position -- see :attr:`AdoptionReport.gps_lat`).
    """
    base = (
        report.existing if report.existing is not None else NodeRecord(node_id=report.node_id.hex)
    )

    # De-duplicated, first-seen order -- classify_live_admin_keys()
    # deliberately never dedupes (a device reporting the same key twice
    # yields two LiveAdminKey entries), but the persisted cell must not
    # assert the same ref twice; schema.normalize_ref_list() would
    # silently clean this up on the next load anyway, so writing it
    # clean here just avoids a transient, self-correcting duplicate.
    seen_refs: set[str] = set()
    admin_key_refs: list[str] = []
    for key in report.admin_keys:
        ref = observed_refs.get(key.material) or key.preferred_ref
        if ref is not None and ref not in seen_refs:
            seen_refs.add(ref)
            admin_key_refs.append(ref)

    # What is left after preferred_ref/observed_refs above is material
    # that could not be given any ref at all -- not exactly 32 bytes, the
    # one case register_observed_key() (and, before it,
    # crypto_keys.encode_key() here) both refuse. De-duplicated,
    # first-seen, same full-replace treatment as admin_key_refs above;
    # the same degrade-not-crash handling AdoptionReport.to_json_dict
    # already gives this material, since the report's own warnings
    # already flag it separately.
    seen_materials: set[bytes] = set()
    unregistered_encoded: list[str] = []
    for key in report.admin_keys:
        if key.preferred_ref is not None or key.material in observed_refs:
            continue
        if key.material in seen_materials:
            continue
        seen_materials.add(key.material)
        try:
            unregistered_encoded.append(crypto_keys.encode_key(key.material))
        except KeyMaterialError:
            continue

    changes: dict[str, object] = {
        "short_name": report.short_name,
        "long_name": report.long_name,
        "authorized_admin_keys": tuple(admin_key_refs),
        "unregistered_admin_keys": tuple(unregistered_encoded),
        "management": ManagementMode.OBSERVED,
    }
    # hw_model/firmware_version follow the same "empty is no new information,
    # not evidence of absence" rule role/region already had below -- a
    # backup-only adopt (mesh adopt --from-backup with no paired node-db
    # export) reports both as "" (a .cfg carries neither at all), and
    # without this guard a re-adopt from such a backup would blank out
    # values a live adopt had previously recorded.
    if report.hw_model or report.existing is None:
        changes["hw_model"] = report.hw_model
    if report.firmware_version or report.existing is None:
        changes["firmware_version"] = report.firmware_version
    if report.role or report.existing is None:
        changes["role"] = report.role
    if report.region or report.existing is None:
        changes["region"] = report.region
    if report.ble_pin is not None:
        changes["ble_pin"] = report.ble_pin
    if report.gps_lat is not None:
        changes["gps_lat"] = report.gps_lat
    if report.gps_lon is not None:
        changes["gps_lon"] = report.gps_lon
    if report.gps_alt is not None:
        changes["gps_alt"] = report.gps_alt

    return base.with_updates(**changes).touched(now=now)


def persist_adoption(
    report: AdoptionReport,
    live: detect.LiveConfig,
    *,
    nodes: NodeRepository,
    keys: KeyRepository,
    channel: ChannelInfo | None,
    now: datetime,
) -> NodeRecord:
    """Write one adoption's result into the ``Nodes``/``Keys`` sheets.

    Performs, in order, exactly what ``mesh adopt`` has always persisted:
    the device's own keypair (or public-only key), the
    ``adopt_canonical_ref`` reconciliation, an optional decoded channel
    PSK, every live admin key's ``observed-*``/real ref resolution, and
    finally the :class:`~meshprovision.db.nodes.NodeRecord` itself. The
    ordering is load-bearing and documented inline below; it must not be
    reshuffled without re-reading why each step runs where it does.

    Does not call ``ctx.confirm``/``--dry-run`` handling or echo any
    output -- the caller (``cli/adopt.py``) is responsible for that, and
    for deciding *whether* to call this at all. It does call
    ``nodes.db.save()`` itself, below, matching
    :func:`meshprovision.provisioning.persist.persist_result`'s convention.

    Args:
        report: The adoption report to persist.
        live: The device's normalized live configuration, for its own
            keypair material and node id.
        nodes: The open :class:`~meshprovision.db.nodes.NodeRepository`.
        keys: The open :class:`~meshprovision.db.keys.KeyRepository`.
            Must share the same
            :class:`~meshprovision.db.ods.OdsDatabase` session as
            ``nodes`` -- this is what makes the final :meth:`save` atomic
            across both sheets.
        channel: The backup's decoded channel PSK to record, or ``None``.
        now: Timestamp for every upsert and the node's ``touched`` update.

    Returns:
        The upserted :class:`~meshprovision.db.nodes.NodeRecord`.

    Raises:
        AdoptionRefusedError: If the node's own key is recorded public-only
            while an existing ``<node_id>_priv`` row does not derive it (see
            :func:`check_stale_private_key`, which ``mesh adopt`` runs
            first). Raised before anything is written.
    """
    node_id_hex = live.node_id.hex

    # The node's own keypair, so public_key_ref/private_key_ref
    # actually resolve (see NodeRecord.public_key_ref/private_key_ref)
    # -- mirrors what mesh provision records via KeyRecord.for_keypair,
    # public half always, private half only when report.own_private_key_captured
    # (the device exposes one and it was proven to derive the reported
    # public key -- see build_adoption_report). Registered *before* the
    # observed-admin-key loop below, so a device that also lists its own
    # key on security.adminKey resolves that entry to this real ref
    # rather than minting a fresh observed one for it.
    node_public = live.security.real_public_key
    node_private = live.security.private_key
    if node_public is not None:
        if report.own_private_key_captured and node_private is not None:
            pair = crypto_keys.KeyPair(private=node_private, public=node_public)
            pub_record, priv_record = KeyRecord.for_keypair(
                node_id_hex, pair, origin=KeyOrigin.CAPTURED, created_ts=now
            )
            keys.upsert(pub_record)
            keys.upsert(priv_record)
        else:
            # Defense in depth behind the CLI's earlier check_stale_private_key
            # call: no proven private key is written on this branch, so an
            # existing _priv row must already belong to node_public. Raises
            # before the first write of this function.
            _refuse_stale_private_key(keys, node_id=live.node_id, node_public=node_public)
            keys.upsert(
                KeyRecord.from_material(
                    node_id_hex,
                    KeyType.ADMIN_PUBLIC,
                    node_public,
                    origin=KeyOrigin.CAPTURED,
                    created_ts=now,
                )
            )
        # Reconcile: this key may already sit on some other node's row
        # under a synthetic observed-* ref from an earlier adopt, back
        # before its real owner was known.
        adopt_canonical_ref(nodes, keys, material=node_public, canonical_owner=node_id_hex)

    # A --from-backup profile's channel_url, decoded to its primary
    # channel's PSK -- only ever a 32-byte AES256 key (the CLI layer
    # only ever passes a non-None channel for that case): a 1-byte
    # "default" preset or 16-byte AES128 PSK cannot round-trip through
    # this column, which was built for X25519-sized (32-byte) material.
    if channel is not None:
        keys.upsert(
            KeyRecord.from_material(
                node_id_hex,
                KeyType.CHANNEL_PSK,
                channel.psk,
                origin=KeyOrigin.CAPTURED,
                created_ts=now,
            )
        )

    # Resolve every live admin key's ref *now*, after the own-keypair
    # registration and adopt_canonical_ref reconciliation above --
    # never from report.admin_keys' own key.preferred_ref, which was
    # classified before either of those ran and can be stale: when
    # the device also lists its own key on security.adminKey,
    # adopt_canonical_ref may have just deleted the observed-* ref
    # that classification pointed at (its real owner turned out to be
    # this node). register_observed_key() is idempotent and cheap for
    # an already-registered key (it resolves and returns the existing
    # ref via pipeline.match_admin_key_refs without writing anything),
    # so calling it unconditionally for every live key -- not only
    # ones report.admin_keys thought were unregistered -- is what
    # keeps this resolution current. A malformed-length key (detect.py
    # applies no length check) is simply skipped, same degrade-not-
    # crash treatment as everywhere else in this module;
    # adopted_record() below then falls back to recording it on
    # unregistered_admin_keys, exactly as before.
    observed_refs: dict[bytes, str] = {}
    for key in report.admin_keys:
        try:
            observed_refs[key.material] = register_observed_key(
                nodes, keys, key.material, created_ts=now
            )
        except KeyMaterialError:
            continue

    record = adopted_record(report, now=now, observed_refs=observed_refs)
    nodes.upsert(record)
    nodes.db.save()
    return record
