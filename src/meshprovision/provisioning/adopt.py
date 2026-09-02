"""Pure adoption logic: an already-deployed device's live state -> a record of it.

The pure half of the ``mesh adopt`` command (see
:mod:`meshprovision.cli.adopt`), which connects to a device that is
already configured and already in service and records its *actual* live
state into the database -- the opposite of ``mesh provision``: no
desired-state diff against a template (unlike
:mod:`meshprovision.provisioning.plan`), and no device write anywhere in
this package. :func:`build_adoption_report` turns an already-read
:class:`~meshprovision.provisioning.detect.LiveConfig`, an optional
existing :class:`~meshprovision.db.nodes.NodeRecord`, a ``{key_ref:
material}`` map, and an already-loaded
:class:`~meshprovision.config.template.TemplateConfig` into an
:class:`AdoptionReport` -- a full, read-only inventory of what the device
is currently carrying, ready to display. :func:`adopted_record` turns
that report into the :class:`~meshprovision.db.nodes.NodeRecord` to
persist.

Nothing here touches a :class:`~meshprovision.cli.common.CliContext`, a
``DbSession``, a click prompt, or a console; and nothing here reads the
clock -- :func:`adopted_record` takes ``now`` as an explicit argument,
exactly like :meth:`~meshprovision.db.nodes.NodeRecord.touched` already
does, so this module stays as pure and deterministic as
:mod:`meshprovision.provisioning.plan`.

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

import base64
from dataclasses import dataclass
from typing import TYPE_CHECKING

from meshprovision import enums
from meshprovision.crypto import redact, weakkeys
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import BLE_PIN_LENGTH, ManagementMode
from meshprovision.provisioning import detect, pipeline

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from meshprovision.config.template import TemplateConfig
    from meshprovision.nodeid import NodeId

__all__ = [
    "AdoptionReport",
    "LiveAdminKey",
    "adopted_record",
    "build_adoption_report",
    "capture_ble_pin",
    "check_name_pattern_fit",
    "classify_live_admin_keys",
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
            warnings, then an unmappable-region warning (if any), then an
            unmappable-role warning (if any).
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
    ble_pin: str | None
    warnings: tuple[str, ...]

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

        lines.extend(self.warnings)
        return tuple(lines)

    def to_json_dict(self, *, show_key_material: bool = False) -> dict[str, object]:
        """Render this report as a JSON-safe, deterministic dict.

        Args:
            show_key_material: When ``True``, include the base64-encoded
                raw public key for every *unregistered* admin key
                (``refs == ()``). A registered key's material is already
                discoverable via ``mesh admin list``/the ``Keys`` sheet,
                so it is never included here regardless of this flag.

        Returns:
            The report as a plain dict. ``"ble_pin_captured"`` is always a
            boolean and the raw PIN never appears anywhere in the result,
            under any value of ``show_key_material``.
        """
        admin_keys: list[dict[str, object]] = []
        for key in self.admin_keys:
            entry: dict[str, object] = {"fingerprint": key.fingerprint, "refs": list(key.refs)}
            if show_key_material and not key.refs:
                entry["material"] = base64.b64encode(key.material).decode("ascii")
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
            "warnings": list(self.warnings),
        }


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
        known_bad: The loaded weak-key blocklist. Accepted for
            signature-compatibility with the rest of this package and
            reserved for a future per-admin-key weak-key audit during
            adopt; **unused** by this batch's logic, which only wires up
            the firmware-window and name-pattern checks.

    Returns:
        The constructed :class:`AdoptionReport`. ``region``/``role`` are
        the live values only when they map to a known enum name -- an
        unmappable value is never silently defaulted, only warned about
        via :attr:`AdoptionReport.warnings`.
    """
    del known_bad

    state = detect.classify(live, db_entry=existing).state
    admin_keys = classify_live_admin_keys(live, public_keys)

    warnings: list[str] = list(
        check_name_pattern_fit(template, short_name=live.short_name, long_name=live.long_name)
    )

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

    live_role = live.value("device", "role")
    role = ""
    if live_role:
        role_name = str(live_role)
        if role_name in enums.role_table().name_to_value:
            role = role_name
        else:
            warnings.append(
                f"live role {role_name!r} is not a recognized device role; recorded "
                "without a role value rather than guessing."
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
    )


def adopted_record(report: AdoptionReport, *, now: datetime) -> NodeRecord:
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

    Never writes a ``Keys`` sheet row: an unregistered admin key
    (``preferred_ref is None``) is simply excluded here. Registering it is
    a separate, explicit ``mesh admin import`` action for the operator.

    Args:
        report: The adoption report to persist.
        now: Timestamp for the touch. Supplied by the caller -- this
            module never reads the clock itself.

    Returns:
        A new :class:`~meshprovision.db.nodes.NodeRecord`, built from
        ``report.existing`` (or a fresh record for ``report.node_id`` when
        ``existing`` is ``None``), with ``management`` set to
        :attr:`~meshprovision.db.schema.ManagementMode.OBSERVED`.
        On a **re-adopt** (``report.existing`` was not ``None``),
        ``role``/``region`` are only overwritten when
        :attr:`AdoptionReport.role`/:attr:`AdoptionReport.region` are
        non-empty (i.e. the live value validated) -- otherwise the
        existing recorded value is left untouched, since an unmapped live
        value is "no new information," not "clear what we already know."
        On a **first-time adopt** (``report.existing`` is ``None``),
        ``role``/``region`` are always set explicitly to
        :attr:`AdoptionReport.role`/:attr:`AdoptionReport.region` --
        including the empty string when unmapped -- so an unrecognized
        live value is recorded as genuinely unknown rather than silently
        picking up :class:`~meshprovision.db.nodes.NodeRecord`'s
        template-oriented ``"CLIENT"``/``"EU_868"`` class defaults as if
        they had been observed.
        ``ble_pin`` is only overwritten when
        :attr:`AdoptionReport.ble_pin` is not ``None``.
    """
    base = (
        report.existing if report.existing is not None else NodeRecord(node_id=report.node_id.hex)
    )

    changes: dict[str, object] = {
        "short_name": report.short_name,
        "long_name": report.long_name,
        "hw_model": report.hw_model,
        "firmware_version": report.firmware_version,
        "authorized_admin_keys": tuple(
            key.preferred_ref for key in report.admin_keys if key.preferred_ref is not None
        ),
        "management": ManagementMode.OBSERVED,
    }
    if report.role or report.existing is None:
        changes["role"] = report.role
    if report.region or report.existing is None:
        changes["region"] = report.region
    if report.ble_pin is not None:
        changes["ble_pin"] = report.ble_pin

    return base.with_updates(**changes).touched(now=now)
