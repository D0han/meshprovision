"""Read-back/verification half of ``apply.py``'s write-then-verify guarantee.

Split out of ``apply.py`` (which had grown past the project's ~400-line
typical file size) along the same kind of seam already used for
:mod:`~meshprovision.provisioning.apply_session`: everything here --
:func:`_render_value`, :func:`_verify_name`, :func:`_verify_key_material`,
:func:`_verify_admin_keys`, and :func:`verify_plan` -- only ever compares a
freshly re-read live device state against a plan's intent; it never writes
anything. ``apply.py`` imports :func:`verify_plan` from here and calls it
once, after its own write phase and reconnect.

Secret hygiene: same invariant as ``apply.py`` -- nothing here ever logs,
prints, or otherwise renders raw key bytes, base64 key strings, or a BLE
PIN. Every human-facing representation of a secret field goes through
:func:`meshprovision.crypto.redact.fingerprint` first.
"""

from __future__ import annotations

import logging
from collections.abc import Collection

from meshprovision.crypto import redact
from meshprovision.crypto.keys import KeyPair, decode_key
from meshprovision.errors import KeyMaterialError
from meshprovision.provisioning import detect
from meshprovision.provisioning.apply_session import WriteResult, WriteStatus
from meshprovision.provisioning.plan import ChangePlan, values_equal

__all__ = [
    "verify_plan",
]

_logger = logging.getLogger(__name__)


def _render_value(value: object, *, secret: bool) -> str:
    """Render a plan/live value as an already-redacted, human-readable string.

    Args:
        value: The value to render.
        secret: Whether this field is secret (per
            :attr:`~meshprovision.provisioning.plan.FieldChange.secret`).

    Returns:
        The literal ``"<redacted>"`` when ``secret`` is ``True``;
        otherwise ``str(value)``.
    """
    if secret:
        return "<redacted>"
    return str(value)


def _verify_name(
    live: detect.LiveConfig, desired: str | None, *, field: str, read_back: bool = True
) -> WriteResult | None:
    """Verify one name field (``short_name``/``long_name``) against its desired value.

    Args:
        live: The freshly re-read live configuration.
        desired: The name the plan intended to write, or ``None`` if this
            name was not part of the plan.
        field: ``"short_name"`` or ``"long_name"``.
        read_back: Whether the session that produced ``live`` genuinely
            re-read from the device (see
            :attr:`~meshprovision.provisioning.apply_session.DeviceSession.reads_back`).
            When ``False``, a mismatch that would otherwise be
            :attr:`WriteStatus.UNCONFIRMED` is instead reported
            :attr:`WriteStatus.CONFIRMED` with a note that the write
            could not be read back -- the in-memory interface a
            non-reconnecting session re-reads may simply not reflect the
            same post-write state a real reconnect would, so an
            unconditional UNCONFIRMED here would misreport imprecision
            as failure (``--no-reconnect``, see firmware issue #7449).

    Returns:
        ``None`` when ``desired`` is ``None`` (nothing to verify);
        otherwise the :class:`WriteResult` for this name.
    """
    if desired is None:
        return None
    actual = live.short_name if field == "short_name" else live.long_name
    if actual == desired:
        return WriteResult("owner", WriteStatus.CONFIRMED, "confirmed", field=field)
    # actual must be non-empty: an empty read-back is not truncation, it's
    # the post-reboot NodeDB user entry not having repopulated yet (the
    # same condition _verify_key_material already treats as "unavailable"
    # for the sibling getPublicKey() read -- both come from iface.getMyUser()).
    # Without this guard, desired.startswith("") is trivially True and an
    # unreadable name was misreported CONFIRMED, silently blanking it.
    if (
        actual
        and desired.startswith(actual)
        and len(actual.encode("utf-8")) < len(desired.encode("utf-8"))
    ):
        return WriteResult(
            "owner",
            WriteStatus.CONFIRMED,
            f"firmware truncated the name to {len(actual.encode('utf-8'))} bytes",
            field=field,
            expected=desired,
            actual=actual,
        )
    if not read_back:
        return WriteResult(
            "owner",
            WriteStatus.CONFIRMED,
            "written; not read back (--no-reconnect)",
            field=field,
        )
    return WriteResult(
        "owner",
        WriteStatus.UNCONFIRMED,
        "name did not match after write",
        field=field,
        expected=desired,
        actual=actual,
    )


def _verify_key_material(
    plan: ChangePlan,
    live_after: detect.LiveConfig,
    *,
    keypair: KeyPair | None,
    device_public_key: object,
) -> WriteResult | None:
    """Verify the node's own keypair, per the firmware issue #7449 requirement.

    Runs for both ``key_plan.regenerate`` (a freshly written keypair must
    actually have taken) and ``key_plan.adopt_device_key`` (the keypair
    ``persist_result`` is about to record as the device's own must still
    genuinely be on the device after this run's writes and reboot --
    #7449 is exactly "a restored key can silently fail to persist", and an
    unrelated section write earlier in this same plan can still trigger
    that reboot). A key write is confirmed only when both the fresh
    ``LocalConfig`` read and the independent NodeDB view
    (``iface.getPublicKey()``) agree with ``keypair.public``.

    Args:
        plan: The executed plan.
        live_after: The freshly re-read live configuration.
        keypair: The keypair to confirm -- freshly generated when
            ``regenerate`` is set, or the device's pre-existing keypair
            (as read before this run's writes) when ``adopt_device_key``
            is set.
        device_public_key: The raw value of ``iface.getPublicKey()``: a
            base64 ``str`` (the common case -- it is produced by
            ``google.protobuf.json_format.MessageToDict``), raw
            ``bytes``, or ``None`` when the NodeDB entry is not yet
            repopulated.

    Returns:
        ``None`` when the plan neither regenerated nor adopted a key;
        otherwise the :class:`WriteResult` for ``security.public_key``.
    """
    if keypair is None or not (plan.key_plan.regenerate or plan.key_plan.adopt_device_key):
        return None

    local_config_ok = live_after.security.public_key == keypair.public

    nodedb_available = device_public_key is not None
    nodedb_bytes: bytes | None = None
    nodedb_decode_error: str | None = None
    if isinstance(device_public_key, bytes | bytearray):
        nodedb_bytes = bytes(device_public_key)
    elif isinstance(device_public_key, str):
        try:
            nodedb_bytes = decode_key(device_public_key, field="NodeDB public key")
        except KeyMaterialError as exc:
            nodedb_decode_error = exc.reason
    nodedb_ok = nodedb_bytes is not None and nodedb_bytes == keypair.public

    if local_config_ok and (nodedb_ok or not nodedb_available):
        note = "" if nodedb_available else " (NodeDB cross-check unavailable)"
        return WriteResult(
            "security", WriteStatus.CONFIRMED, f"public key confirmed{note}", field="public_key"
        )

    if nodedb_decode_error is not None:
        # Distinct from "decoded fine but genuinely differs" below -- the
        # NodeDB value never became comparable at all.
        actual_repr = f"<NodeDB value did not decode: {nodedb_decode_error}>"
    else:
        actual_bytes = nodedb_bytes if nodedb_bytes is not None else live_after.security.public_key
        actual_repr = redact.fingerprint(actual_bytes) if actual_bytes is not None else "<absent>"
    return WriteResult(
        "security",
        WriteStatus.UNCONFIRMED,
        "public key mismatch after write",
        field="public_key",
        expected=redact.fingerprint(keypair.public),
        actual=actual_repr,
    )


def _verify_admin_keys(plan: ChangePlan, live_after: detect.LiveConfig) -> WriteResult | None:
    """Verify the device's authorized admin keys against the plan's intent.

    Args:
        plan: The executed plan.
        live_after: The freshly re-read live configuration.

    Returns:
        ``None`` when the plan did not change admin keys; otherwise the
        :class:`WriteResult` for ``security.admin_key``.
    """
    if not plan.key_plan.change_admin_keys:
        return None

    desired = sorted(plan.key_plan.desired_admin_keys)
    actual = sorted(live_after.security.admin_keys)
    if desired == actual:
        return WriteResult(
            "security",
            WriteStatus.CONFIRMED,
            f"{len(actual)} admin key(s) confirmed",
            field="admin_key",
        )
    expected_fps = ", ".join(redact.fingerprint(k) for k in desired)
    actual_fps = ", ".join(redact.fingerprint(k) for k in actual)
    return WriteResult(
        "security",
        WriteStatus.UNCONFIRMED,
        f"admin key set mismatch: expected {len(desired)}, got {len(actual)}",
        field="admin_key",
        expected=expected_fps or "<none>",
        actual=actual_fps or "<none>",
    )


def verify_plan(
    plan: ChangePlan,
    live_after: detect.LiveConfig,
    *,
    keypair: KeyPair | None,
    device_public_key: object = None,
    attempted_sections: Collection[str] | None = None,
    read_back: bool = True,
) -> tuple[WriteResult, ...]:
    """Compare a freshly re-read device state against a plan's intent.

    This is the read-back half of the transactional write guarantee: it
    never writes anything, only compares.

    Args:
        plan: The executed plan.
        live_after: The freshly re-read live configuration (obtained
            through :meth:`DeviceSession.refresh`, never the in-memory
            copy the write phase used).
        keypair: The freshly generated keypair, when the plan regenerated
            one.
        read_back: Whether the session that produced ``live_after``
            genuinely re-read from the device (see
            :attr:`~meshprovision.provisioning.apply_session.DeviceSession.reads_back`).
            Threaded only to the two name-field verifications (see
            :func:`_verify_name`) -- the one case where the in-memory
            interface a non-reconnecting session re-reads may not reflect
            the same post-write state a real reconnect would. Ordinary
            field verification, :func:`_verify_key_material`, and
            :func:`_verify_admin_keys` compare directly against the
            in-memory interface either way, and the CLI refuses
            ``--no-reconnect`` outright when the plan would regenerate
            the key (see ``run_provision``), so they never need this.
        device_public_key: The raw value of ``iface.getPublicKey()``, as
            documented on :func:`_verify_key_material`.
        attempted_sections: The section names whose ``writeConfig`` was
            actually called (see :func:`apply_plan`'s stop-on-first-failure
            behavior). ``None`` (the default) means every section in
            ``plan.sections`` was attempted -- today's behavior for every
            direct caller. A section not in this collection is skipped
            entirely: reporting it "unconfirmed: value mismatch" would
            wrongly suggest it was written. When ``"security"`` was not
            attempted, :func:`_verify_admin_keys` is skipped outright, and
            :func:`_verify_key_material` is skipped only when
            ``plan.key_plan.regenerate`` is set -- an ``adopt_device_key``
            plan still verifies that the device's pre-existing key
            survived the earlier writes and reboot, independent of
            whether this run's own security write happened.

    Returns:
        One :class:`WriteResult` per verified field/section, covering the
        name phase, every ordinary field change, and (when relevant) the
        key-material and admin-key checks.
    """
    results: list[WriteResult] = []
    security_attempted = attempted_sections is None or "security" in attempted_sections

    short_result = _verify_name(
        live_after,
        plan.name_change.desired_short_name if plan.name_change.short_changed else None,
        field="short_name",
        read_back=read_back,
    )
    if short_result is not None:
        results.append(short_result)
    long_result = _verify_name(
        live_after,
        plan.name_change.desired_long_name if plan.name_change.long_changed else None,
        field="long_name",
        read_back=read_back,
    )
    if long_result is not None:
        results.append(long_result)

    if plan.name_change.is_unmessagable_changed:
        desired_is_unmessagable = plan.name_change.desired_is_unmessagable
        if live_after.is_unmessagable == desired_is_unmessagable:
            results.append(
                WriteResult("owner", WriteStatus.CONFIRMED, "confirmed", field="is_unmessagable")
            )
        else:
            results.append(
                WriteResult(
                    "owner",
                    WriteStatus.UNCONFIRMED,
                    "value mismatch after write",
                    field="is_unmessagable",
                    expected=str(desired_is_unmessagable),
                    actual=str(live_after.is_unmessagable),
                )
            )

    for change in plan.sections:
        if attempted_sections is not None and change.section not in attempted_sections:
            continue
        for field_change in change.changes:
            if change.section == "security":
                # LiveConfig.sections/module_sections deliberately exclude
                # "security" (its content lives in LiveConfig.security
                # instead -- see that field's docstring), so the generic
                # value() lookup below always returns None here and every
                # security scalar field (is_managed, serial_enabled,
                # debug_log_api_enabled, admin_channel_enabled) would
                # otherwise report UNCONFIRMED even on a fully successful
                # write. Read the real post-write value the same way
                # _verify_key_material/_verify_admin_keys already do.
                actual = getattr(live_after.security, field_change.field, None)
            elif change.section == "default_channel":
                # LiveConfig.sections/module_sections deliberately exclude
                # "default_channel" too -- it is backed by a structurally
                # different container (iface.localNode.channels), not
                # LocalConfig/LocalModuleConfig -- so the generic value()
                # lookup below would always return None here.
                actual = live_after.default_channel.get(field_change.field)
            else:
                actual = live_after.value(change.section, field_change.field)
            if values_equal(actual, field_change.desired):
                results.append(
                    WriteResult(
                        change.section, WriteStatus.CONFIRMED, "confirmed", field=field_change.field
                    )
                )
            else:
                results.append(
                    WriteResult(
                        change.section,
                        WriteStatus.UNCONFIRMED,
                        "value mismatch after write",
                        field=field_change.field,
                        expected=_render_value(field_change.desired, secret=field_change.secret),
                        actual=_render_value(actual, secret=field_change.secret),
                    )
                )

    if security_attempted or not plan.key_plan.regenerate:
        key_result = _verify_key_material(
            plan, live_after, keypair=keypair, device_public_key=device_public_key
        )
        if key_result is not None:
            results.append(key_result)

    if security_attempted:
        admin_result = _verify_admin_keys(plan, live_after)
        if admin_result is not None:
            results.append(admin_result)

    confirmed = sum(1 for r in results if r.status == WriteStatus.CONFIRMED)
    _logger.debug(
        "Verified %d field(s): %d confirmed, %d unconfirmed.",
        len(results),
        confirmed,
        len(results) - confirmed,
    )
    return tuple(results)
