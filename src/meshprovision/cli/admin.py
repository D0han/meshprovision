"""``mesh admin`` group -- admin-key custody: ``bootstrap``, ``import``, ``list``.

The chicken-and-egg problem (no node can be provisioned as managed until
some admin's public key already exists in the ``Keys`` sheet) is solved
two ways, both here: ``mesh admin bootstrap`` provisions the connected
node *and* registers it as an admin in one pass (reusing
:mod:`meshprovision.cli.provision`'s pipeline wholesale, never
duplicating it), and ``mesh admin import`` registers a public key already
held elsewhere without touching a device.

Secret hygiene: nothing here ever echoes a base64-encoded key, a
``KeyRecord.key_value``, or a revealed :class:`~meshprovision.crypto.
redact.SecretBytes`. Keys are always identified by
:func:`meshprovision.crypto.redact.fingerprint` or ``KeyRecord.fingerprint``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import click

from meshprovision.cli.common import CONTEXT_SETTINGS, echo_json, handle_cli_errors, pass_cli
from meshprovision.cli.provision import (
    ProvisionOptions,
    TransportOptions,
    device_session,
    provisioning_options,
    resolve_backend,
    run_provision,
    transport_options,
)
from meshprovision.crypto import keys as crypto_keys
from meshprovision.crypto import redact, weakkeys
from meshprovision.db import schema
from meshprovision.db.keys import KeyRecord
from meshprovision.db.schema import KeyType
from meshprovision.errors import (
    ExitCode,
    KeyVerificationError,
    SettingsError,
    WeakKeyError,
    WeakKeySeverity,
)
from meshprovision.provisioning import connection
from meshprovision.provisioning.admin_custody import build_admin_table, collect_admins

if TYPE_CHECKING:
    from meshprovision.cli.common import CliContext
    from meshprovision.db.nodes import NodeRepository

__all__ = [
    "admin",
    "admin_bootstrap",
    "admin_import",
    "admin_list",
    "parse_assignment",
]


def _validate_admin_ref(ref: str) -> None:
    """Validate an admin reference's shape, shared by import and bootstrap.

    Args:
        ref: The already-stripped candidate admin reference.

    Raises:
        SettingsError: If ``ref`` does not match
            :data:`meshprovision.db.schema.REF_PATTERN`, or ends in
            ``_pub``, ``_priv``, or ``_psk`` (mirroring the template
            validator's own rule for ``admin_nodes`` entries).
    """
    if not schema.REF_PATTERN.match(ref):
        raise SettingsError(
            f"{ref!r} is not a valid admin reference.",
            hint="Use 1-64 characters from [A-Za-z0-9._-], starting with an alphanumeric.",
        )
    if ref.endswith(("_pub", "_priv", "_psk")):
        raise SettingsError(
            f"Admin reference {ref!r} must not end in '_pub', '_priv', or '_psk'.",
            hint="meshprovision appends these suffixes itself when resolving Keys sheet rows.",
        )


def _drop_now_registered_key(db_nodes: NodeRepository, material: bytes) -> None:
    """Clear a just-registered key from every node's ``unregistered_admin_keys``.

    ``mesh adopt`` persists an admin key it could not resolve to a ``Keys``
    sheet ref onto the adopting node's ``unregistered_admin_keys``. Once
    ``mesh admin import`` files that same material under a ref, the field
    is stale, and :func:`meshprovision.cli.adopt._duplicate_admin_key_warnings`
    would describe the key as "unregistered" until the node is re-adopted.
    Mutates the in-memory session only; the caller owns the transaction.

    Args:
        db_nodes: The open :class:`~meshprovision.db.nodes.NodeRepository`.
        material: The raw public key that was just registered.
    """
    for node in db_nodes.all():
        kept = tuple(
            encoded
            for encoded, raw in zip(
                node.unregistered_admin_keys,
                node.unregistered_admin_key_materials(),
                strict=True,
            )
            if raw != material
        )
        if len(kept) != len(node.unregistered_admin_keys):
            db_nodes.upsert(node.with_updates(unregistered_admin_keys=kept))


def parse_assignment(raw: str) -> tuple[str, str]:
    """Parse one ``REF=BASE64`` assignment.

    Partitions on the *first* ``=`` so base64 padding at the end survives.

    Args:
        raw: The raw ``REF=BASE64`` token.

    Returns:
        The ``(ref, base64)`` pair, both stripped. ``base64`` is returned
        unvalidated -- the caller decodes it separately.

    Raises:
        SettingsError: If ``raw`` contains no ``=``, or the ``REF`` half
            fails :func:`_validate_admin_ref`. Never echoes the base64
            half in any message.
    """
    ref, sep, b64 = raw.partition("=")
    if not sep:
        raise SettingsError(
            f"Expected REF=BASE64, got {raw!r}.",
            hint="Example: mesh admin import ADMIN1=<base64 public key>",
        )
    ref = ref.strip()
    b64 = b64.strip()
    _validate_admin_ref(ref)
    return ref, b64


@click.group(name="admin", context_settings=CONTEXT_SETTINGS)
def admin() -> None:
    """Manage admin-key custody: bootstrap, import, and list configured admins."""


@admin.command(name="bootstrap")
@transport_options
@provisioning_options
@click.option(
    "--ref",
    default=None,
    metavar="REF",
    help="Admin reference to file this node's keys under. Defaults to the node's hex id.",
)
@pass_cli
@handle_cli_errors
def admin_bootstrap(
    ctx: CliContext,
    *,
    port: str | None,
    ble_address: str | None,
    ble_scan: bool,
    host: str | None,
    interface: str | None,
    timeout: int,
    ble_scan_timeout: float,
    ref: str | None,
    dry_run: bool,
    yes: bool,
    enroll: bool,
    allow_lockdown: bool,
    allow_weak_admin_key: bool,
    force_regenerate_key: bool,
    no_reconnect: bool,
    json_output: bool,
) -> None:
    """Provision the connected node and register it as an admin.

    Reuses :func:`meshprovision.cli.provision.run_provision` wholesale:
    generates the connected node's keypair, writes it to the device,
    records it in both sheets, and (when ``--ref`` names an alias
    different from the node's own hex id) additionally files the same
    public/private material under that alias. Reports which of the
    template's other admins are already authorized on this node, and
    which cross-authorizations are still pending.

    Args:
        ctx: The shared CLI context, injected by :data:`~meshprovision.
            cli.common.pass_cli`.
        port: Explicit serial port, from ``--port``.
        ble_address: Explicit BLE address, from ``--ble-address``.
        ble_scan: Whether to force BLE and scan, from ``--ble-scan``.
        host: Explicit TCP host, from ``--host``.
        interface: Forced transport name, from ``--interface``.
        timeout: Connect timeout, in seconds, from ``--timeout``.
        ble_scan_timeout: BLE scan duration, from ``--ble-scan-timeout``.
        ref: Admin reference to file this node under, from ``--ref``.
            Defaults to the connected node's own hex id.
        dry_run: Whether to skip all writes, from ``--dry-run``.
        yes: Whether to assume yes to confirmations, from ``-y``/``--yes``.
        enroll: Whether to bring an observed node under template
            management, from --enroll.
        allow_lockdown: Whether to authorize ``security.is_managed``, from
            ``--allow-lockdown``.
        allow_weak_admin_key: Whether to authorize admin keys that fail
            the weak-key audit, from ``--allow-weak-admin-key``.
        force_regenerate_key: Whether to force key regeneration, from
            ``--force-regenerate-key``.
        no_reconnect: Whether to skip the reconnect-verify step, from
            ``--no-reconnect``.
        json_output: Whether to emit JSON, from ``--json``.

    Raises:
        SettingsError: If ``--ref`` is not a valid admin reference.
        SystemExit: With the run's exit code, when it is non-zero.
    """
    ctx = ctx.with_assume_yes(yes)

    normalized_ref: str | None = None
    if ref is not None:
        normalized_ref = ref.strip()
        _validate_admin_ref(normalized_ref)

    transport_opts = TransportOptions(
        interface=connection.Transport(interface) if interface is not None else None,
        port=port,
        ble_address=ble_address,
        ble_scan=ble_scan,
        host=host,
        timeout=timeout,
        ble_scan_timeout=ble_scan_timeout,
    )
    opts = ProvisionOptions(
        dry_run=dry_run,
        enroll=enroll,
        allow_lockdown=allow_lockdown,
        allow_weak_admin_key=allow_weak_admin_key,
        force_regenerate_key=force_regenerate_key,
        rename=False,
        no_reconnect=no_reconnect,
        json_output=json_output,
        admin_ref=normalized_ref,
    )

    template = ctx.load_template()
    with ctx.open_database(for_write=not dry_run) as db:
        known_bad = weakkeys.load_known_bad_keys()

        backend = resolve_backend(ctx, transport_opts)
        with device_session(ctx, backend, no_reconnect=no_reconnect) as session:
            result = run_provision(ctx, session, db, template, opts)

        if result.persisted:
            new_ref = normalized_ref if normalized_ref is not None else result.node_id.hex
            authorized_here = tuple(result.plan.key_plan.desired_admin_key_refs)
            summaries = collect_admins(db.nodes, db.keys, template, known_bad=known_bad)
            new_summary = next((s for s in summaries if s.ref == new_ref), None)

            # Two distinct facts, each needing its own (ref, node) pair --
            # merging them into one node-id set previously lost track of
            # which ref was pending on which node (see git history for the
            # bug this replaced): `new_summary.pending_on` names nodes that
            # still need *this* bootstrap's ref; the loop below instead
            # finds other admins whose ref this newly-bootstrapped node
            # doesn't yet authorize.
            pending_pairs: set[tuple[str, str]] = {
                (new_ref, other_hex)
                for other_hex in (new_summary.pending_on if new_summary is not None else ())
            }
            for other in summaries:
                if (
                    other.ref != new_ref
                    and other.node_id is not None
                    and result.node_id.hex in other.pending_on
                ):
                    pending_pairs.add((other.ref, result.node_id.hex))

            pending_lines = tuple(
                f"pending: authorize {ref}_pub on node {node_hex} "
                "(run `mesh provision` with that device connected)"
                for ref, node_hex in sorted(pending_pairs)
            )

            if authorized_here:
                ctx.warn(f"Authorized on {result.node_id.display}: {', '.join(authorized_here)}")
            for line in pending_lines:
                ctx.warn(line)

            if json_output:
                echo_json(
                    {
                        "node_id": result.node_id.hex,
                        "ref": new_ref,
                        "authorized_on_this_node": list(authorized_here),
                        "pending": list(pending_lines),
                    }
                )

    if result.exit_code:
        raise SystemExit(result.exit_code)


@admin.command(name="import")
@click.argument("assignments", nargs=-1, required=True, metavar="REF=BASE64...")
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Overwrite an existing, differing key; skip the weak-key/duplicate refusal.",
)
@click.option(
    "--json", "json_output", is_flag=True, default=False, help="Emit JSON instead of human text."
)
@pass_cli
@handle_cli_errors
def admin_import(
    ctx: CliContext, *, assignments: tuple[str, ...], force: bool, json_output: bool
) -> None:
    """Register one or more admin public keys already held elsewhere.

    Never touches a device. Validates key length and canonical base64
    encoding, runs the weak-key audit, and refuses a duplicate public key
    already registered under a different reference, unless ``--force`` is
    passed. Registering a key also drops it from every node's
    ``unregistered_admin_keys`` (see :func:`_drop_now_registered_key`),
    which ``mesh adopt`` records for keys it could not resolve to a ref.

    Args:
        ctx: The shared CLI context, injected by :data:`~meshprovision.
            cli.common.pass_cli`.
        assignments: One or more ``REF=BASE64`` tokens.
        force: Whether to skip the differing-material and duplicate-key
            refusals, from ``--force``.
        json_output: Whether to emit JSON, from ``--json``.

    Raises:
        SettingsError: If an assignment is malformed.
        KeyMaterialError: If a base64 value is not exactly 32 bytes of
            canonical base64.
        KeyVerificationError: If a reference already exists with
            different material and ``--force`` was not passed.
        WeakKeyError: If a key fails the weak-key audit, or duplicates
            another registered key, and ``--force`` was not passed.
    """
    registered: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []

    with ctx.open_database(for_write=True) as db:
        known_bad = weakkeys.load_known_bad_keys()

        for raw in assignments:
            ref, b64 = parse_assignment(raw)
            material = crypto_keys.decode_key(b64, field="public_key")
            key_ref = schema.ref_for(ref, KeyType.ADMIN_PUBLIC)

            existing = db.keys.find(key_ref)
            if existing is not None:
                if existing.material() == material:
                    ctx.info(
                        f"{key_ref} already registered with identical material; nothing to do."
                    )
                    skipped.append({"ref": ref, "key_ref": key_ref, "reason": "identical"})
                    continue
                if not force:
                    raise KeyVerificationError(
                        f"{key_ref} already exists with different key material.",
                        key_ref=key_ref,
                        hint="Pass --force to replace it.",
                    )

            audit = weakkeys.audit_public_key(material, key_ref=key_ref, known_bad=known_bad)
            if audit.compromised and not force:
                audit.raise_if_compromised()
            elif audit.findings:
                for line in audit.summary().splitlines():
                    ctx.warn(line)

            dupes = [
                existing_ref
                for existing_ref, existing_material in db.keys.public_key_map().items()
                if existing_ref != key_ref and existing_material == material
            ]
            if dupes and not force:
                raise WeakKeyError(
                    f"That public key is already registered as {', '.join(dupes)}.",
                    reason="duplicate public key",
                    key_ref=key_ref,
                    severity=WeakKeySeverity.CRITICAL,
                    fingerprint=redact.fingerprint(material),
                    hint="Pass --force if this is a deliberate alias for the same physical node.",
                )

            db.keys.upsert(
                KeyRecord.from_material(
                    ref, KeyType.ADMIN_PUBLIC, material, created_ts=datetime.now(tz=UTC)
                )
            )
            _drop_now_registered_key(db.nodes, material)
            registered.append(
                {"ref": ref, "key_ref": key_ref, "fingerprint": redact.fingerprint(material)}
            )

        db.db.save()

    ctx.success(f"Registered {len(registered)} admin public key(s) in {db.path}")
    for entry in registered:
        ctx.info(f"  {entry['key_ref']}  {entry['fingerprint']}")

    if json_output:
        echo_json({"registered": registered, "skipped": skipped})


@admin.command(name="list")
@click.option(
    "--json", "json_output", is_flag=True, default=False, help="Emit JSON instead of a table."
)
@pass_cli
@handle_cli_errors
def admin_list(ctx: CliContext, *, json_output: bool) -> None:
    """List configured admins, key custody, weak-key audits, and pending cross-authorizations.

    Args:
        ctx: The shared CLI context, injected by :data:`~meshprovision.
            cli.common.pass_cli`.
        json_output: Whether to emit JSON, from ``--json``.

    Raises:
        SystemExit: With :attr:`~meshprovision.errors.ExitCode.CONFIG`
            when a template-listed admin is missing from the ``Keys``
            sheet.
    """
    with ctx.open_database() as db:
        template = ctx.load_template()
        known_bad = weakkeys.load_known_bad_keys()
        summaries = collect_admins(db.nodes, db.keys, template, known_bad=known_bad)

    if json_output:
        echo_json({"admins": [s.to_json_dict() for s in summaries]})
    else:
        table = build_admin_table(summaries)
        ctx.err.print(table, markup=False, highlight=False)

    if any(not summary.present for summary in summaries if summary.in_template):
        ctx.error("One or more template admin_nodes are missing from the Keys sheet.")
        raise SystemExit(int(ExitCode.CONFIG))
