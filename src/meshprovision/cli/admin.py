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

from meshprovision.cli.common import (
    CONTEXT_SETTINGS,
    MeshGroup,
    echo_json,
    handle_cli_errors,
    pass_cli,
)
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
from meshprovision.db import observed_keys, schema
from meshprovision.db.keys import KeyRecord
from meshprovision.db.schema import KeyOrigin, KeyType
from meshprovision.errors import (
    ExitCode,
    KeyVerificationError,
    SettingsError,
    WeakKeyError,
    WeakKeySeverity,
)
from meshprovision.provisioning import connection
from meshprovision.provisioning.admin_custody import build_admin_table, collect_admins
from meshprovision.provisioning.key_registry import adopt_canonical_ref

if TYPE_CHECKING:
    from meshprovision.cli.common import CliContext
    from meshprovision.db.keys import KeyRepository
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
            :data:`meshprovision.db.schema.REF_PATTERN`, ends in
            ``_pub``, ``_priv``, or ``_psk`` (mirroring the template
            validator's own rule for ``admin_nodes`` entries), or starts
            with :data:`~meshprovision.db.observed_keys.
            OBSERVED_PREFIX` -- that namespace is reserved for the
            synthetic refs ``mesh adopt`` mints for a not-yet-recognized
            admin key (see :mod:`meshprovision.db.
            observed_keys`), so a human-chosen ref can never collide with
            one.
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
    if observed_keys.is_observed_owner(ref):
        raise SettingsError(
            f"Admin reference {ref!r} must not start with {observed_keys.OBSERVED_PREFIX!r}.",
            hint=(
                "That prefix is reserved for refs mesh adopt mints automatically for an "
                "unrecognized admin key. Choose a different name."
            ),
        )


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


def _warn_stale_admin_alias(
    ctx: CliContext,
    *,
    nodes: NodeRepository,
    keys: KeyRepository,
    ref: str,
    key_ref: str,
    old_material: bytes,
) -> None:
    """Warn about custody left stale by an ``admin import --overwrite``.

    Called right after ``key_ref`` has been upserted with new material,
    replacing what ``old_material`` held. Under D1=B (CONSISTENCY-CHECK.md
    Round 37 §4.4), this is the only remaining way an admin alias goes
    stale: every other stale-alias scenario is refused before any write
    (see :func:`~meshprovision.provisioning.pipeline.node_key_admin_refs`),
    but ``admin import --overwrite`` is itself the explicit, out-of-band
    recovery step, and it only ever touches ``key_ref`` -- any other ref
    still naming ``old_material``, and any device whose on-file admin key
    changed, is left for the operator to notice and act on.

    Args:
        ctx: The shared CLI context, used for ``ctx.warn``.
        nodes: The already-open node repository.
        keys: The already-open key repository, already reflecting
            ``key_ref``'s new material.
        ref: The admin reference just overwritten (as it appears in
            ``admin_nodes``, not a ``key_ref``).
        key_ref: ``key_ref``'s ``Keys`` sheet reference (``f"{ref}_pub"``).
        old_material: The raw public key material ``key_ref`` held before
            this overwrite.
    """
    stale_refs = sorted(
        other_ref
        for other_ref, other_material in keys.public_key_map().items()
        if other_ref != key_ref
        and other_material == old_material
        and not observed_keys.is_observed_ref(other_ref)
    )

    watch_refs = frozenset((key_ref, *stale_refs))
    stale_nodes = sorted(
        node.node.display
        for node in nodes.all()
        if not node.is_archived
        and any(admin_ref in node.authorized_admin_keys for admin_ref in watch_refs)
    )

    if stale_refs:
        alias_list = ", ".join(stale_refs)
        pronoun = "it" if len(stale_refs) == 1 else "them"
        verb = "holds" if len(stale_refs) == 1 else "hold"
        message = (
            f"{alias_list} still {verb} the previous key for {key_ref}. Re-import "
            f"{pronoun} too (`--overwrite --allow-alias`) or point the template at "
            f"{ref!r}."
        )
        if stale_nodes:
            message = f"{message} Then re-run `mesh provision` on: {', '.join(stale_nodes)}."
        ctx.warn(message)

    if keys.private_key_mismatch(ref):
        ctx.warn(
            f"{key_ref} was overwritten, but "
            f"{schema.ref_for(ref, KeyType.ADMIN_PRIVATE)} was not, and no longer derives "
            "it. This command never writes a private key; run `mesh provision` against "
            "that device once it can prove possession of the new public key -- it will "
            "record the matching private key automatically."
        )


@click.group(name="admin", cls=MeshGroup, context_settings=CONTEXT_SETTINGS)
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
        known_bad = ctx.known_bad_keys()

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
    "--overwrite",
    is_flag=True,
    default=False,
    help="Allow overwriting an existing ref's differing key material.",
)
@click.option(
    "--allow-alias",
    is_flag=True,
    default=False,
    help="Allow registering a key already authorized under another ref.",
)
@click.option(
    "--allow-weak",
    is_flag=True,
    default=False,
    help="Allow a key that fails the weak-key audit to be registered anyway.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Validate and report without registering anything.",
)
@click.option(
    "--json", "json_output", is_flag=True, default=False, help="Emit JSON instead of human text."
)
@pass_cli
@handle_cli_errors
def admin_import(
    ctx: CliContext,
    *,
    assignments: tuple[str, ...],
    overwrite: bool,
    allow_alias: bool,
    allow_weak: bool,
    dry_run: bool,
    json_output: bool,
) -> None:
    """Register one or more admin public keys already held elsewhere.

    Never touches a device. Validates key length and canonical base64
    encoding, runs the weak-key audit, and refuses a duplicate public key
    already registered under a different (non-``observed-*``) reference,
    unless ``--allow-alias`` is passed. Registering a key also reconciles
    it onto its real ref everywhere else in the database (see
    :func:`~meshprovision.provisioning.key_registry.adopt_canonical_ref`):
    a synthetic ``observed-*`` row ``mesh adopt`` minted for this exact
    material is deleted and every node's ``authorized_admin_keys``
    rewritten to point at the real ref instead, and any legacy
    ``unregistered_admin_keys`` entry for the same material is dropped.

    ``--overwrite``, ``--allow-alias`` and ``--allow-weak`` each gate
    exactly one refusal and are independent of one another: none of them
    implicitly grants either of the others.

    When ``--overwrite`` replaces an existing ref's material, this is the
    one remaining way an admin alias can go stale (every other case is
    refused up front -- see :func:`~meshprovision.provisioning.pipeline.
    node_key_admin_refs`): another ref may still name the old material, or
    a recorded private key may no longer derive it. See
    :func:`_warn_stale_admin_alias` -- this never blocks the overwrite,
    it only warns.

    Args:
        ctx: The shared CLI context, injected by :data:`~meshprovision.
            cli.common.pass_cli`.
        assignments: One or more ``REF=BASE64`` tokens.
        overwrite: Whether to allow replacing an existing ref's differing
            key material, from ``--overwrite``.
        allow_alias: Whether to allow registering a key already
            authorized under another (non-``observed-*``) ref, from
            ``--allow-alias``.
        allow_weak: Whether to allow a key that fails the weak-key audit
            to be registered anyway, from ``--allow-weak``. Never
            overrides an all-zero or small-order finding (see
            :data:`~meshprovision.crypto.weakkeys.NON_OVERRIDABLE_CHECKS`)
            -- those are refused regardless.
        dry_run: Whether to run every validation/audit/duplicate check
            and report the outcome without writing anything, from
            ``--dry-run``. Matches ``mesh provision``/``mesh adopt``/
            ``mesh admin bootstrap``'s existing convention -- unlike
            those commands, ``import`` previously had no way to preview
            a registration's outcome (weak-key result, duplicate
            collision, ``--overwrite``) before committing it.
        json_output: Whether to emit JSON, from ``--json``.

    Raises:
        SettingsError: If an assignment is malformed.
        KeyMaterialError: If a base64 value is not exactly 32 bytes of
            canonical base64.
        KeyVerificationError: If a reference already exists with
            different material and ``--overwrite`` was not passed.
        WeakKeyError: If a key fails the weak-key audit and
            ``--allow-weak`` was not passed, or duplicates another
            registered key and ``--allow-alias`` was not passed, or the
            audit's finding is all-zero or small-order (never overridable,
            regardless of ``--allow-weak``).
    """
    registered: list[dict[str, object]] = []
    skipped: list[dict[str, object]] = []

    with ctx.open_database(for_write=not dry_run) as db:
        known_bad = ctx.known_bad_keys()

        for raw in assignments:
            ref, b64 = parse_assignment(raw)
            material = crypto_keys.decode_key(b64, field="public_key")
            key_ref = schema.ref_for(ref, KeyType.ADMIN_PUBLIC)

            existing = db.keys.find(key_ref)
            old_material: bytes | None = None
            if existing is not None:
                if existing.material() == material:
                    ctx.info(
                        f"{key_ref} already registered with identical material; nothing to do."
                    )
                    skipped.append({"ref": ref, "key_ref": key_ref, "reason": "identical"})
                    continue
                if not overwrite:
                    raise KeyVerificationError(
                        f"{key_ref} already exists with different key material.",
                        key_ref=key_ref,
                        hint="Pass --overwrite to replace it.",
                    )
                old_material = existing.material()

            audit = weakkeys.audit_public_key(material, key_ref=key_ref, known_bad=known_bad)
            if audit.compromised and (not allow_weak or not audit.overridable):
                hint: str | None = None
                if allow_weak and not audit.overridable:
                    hint = (
                        "This key is all-zero or a degenerate small-order curve point; "
                        "no flag can override this refusal."
                    )
                audit.raise_if_compromised(hint=hint)
            elif audit.findings:
                for line in audit.summary().splitlines():
                    ctx.warn(line)

            # A duplicate under an observed-* ref is not a collision to
            # refuse -- it is exactly the reconciliation this command
            # performs (see the adopt_canonical_ref() call below), so it
            # is excluded before the refusal check, not just from its
            # message.
            dupes = [
                existing_ref
                for existing_ref, existing_material in db.keys.public_key_map().items()
                if existing_ref != key_ref
                and existing_material == material
                and not observed_keys.is_observed_ref(existing_ref)
            ]
            if dupes and not allow_alias:
                raise WeakKeyError(
                    f"That public key is already registered as {', '.join(dupes)}.",
                    reason="duplicate public key",
                    key_ref=key_ref,
                    severity=WeakKeySeverity.CRITICAL,
                    fingerprint=redact.fingerprint(material),
                    hint=(
                        "Pass --allow-alias if this is a deliberate alias for the "
                        "same physical node."
                    ),
                )

            # Upserted into the in-memory session unconditionally, even
            # under --dry-run: the dupe check above reads db.keys.public_key_map()
            # fresh each iteration, so a later assignment in the same batch
            # must see an earlier one's material to catch an intra-batch
            # duplicate the same way a real run would. Nothing persists
            # unless db.db.save() runs below, which is still dry_run-gated.
            db.keys.upsert(
                KeyRecord.from_material(
                    ref,
                    KeyType.ADMIN_PUBLIC,
                    material,
                    origin=KeyOrigin.IMPORTED,
                    created_ts=datetime.now(tz=UTC),
                )
            )
            adopt_canonical_ref(db.nodes, db.keys, material=material, canonical_owner=ref)
            if old_material is not None:
                _warn_stale_admin_alias(
                    ctx,
                    nodes=db.nodes,
                    keys=db.keys,
                    ref=ref,
                    key_ref=key_ref,
                    old_material=old_material,
                )
            registered.append(
                {"ref": ref, "key_ref": key_ref, "fingerprint": redact.fingerprint(material)}
            )

        if not dry_run:
            db.db.save()

    verb = "Would register" if dry_run else "Registered"
    ctx.success(f"{verb} {len(registered)} admin public key(s) in {db.path}")
    for entry in registered:
        ctx.info(f"  {entry['key_ref']}  {entry['fingerprint']}")

    if json_output:
        echo_json({"registered": registered, "skipped": skipped, "dry_run": dry_run})


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
        known_bad = ctx.known_bad_keys()
        summaries = collect_admins(db.nodes, db.keys, template, known_bad=known_bad)

    if json_output:
        echo_json({"admins": [s.to_json_dict() for s in summaries]})
    else:
        table = build_admin_table(summaries)
        ctx.err.print(table, markup=False, highlight=False)

    if any(not summary.present for summary in summaries if summary.in_template):
        ctx.error("One or more template admin_nodes are missing from the Keys sheet.")
        raise SystemExit(int(ExitCode.CONFIG))
