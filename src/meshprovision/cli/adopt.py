"""``mesh adopt`` -- read-only device inventory, recorded as an observed node.

This module MUST NOT reference ``apply_plan``, ``ReconnectingSession``,
``InPlaceSession``, ``device_session``, ``writeConfig``, or ``setOwner`` --
nothing here ever writes to a **device**. It connects through
:func:`meshprovision.cli.provision.connected_with_progress`, a plain
connect/yield/close context manager (never a write-verification-oriented
session) that additionally prints progress and a heartbeat while the
connect is in flight, reads the device's live state via
:func:`meshprovision.provisioning.detect.read_live_config`, and builds an
:class:`~meshprovision.provisioning.adopt.AdoptionReport` through that
module's pure logic.

Unlike ``cli/status.py`` -- which additionally guarantees the **database**
is never touched -- this module legitimately uses ``OdsDatabase``,
``NodeRepository``, ``KeyRepository``, ``ctx.open_database``, and
``upsert``: recording what was read from the device is this command's
whole purpose. The guarantee this module keeps is narrower than
``status.py``'s: never writes to the **device**, but (unless ``--dry-run``)
does write to the database.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import click

from meshprovision.cli.common import (
    CONTEXT_SETTINGS,
    MeshCommand,
    echo_json,
    handle_cli_errors,
    pass_cli,
)
from meshprovision.cli.provision import (
    TransportOptions,
    connected_with_progress,
    resolve_backend,
    transport_options,
)
from meshprovision.crypto import keys as crypto_keys
from meshprovision.crypto import weakkeys
from meshprovision.db.keys import KeyRecord
from meshprovision.db.schema import KeyType, ManagementMode
from meshprovision.errors import AdoptionRefusedError, KeyMaterialError, NodeArchivedError
from meshprovision.provisioning import adopt as adopt_mod
from meshprovision.provisioning import connection, detect, observed_keys
from meshprovision.provisioning.key_registry import adopt_canonical_ref, register_observed_key

if TYPE_CHECKING:
    from meshprovision.cli.common import CliContext
    from meshprovision.db.nodes import NodeRepository

__all__ = ["adopt"]


def _duplicate_name_warnings(
    db_nodes: NodeRepository, *, live_node_id: str, short_name: str, long_name: str
) -> tuple[str, ...]:
    """Check a device's live names against every *other* node in the database.

    Belongs in the CLI layer rather than
    :func:`meshprovision.provisioning.adopt.build_adoption_report`, which
    only ever sees one device's live config and has no
    :class:`~meshprovision.db.nodes.NodeRepository` access. Display-only:
    never persisted onto the :class:`~meshprovision.db.nodes.NodeRecord`
    itself.

    Args:
        db_nodes: The open :class:`~meshprovision.db.nodes.NodeRepository`.
        live_node_id: The adopted device's own ``node_id`` (hex), excluded
            from the comparison so a re-adopt never flags itself.
        short_name: The device's live ``short_name``.
        long_name: The device's live ``long_name``.

    Returns:
        One warning string per colliding other node/field.
    """
    warnings: list[str] = []
    for other in db_nodes.all():
        if other.node_id == live_node_id:
            continue
        if short_name and other.short_name == short_name:
            warnings.append(f"short_name {short_name!r} is already used by node {other.node_id}.")
        if long_name and other.long_name == long_name:
            warnings.append(f"long_name {long_name!r} is already used by node {other.node_id}.")
    return tuple(warnings)


def _duplicate_admin_key_warnings(
    db_nodes: NodeRepository, *, live_node_id: str, admin_keys: tuple[adopt_mod.LiveAdminKey, ...]
) -> tuple[str, ...]:
    """Check a device's live admin keys against every *other* node's unregistered keys.

    The CVE-2025-52464 vendor key-cloning scenario this exists to catch:
    two already-deployed devices share the same admin keypair, and
    neither has ever been imported into the ``Keys`` sheet, so
    :func:`meshprovision.provisioning.pipeline.audit_node_key`'s own
    cross-fleet check (which only ever sees one device) has nothing to
    compare against. Belongs in the CLI layer, same reasoning as
    :func:`_duplicate_name_warnings`: :func:`meshprovision.provisioning.
    adopt.build_adoption_report` only ever sees one device's live config.

    Deliberately does **not** also compare against every ``other`` node's
    *registered* refs -- an earlier version did, and it was a bug, not
    an extra layer of rigor: ``admin_keys`` (via :func:`meshprovision.
    provisioning.adopt.classify_live_admin_keys`) is resolved against the
    exact same ``public_keys`` map ``other``'s registered material would
    be looked up in, so a live key that matches *any* registered material
    anywhere in the fleet has, by construction, already resolved to a
    non-``None`` :attr:`~meshprovision.provisioning.adopt.LiveAdminKey
    .preferred_ref` for *this* device too -- there is no possible input
    where that registered-material comparison could fire on a key this
    device doesn't already recognize as a known ref. In practice this
    made every legitimate ``template.admin_nodes``-shared admin key (the
    standard, intended way to authorize the same key on many nodes) trip
    a false CVE-2025-52464 alarm on nearly every adopt after the first.
    Comparing only against ``other``'s *unregistered* keys avoids this:
    that data source is node-scoped, not derived from the same global
    map, so it can genuinely differ between two devices reporting the
    same still-unimported material. The same reasoning extends to the
    second tier below, which checks ``other.authorized_admin_keys`` for
    the ``observed-*`` ref this key would resolve to: a key already
    registered under a real ref is never *also* left sitting under an
    ``observed-*`` one (:func:`~meshprovision.provisioning.key_registry.
    adopt_canonical_ref` guarantees that on every node whenever a real ref
    is created), so this tier can only ever fire on genuinely
    still-unregistered material, exactly like the first.

    Both tiers are pure lookups against already-loaded rows -- run
    *before* this adopt's own keys are registered (see ``adopt()``'s
    write phase below), so a key observed on ``other`` via an earlier
    adopt is what they compare against, never this run's own writes.

    Args:
        db_nodes: The open :class:`~meshprovision.db.nodes.NodeRepository`.
        live_node_id: The adopted device's own ``node_id`` (hex), excluded
            from the comparison so a re-adopt never flags itself.
        admin_keys: The adopted device's live admin keys.

    Returns:
        One warning string per duplicate found, in ``admin_keys``/other-node order.
    """
    warnings: list[str] = []
    for other in db_nodes.all():
        if other.node_id == live_node_id:
            continue
        other_unregistered_material = other.unregistered_admin_key_materials()
        other_authorized = frozenset(other.authorized_admin_keys)
        for key in admin_keys:
            if any(key.material == material for material in other_unregistered_material):
                warnings.append(
                    f"admin key {key.fingerprint} was also observed, unregistered, on node "
                    f"{other.node_id} during a previous adopt -- the CVE-2025-52464 vendor "
                    "key-cloning failure mode."
                )
            observed_ref = observed_keys.observed_key_ref(key.material)
            if observed_ref in other_authorized:
                warnings.append(
                    f"admin key {key.fingerprint} is also authorized, under the same "
                    f"observed ref {observed_ref!r}, on node {other.node_id} -- the "
                    "CVE-2025-52464 vendor key-cloning failure mode."
                )
    return tuple(warnings)


def _render_admin_key_lines(
    report: adopt_mod.AdoptionReport, *, show_admin_keys: bool
) -> tuple[str, ...]:
    """Render the human-mode lines describing admin keys about to be auto-registered.

    Unless ``--dry-run``, ``adopt()``'s write phase files every one of
    these keys under a synthetic ``observed-*`` ref (see
    :mod:`meshprovision.provisioning.observed_keys`) so it always resolves
    to a real ``Keys`` sheet row -- these lines describe that, and give
    the operator the ``mesh admin import`` command that renames the
    synthetic ref to a real one once the key's true owner is known.

    Args:
        report: The adoption report to render.
        show_admin_keys: Whether ``--show-admin-keys`` was passed.

    Returns:
        One line per unregistered key when ``show_admin_keys`` is set
        (or, for a key whose material is not exactly 32 bytes --
        reachable from a device reporting malformed data, ``detect.py``
        applies no length check -- a ``#``-prefixed line noting it can't
        be rendered or registered at all, rather than a crash or a
        silently wrong encoding; the report's own warnings already flag
        the malformed key separately); otherwise a single count hint
        line, or nothing when every key is already registered.
    """
    unregistered = [key for key in report.admin_keys if not key.refs]
    if not unregistered:
        return ()
    if show_admin_keys:
        lines: list[str] = []
        for key in unregistered:
            try:
                encoded = crypto_keys.encode_key(key.material)
            except KeyMaterialError:
                lines.append(
                    f"# admin key {key.fingerprint}: cannot render an import command "
                    "(malformed key material); it will not be registered either"
                )
                continue
            observed_ref = observed_keys.observed_key_ref(key.material)
            lines.append(
                f"admin key {key.fingerprint} will be filed under {observed_ref!r}; "
                f"rename it once its owner is known: mesh admin import <REF>={encoded}"
            )
        return tuple(lines)
    return (
        f"{len(unregistered)} admin key(s) will be filed under a synthetic observed-* ref "
        "in the Keys sheet; re-run with --show-admin-keys for import commands to rename them.",
    )


@click.command(name="adopt", cls=MeshCommand, context_settings=CONTEXT_SETTINGS)
@transport_options
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Print the report without writing to the database.",
)
@click.option("-y", "--yes", is_flag=True, default=False, help="Assume yes to every confirmation.")
@click.option(
    "--json", "json_output", is_flag=True, default=False, help="Emit JSON instead of human text."
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Re-adopt (demote) a node that is currently template-managed.",
)
@click.option(
    "--show-admin-keys",
    is_flag=True,
    default=False,
    help=(
        "Include paste-ready `mesh admin import` commands / raw base64 for unregistered admin keys."
    ),
)
@pass_cli
@handle_cli_errors
def adopt(
    ctx: CliContext,
    *,
    port: str | None,
    ble_address: str | None,
    ble_scan: bool,
    host: str | None,
    interface: str | None,
    timeout: int,
    ble_scan_timeout: float,
    dry_run: bool,
    yes: bool,
    json_output: bool,
    force: bool,
    show_admin_keys: bool,
) -> None:
    """Inventory an already-configured device and record it as observed.

    Connects to a device over serial, BLE, or TCP strictly read-only,
    reads its live configuration, and -- unless ``--dry-run`` -- persists
    the result in the database with ``management=observed``. Never diffs
    against or writes to the device; a later ``mesh provision --enroll``
    is required before the node is touched by template enforcement.

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
        dry_run: Whether to skip the database write, from ``--dry-run``.
        yes: Whether to assume yes to confirmations, from ``-y``/``--yes``.
        json_output: Whether to emit JSON, from ``--json``.
        force: Whether to allow re-adopting (demoting) a template-managed
            node, from ``--force``.
        show_admin_keys: Whether to print import-ready admin key material,
            from ``--show-admin-keys``.

    Raises:
        NodeArchivedError: If the node's database record was archived
            via ``mesh db forget`` -- not bypassable with ``--force``.
        AdoptionRefusedError: If the node's database record is already
            ``management=template`` and ``--force`` was not passed.
        click.Abort: If the operator declines the confirmation prompt.
    """
    ctx = ctx.with_assume_yes(yes)
    template = ctx.load_template()

    with ctx.open_database(for_write=not dry_run) as db:
        known_bad = weakkeys.load_known_bad_keys()
        transport_opts = TransportOptions(
            interface=connection.Transport(interface) if interface is not None else None,
            port=port,
            ble_address=ble_address,
            ble_scan=ble_scan,
            host=host,
            timeout=timeout,
            ble_scan_timeout=ble_scan_timeout,
        )
        backend = resolve_backend(ctx, transport_opts)

        with connected_with_progress(ctx, backend) as iface:
            live = detect.read_live_config(iface)

        existing = db.nodes.find(live.node_id)
        if existing is not None and existing.is_archived:
            raise NodeArchivedError(
                f"Node {live.node_id.display} was archived via `mesh db forget`.",
                node_id=live.node_id.display,
            )
        if existing is not None and existing.management is ManagementMode.TEMPLATE and not force:
            raise AdoptionRefusedError(
                f"Node {live.node_id.display} is template-managed; mesh adopt "
                "refuses to overwrite it.",
                node_id=live.node_id.display,
            )

        public_keys = db.keys.public_key_map()
        report = adopt_mod.build_adoption_report(
            live,
            existing=existing,
            public_keys=public_keys,
            template=template,
            known_bad=known_bad,
        )

        duplicate_warnings = _duplicate_name_warnings(
            db.nodes,
            live_node_id=live.node_id.hex,
            short_name=report.short_name,
            long_name=report.long_name,
        )
        duplicate_admin_key_warnings = _duplicate_admin_key_warnings(
            db.nodes, live_node_id=live.node_id.hex, admin_keys=report.admin_keys
        )

        if json_output:
            payload = report.to_json_dict(show_key_material=show_admin_keys)
            payload["warnings"] = [
                *report.warnings,
                *duplicate_warnings,
                *duplicate_admin_key_warnings,
            ]
            echo_json(payload)
        else:
            for line in report.describe():
                ctx.info(line)
            for warning in duplicate_warnings:
                ctx.warn(warning)
            for warning in duplicate_admin_key_warnings:
                ctx.warn(warning)
            for line in _render_admin_key_lines(report, show_admin_keys=show_admin_keys):
                ctx.info(line)

        if dry_run:
            return

        demoting = existing is not None and existing.management is ManagementMode.TEMPLATE
        if demoting:
            question = (
                f"Node {live.node_id.display} is currently template-managed; re-adopting "
                "will mark it observed, and mesh provision will not manage it again until "
                "it is re-enrolled with --enroll. Continue?"
            )
        else:
            question = f"Record {live.node_id.display}'s current state in the database?"
        if not ctx.confirm(question, default=False):
            raise click.Abort()

        now = datetime.now(tz=UTC)

        # The node's own keypair, so public_key_ref/private_key_ref
        # actually resolve (see NodeRecord.public_key_ref/private_key_ref)
        # -- mirrors what mesh provision records via KeyRecord.for_keypair,
        # public half always, private half only when the device exposes
        # it. Registered *before* the observed-admin-key loop below, so a
        # device that also lists its own key on security.adminKey
        # resolves that entry to this real ref rather than minting a
        # fresh observed one for it.
        node_public = live.security.public_key
        node_private = live.security.private_key
        if live.security.has_public_key and node_public is not None:
            if live.security.has_private_key and node_private is not None:
                pair = crypto_keys.KeyPair(private=node_private, public=node_public)
                pub_record, priv_record = KeyRecord.for_keypair(
                    live.node_id.hex, pair, created_ts=now
                )
                db.keys.upsert(pub_record)
                db.keys.upsert(priv_record)
            else:
                db.keys.upsert(
                    KeyRecord.from_material(
                        live.node_id.hex, KeyType.ADMIN_PUBLIC, node_public, created_ts=now
                    )
                )
            # Reconcile: this key may already sit on some other node's row
            # under a synthetic observed-* ref from an earlier adopt, back
            # before its real owner was known.
            adopt_canonical_ref(
                db.nodes, db.keys, material=node_public, canonical_owner=live.node_id.hex
            )

        # Every admin key the device reports that resolved to no Keys
        # sheet ref gets one now, minted content-addressed from its own
        # material (see meshprovision.provisioning.observed_keys) -- a
        # malformed-length key (detect.py applies no length check) is
        # simply skipped, same degrade-not-crash treatment as everywhere
        # else in this module; adopted_record() below then falls back to
        # recording it on unregistered_admin_keys, exactly as before.
        observed_refs: dict[bytes, str] = {}
        for key in report.admin_keys:
            if key.preferred_ref is not None:
                continue
            try:
                observed_refs[key.material] = register_observed_key(
                    db.nodes, db.keys, key.material, created_ts=now
                )
            except KeyMaterialError:
                continue

        record = adopt_mod.adopted_record(report, now=now, observed_refs=observed_refs)
        db.nodes.upsert(record)
        db.db.save()

    if not json_output:
        ctx.info(f"Recorded {live.node_id.display} as observed.")
