"""``mesh provision`` and the reusable provisioning pipeline.

This module owns two things: the ``provision`` click command itself, and
the CLI-shaped pipeline (transport resolution, device session management,
plan build/render, confirm, apply, persist) that
:mod:`meshprovision.cli.admin`'s ``mesh admin bootstrap`` reuses wholesale
rather than duplicating. The pipeline's pure half -- admin-key resolution,
the weak-key audits, name allocation -- lives in
:mod:`meshprovision.provisioning.pipeline`, below the CLI layer, because
none of it needs a :class:`~meshprovision.cli.common.CliContext`.

``mesh provision`` is also the drift-repair path: for an already-provisioned
node :func:`run_provision` reports drift via
:func:`meshprovision.provisioning.repair.diff_record`, then builds a single
:class:`~meshprovision.provisioning.plan.PlanInputs` and applies it the same
way it does for a fresh node. ``build_plan`` already implements the
already-provisioned defaults: with ``desired_short_name``/``desired_long_name``
left ``None`` (see :func:`meshprovision.provisioning.pipeline.allocate_names`)
the database's names win, and the
recorded BLE PIN is reused because this module passes it back in. From
:mod:`meshprovision.provisioning.repair` this module uses ``diff_record``
and ``Drift``.

Secret hygiene: nothing here ever prints/logs a BLE PIN, a base64 key, or
raw key bytes. Identification always goes through
:func:`meshprovision.crypto.redact.fingerprint` or the already-redaction-safe
``ChangePlan.describe()``/``to_json_dict()`` and ``ApplyOutcome.describe()``.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final, NamedTuple, TypeVar

import click

from meshprovision.cli.common import (
    CONTEXT_SETTINGS,
    echo_json,
    handle_cli_errors,
    pass_cli,
)
from meshprovision.cli.help_format import MeshCommand
from meshprovision.cli.provision_apply import ProvisionOptions, apply_and_persist
from meshprovision.cli.provision_keys import (
    finalize_admin_key_rotation_error,
    select_keypair,
)
from meshprovision.cli.transport import (
    TransportOptions,
    device_session,
    resolve_backend,
    transport_options,
)
from meshprovision.crypto import keys as crypto_keys
from meshprovision.db import pending_keys, schema
from meshprovision.db.schema import KeyType, ManagementMode
from meshprovision.errors import (
    AdminKeyRotationRefusedError,
    ExitCode,
    NodeArchivedError,
    NodeNotEnrolledError,
    PlanConflictError,
)
from meshprovision.nodeid import NodeId
from meshprovision.provisioning import apply, connection, detect, plan_render, repair
from meshprovision.provisioning import plan as plan_mod
from meshprovision.provisioning.pipeline import (
    alias_would_rotate_admin_key,
    allocate_names,
    audit_live_admin_keys,
    audit_node_key,
    duplicate_candidate_keys,
    is_host_generated_key,
    match_admin_key_refs,
    node_key_admin_refs,
    resolve_admin_keys,
    resolve_removed_admin_refs,
)

if TYPE_CHECKING:
    from pathlib import Path

    from meshprovision.cli.common import CliContext, DbSession
    from meshprovision.config.template import TemplateConfig

__all__ = [
    "ProvisionOptions",
    "ProvisionResult",
    "provision",
    "provisioning_options",
    "render_plan",
    "run_provision",
]

F = TypeVar("F", bound=Callable[..., Any])


_PROVISIONING_OPTIONS: Final = (
    click.option(
        "--dry-run", is_flag=True, default=False, help="Print the plan without writing anything."
    ),
    click.option(
        "-y", "--yes", is_flag=True, default=False, help="Assume yes to every confirmation."
    ),
    click.option(
        "--enroll",
        is_flag=True,
        default=False,
        help="Bring an observed (mesh adopt-recorded) node under template management.",
    ),
    click.option(
        "--allow-lockdown",
        is_flag=True,
        default=False,
        help="Explicitly authorize enabling security.is_managed when the safety gates pass.",
    ),
    click.option(
        "--allow-weak-admin-key",
        is_flag=True,
        default=False,
        help=(
            "Authorize admin keys that fail the weak-key audit. "
            "Does not relax the security.is_managed safety gate."
        ),
    ),
    click.option(
        "--force-regenerate-key",
        is_flag=True,
        default=False,
        help="Regenerate the node keypair unconditionally.",
    ),
    click.option(
        "--no-reconnect",
        is_flag=True,
        default=False,
        help="Verify writes against the in-memory interface only (weaker guarantee).",
    ),
    click.option(
        "--json",
        "json_output",
        is_flag=True,
        default=False,
        help="Emit JSON instead of human text.",
    ),
)


def provisioning_options(func: F) -> F:
    """Apply the eight shared provisioning-behavior options to a command.

    Declared once and shared by ``mesh provision`` and ``mesh admin
    bootstrap``; the option names correspond 1:1 to
    :class:`ProvisionOptions`'s fields (excluding ``admin_ref``, which
    only ``admin bootstrap`` sets, via its own ``--ref`` option).

    Args:
        func: The command function to decorate.

    Returns:
        ``func`` with every provisioning option attached, in help order.
    """
    for option in reversed(_PROVISIONING_OPTIONS):
        func = option(func)
    return func


@dataclass(frozen=True, slots=True)
class ProvisionResult:
    """The full outcome of one :func:`run_provision` call.

    Attributes:
        node_id: The provisioned node's id.
        detection: The node's classification before the plan was built.
        drifts: Drifts detected against the database, when the node was
            already provisioned.
        plan: The change plan that was built and (unless a dry run)
            applied.
        keypair: The freshly generated node keypair, when one was
            generated (``regenerate``); the device's own already-existing
            keypair, when one was adopted into the database instead
            (``adopt_device_key``); otherwise ``None``.
        outcome: The result of applying the plan to the device, or
            ``None`` for a dry run.
        persisted: Whether the database was updated.
        exit_code: The process exit code this run should produce.
    """

    node_id: NodeId
    detection: detect.Detection
    drifts: tuple[repair.Drift, ...]
    plan: plan_mod.ChangePlan
    keypair: crypto_keys.KeyPair | None
    outcome: apply.ApplyOutcome | None
    persisted: bool
    exit_code: int


def render_plan(
    ctx: CliContext,
    change_plan: plan_mod.ChangePlan,
    *,
    drifts: Sequence[repair.Drift] = (),
    json_output: bool = False,
) -> None:
    """Render a change plan (and any pre-existing drift) for the operator.

    A thin dispatcher: the actual line-building is pure and lives in
    :mod:`meshprovision.provisioning.plan_render`, so it is reusable and
    testable without a :class:`CliContext`.

    Args:
        ctx: The shared CLI context.
        change_plan: The plan to render.
        drifts: Drifts detected against the database before the plan was
            built, when the node was already provisioned.
        json_output: When ``True``, emit a single JSON document on STDOUT
            and nothing else there; otherwise render human text, mostly
            to STDERR (the change-list lines themselves go to STDOUT via
            :meth:`~meshprovision.cli.common.CliContext.print_out`, so a
            ``--dry-run`` plan stays diffable without ``--json``).
    """
    if json_output:
        echo_json(plan_render.plan_to_json_dict(change_plan, drifts=drifts))
        return

    for line in plan_render.describe_plan(change_plan, drifts=drifts):
        if line.kind is plan_render.PlanLineKind.WARNING:
            ctx.warn(line.text)
        elif line.kind is plan_render.PlanLineKind.CHANGE:
            ctx.print_out(line.text)
        else:
            ctx.info(line.text)


class _GatheredPlanInputs(NamedTuple):
    """What :func:`run_provision` needs from :func:`_gather_plan_inputs`.

    ``live``, the recorded public key and whether a pending keypair was
    recovered travel inside :attr:`inputs` (its ``live``,
    ``db_public_key`` and ``pending_keypair_recovered`` fields).
    """

    inputs: plan_mod.PlanInputs
    detection: detect.Detection
    drifts: tuple[repair.Drift, ...]
    pending_path: Path


def _gather_plan_inputs(
    ctx: CliContext,
    session: apply.DeviceSession,
    db: DbSession,
    template: TemplateConfig,
    opts: ProvisionOptions,
) -> _GatheredPlanInputs:
    """Read the device and the database, and assemble the plan's inputs.

    The first half of :func:`run_provision`: detection, the archived and
    not-enrolled refusals, drift, admin-key resolution and audits, the
    pending-keypair recovery check, name and BLE-PIN allocation, and the
    admin-key identity refs. Nothing is written anywhere.

    Args:
        ctx: The shared CLI context.
        session: The already-open device session.
        db: The already-open database session.
        template: The validated provisioning template.
        opts: The operator's provisioning flags.

    Returns:
        The plan inputs, the detection, any drift, and the path of this
        node's pending-keypair file (the recovered one when there is one).

    Raises:
        AdminKeyCapacityError: If the resolved admin-key set exceeds the
            firmware's capacity.
        NamespaceExhaustedError: If a name pattern's namespace is
            exhausted while allocating a new name.
        NodeArchivedError: If the node's database record was archived
            via ``mesh db forget``.
        NodeNotEnrolledError: If the node's database record has
            ``management == ManagementMode.OBSERVED`` and ``opts.enroll``
            is not set.
    """
    iface = session.interface
    live = detect.read_live_config(iface)

    record = db.nodes.find(live.node_id)
    detection = detect.classify(live, db_entry=record)
    ctx.info(detection.summary())

    if record is not None and record.is_archived:
        raise NodeArchivedError(
            f"Node {live.node_id.display} was archived via `mesh db forget`.",
            node_id=live.node_id.display,
        )

    if record is not None and record.management is ManagementMode.OBSERVED and not opts.enroll:
        raise NodeNotEnrolledError(
            f"Node {live.node_id.display} was recorded by `mesh adopt` and is not yet "
            "under template management.",
            node_id=live.node_id.display,
        )

    known_bad = ctx.known_bad_keys()

    rejected = audit_live_admin_keys(live, known_bad=known_bad)

    drifts: tuple[repair.Drift, ...]
    removed_admin_key_refs: tuple[str, ...]
    if record is not None:
        pubmap = db.keys.public_key_map()
        drifts = repair.diff_record(live, record, public_keys=pubmap)
        removed_admin_key_refs = resolve_removed_admin_refs(record, pubmap, rejected)
    else:
        drifts = ()
        removed_admin_key_refs = ()

    admin_keys = resolve_admin_keys(db.keys, template, known_bad=known_bad)

    db_public_key: bytes | None = None
    db_key_record = db.keys.find(schema.ref_for(live.node_id.hex, KeyType.ADMIN_PUBLIC))
    if db_key_record is not None:
        db_public_key = db_key_record.material()

    # Recovery check for a write-ahead pending keypair (batch #35, see
    # meshprovision.db.pending_keys): a prior interrupted regenerate may
    # have left a keypair on disk that the device still holds. Both halves
    # must match exactly -- the private half is what proves this is the
    # device the pending keypair was actually written to.
    pending = pending_keys.load_pending(db.path, live.node_id)
    pending_matches = (
        pending is not None
        and live.security.public_key is not None
        and live.security.private_key is not None
        and pending.matches(public=live.security.public_key, private=live.security.private_key)
    )
    if pending is not None and not pending_matches:
        # %Y-%m-%dT%H:%M:%SZ, not .isoformat(): the latter's microseconds
        # field is a bare 6-digit run indistinguishable from a BLE PIN by
        # this project's own stderr secret-hygiene check.
        pending_ts = pending.created_ts.strftime("%Y-%m-%dT%H:%M:%SZ")
        # Not "kept": a regenerate later in this run overwrites the file
        # (write_pending), and a successful persist removes it
        # (clear_pending) -- it survives only a run that does neither.
        ctx.warn(
            f"A pending keypair from {pending_ts} for this node does not "
            f"match the device; it was not used. It stays at {pending.path} only until "
            f"this run writes a new pending keypair or updates the database."
        )

    host_generated = is_host_generated_key(db.keys, live) or pending_matches
    node_key_compromised, node_key_reason = audit_node_key(
        live,
        known_bad=known_bad,
        known_public_keys=duplicate_candidate_keys(db.keys, live.node_id),
        host_generated=host_generated,
    )

    desired_short, desired_long = allocate_names(
        db.nodes, template, existing=record, rename=opts.rename
    )

    ble_pin = (
        record.ble_pin.get_secret_value()
        if (record is not None and record.ble_pin is not None)
        else apply.generate_ble_pin()
    )

    admin_refs = node_key_admin_refs(live.node_id, keys=db.keys, nodes=db.nodes, template=template)

    # Secondary check (S1 1b): the live-reported key claims material registered
    # under some OTHER ref -- not this node's own recorded identity or an alias
    # of it -- meaning the device claims to hold someone else's admin key.
    # Folded into the same node_key_admin_refs tuple: the gate in
    # plan_node_keypair already only fires when the plan changes the key, so
    # this never produces a false refusal when nothing would change.
    if live.security.public_key is not None:
        public_key_map = db.keys.public_key_map()
        own_material_refs = (
            match_admin_key_refs(db_public_key, public_key_map) if db_public_key is not None else ()
        )
        # First capture under a named --ref: the operator explicitly named this
        # alias, its recorded material is what matched (that's why it's about to
        # be "adopted"), and node_key_compromised (run earlier in
        # plan_node_keypair) already proved the device holds the matching
        # private key. Recording it as <hex>_pub rotates nothing, so this one
        # ref is exempted from the identity-conflict set. Any OTHER matching ref
        # -- including a clone of a different node's key -- still refuses.
        exempt_refs = (
            frozenset({schema.ref_for(opts.admin_ref, KeyType.ADMIN_PUBLIC)})
            if db_public_key is None and opts.admin_ref is not None
            else frozenset()
        )
        identity_conflict_refs = tuple(
            ref
            for ref in match_admin_key_refs(live.security.public_key, public_key_map)
            if ref not in own_material_refs and ref not in exempt_refs
        )
        admin_refs = tuple(sorted({*admin_refs, *identity_conflict_refs}))

    inputs = plan_mod.PlanInputs(
        live=live,
        template=template,
        db_entry=record,
        state=detection.state,
        admin_keys=admin_keys,
        rejected_admin_keys=rejected,
        removed_admin_key_refs=removed_admin_key_refs,
        desired_short_name=desired_short,
        desired_long_name=desired_long,
        ble_pin=ble_pin,
        node_key_compromised=node_key_compromised,
        node_key_reason=node_key_reason,
        db_public_key=db_public_key,
        force_regenerate_key=opts.force_regenerate_key,
        allow_lockdown=opts.allow_lockdown,
        allow_weak_admin_key=opts.allow_weak_admin_key,
        node_key_admin_refs=admin_refs,
        pending_keypair_recovered=pending_matches,
    )
    # The recovered file's own path, which may carry an older spelling of
    # the database's name (see pending_keys.load_pending).
    pending_path = pending_keys.pending_key_path(db.path, live.node_id)
    if pending is not None:
        pending_path = pending.path
    return _GatheredPlanInputs(
        inputs=inputs, detection=detection, drifts=drifts, pending_path=pending_path
    )


def run_provision(
    ctx: CliContext,
    session: apply.DeviceSession,
    db: DbSession,
    template: TemplateConfig,
    opts: ProvisionOptions,
) -> ProvisionResult:
    """Run the full provisioning pipeline against an already-open device session.

    Detects the node's state, checks for a recoverable write-ahead
    pending keypair from an earlier interrupted run (see
    :mod:`meshprovision.db.pending_keys`), diffs any existing database
    record for drift, resolves and audits admin keys, builds the change
    plan, prints it, and -- unless ``opts.dry_run`` is set -- confirms,
    writes the pending keypair ahead of any device write when regenerating,
    applies the plan to the device, optionally registers an admin alias,
    and persists the result to the database.

    Args:
        ctx: The shared CLI context.
        session: The already-open device session.
        db: The already-open database session.
        template: The validated provisioning template.
        opts: The operator's provisioning flags.

    Returns:
        The full :class:`ProvisionResult`.

    Raises:
        AdminKeyCapacityError: If the resolved admin-key set exceeds the
            firmware's capacity.
        AtomicWriteError: If a fresh keypair's write-ahead pending file
            could not be written. Raised before any device write.
        LockdownRefusedError: If the template requests
            ``security.is_managed=true`` but the safety gates are not
            satisfied.
        NamespaceExhaustedError: If a name pattern's namespace is
            exhausted while allocating a new name.
        NodeArchivedError: If the node's database record was archived
            via ``mesh db forget``.
        NodeNotEnrolledError: If the node's database record has
            ``management == ManagementMode.OBSERVED`` and ``opts.enroll``
            is not set.
        click.Abort: If the operator declines the confirmation prompt.
    """
    inputs, detection, drifts, pending_path = _gather_plan_inputs(ctx, session, db, template, opts)
    live = inputs.live
    db_public_key = inputs.db_public_key
    pending_matches = inputs.pending_keypair_recovered
    try:
        change_plan = plan_mod.build_plan(inputs)
    except AdminKeyRotationRefusedError as exc:
        raise finalize_admin_key_rotation_error(exc, live, pending_path=pending_path) from exc

    if opts.no_reconnect and change_plan.key_plan.regenerate:
        raise PlanConflictError(
            "--no-reconnect cannot verify a key regeneration: it never reconnects, so it "
            "can only compare against the in-memory interface, which cannot tell a key that "
            "genuinely persisted apart from one firmware silently discarded on reboot "
            "(firmware #7449). A FACTORY node always regenerates a key, so it can never be "
            "provisioned with --no-reconnect.",
            field="security.public_key",
            hint="Re-run without --no-reconnect.",
        )

    if opts.admin_ref is not None and opts.admin_ref != change_plan.node_id.hex:
        existing_alias_pub = db.keys.find(schema.ref_for(opts.admin_ref, KeyType.ADMIN_PUBLIC))
        if existing_alias_pub is not None and alias_would_rotate_admin_key(
            existing_alias_public_key=existing_alias_pub.material(),
            plan_regenerates=change_plan.key_plan.regenerate,
            plan_adopts_device_key=change_plan.key_plan.adopt_device_key,
            live_public_key=live.security.public_key,
            db_public_key=db_public_key,
        ):
            raise finalize_admin_key_rotation_error(
                AdminKeyRotationRefusedError(
                    f"{opts.admin_ref!r} already names a different admin key; refusing to "
                    "re-point it.",
                    reason="alias",
                    admin_refs=(schema.ref_for(opts.admin_ref, KeyType.ADMIN_PUBLIC),),
                ),
                live,
                pending_path=pending_path,
            )

    render_plan(ctx, change_plan, drifts=drifts, json_output=opts.json_output)

    if opts.dry_run:
        return ProvisionResult(
            node_id=change_plan.node_id,
            detection=detection,
            drifts=drifts,
            plan=change_plan,
            keypair=None,
            outcome=None,
            persisted=False,
            exit_code=int(ExitCode.OK),
        )

    if not change_plan.is_empty:
        if detection.state is detect.NodeState.FOREIGN:
            ctx.warn(
                "This node is not in the database and does not look factory-default; "
                "it may belong to someone else."
            )
        question = f"Apply this plan to {change_plan.node_id.display} over {session.describe()}?"
        if not ctx.confirm(question, default=False):
            raise click.Abort()

    keypair = select_keypair(change_plan, live)

    if keypair is not None and change_plan.key_plan.regenerate:
        # Write-ahead, before any device write (the database's write lock
        # is already held): if the run never reaches persist_result --
        # UNCERTAIN outcome, Ctrl-C, or a kill -- this is the only record
        # of the key the device is about to receive. Deliberately outside
        # apply_and_persist's own control flow, so a write-ahead failure
        # here propagates before apply.apply_plan ever runs.
        pending_keys.write_pending(db.path, change_plan.node_id, keypair, now=datetime.now(tz=UTC))

    outcome, persisted = apply_and_persist(
        ctx,
        db,
        session,
        change_plan=change_plan,
        keypair=keypair,
        live=live,
        opts=opts,
        pending_keypair_recovered=pending_matches,
    )

    return ProvisionResult(
        node_id=change_plan.node_id,
        detection=detection,
        drifts=drifts,
        plan=change_plan,
        keypair=keypair,
        outcome=outcome,
        persisted=persisted,
        exit_code=outcome.exit_code,
    )


@click.command(name="provision", cls=MeshCommand, context_settings=CONTEXT_SETTINGS)
@transport_options
@provisioning_options
@click.option(
    "--rename", is_flag=True, default=False, help="Allow renaming an already-provisioned node."
)
@pass_cli
@handle_cli_errors
def provision(
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
    enroll: bool,
    allow_lockdown: bool,
    allow_weak_admin_key: bool,
    force_regenerate_key: bool,
    rename: bool,
    no_reconnect: bool,
    json_output: bool,
) -> None:
    """Provision a connected Meshtastic device from the configured template.

    Connects over serial, BLE, or TCP; detects whether the device is
    factory-default, already provisioned, or foreign; builds and prints
    an exact change plan; and, unless ``--dry-run`` is passed, applies it
    to the device and records the result in the ODS database.

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
        rename: Whether renaming is allowed, from ``--rename``.
        no_reconnect: Whether to skip the reconnect-verify step, from
            ``--no-reconnect``.
        json_output: Whether to emit JSON, from ``--json``.

    Raises:
        SystemExit: With the run's exit code, when it is non-zero.
    """
    ctx = ctx.with_assume_yes(yes)
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
        rename=rename,
        no_reconnect=no_reconnect,
        json_output=json_output,
    )

    template = ctx.load_template()
    with ctx.open_database(for_write=not dry_run) as db:
        backend = resolve_backend(ctx, transport_opts)
        with device_session(ctx, backend, no_reconnect=no_reconnect) as session:
            result = run_provision(ctx, session, db, template, opts)

    if result.exit_code:
        raise SystemExit(result.exit_code)
