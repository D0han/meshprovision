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

import contextlib
import dataclasses
import logging
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final, TypeVar

import click

from meshprovision.cli.common import CONTEXT_SETTINGS, echo_json, handle_cli_errors, pass_cli
from meshprovision.crypto import keys as crypto_keys
from meshprovision.crypto import weakkeys
from meshprovision.crypto.redact import SecretBytes
from meshprovision.db.keys import KeyRecord
from meshprovision.db.schema import KeyType, ManagementMode
from meshprovision.errors import (
    DeviceNotFoundError,
    ExitCode,
    NodeNotEnrolledError,
    PlanConflictError,
)
from meshprovision.nodeid import NodeId
from meshprovision.provisioning import apply, connection, detect, discovery, repair
from meshprovision.provisioning import plan as plan_mod
from meshprovision.provisioning.pipeline import (
    allocate_names,
    audit_live_admin_keys,
    audit_node_key,
    resolve_admin_keys,
    resolve_removed_admin_refs,
)

if TYPE_CHECKING:
    from meshprovision.cli.common import CliContext, DbSession
    from meshprovision.config.template import TemplateConfig

__all__ = [
    "ProvisionOptions",
    "ProvisionResult",
    "TransportOptions",
    "device_session",
    "provision",
    "provisioning_options",
    "render_plan",
    "resolve_backend",
    "run_provision",
    "transport_options",
]

_logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


@dataclass(frozen=True, slots=True)
class TransportOptions:
    """Operator-supplied transport-selection flags, before resolution.

    Attributes:
        interface: Forces a transport (``"serial"``, ``"ble"``, or
            ``"tcp"``) when set, from ``--interface``.
        port: An explicit serial port path, from ``--port``.
        ble_address: An explicit BLE address, from ``--ble-address``.
        ble_scan: Whether to run a BLE scan before selection, from
            ``--ble-scan``.
        host: An explicit TCP host, from ``--host``.
        timeout: Connect timeout, in seconds, from ``--timeout``.
        ble_scan_timeout: BLE scan duration, in seconds, from
            ``--ble-scan-timeout``.
    """

    interface: connection.Transport | None = None
    port: str | None = None
    ble_address: str | None = None
    ble_scan: bool = False
    host: str | None = None
    timeout: int = connection.DEFAULT_CONNECT_TIMEOUT
    ble_scan_timeout: float = discovery.DEFAULT_BLE_SCAN_TIMEOUT


_TRANSPORT_OPTIONS: Final = (
    click.option(
        "--port", default=None, metavar="PATH", help="Explicit serial port, e.g. /dev/ttyUSB0."
    ),
    click.option("--ble-address", default=None, metavar="ADDR", help="Explicit BLE address."),
    click.option("--ble-scan", is_flag=True, default=False, help="Force BLE and scan for devices."),
    click.option(
        "--host", default=None, metavar="HOST[:PORT]", help="Explicit TCP host to connect to."
    ),
    click.option(
        "--interface",
        type=click.Choice([t.value for t in connection.TRANSPORTS], case_sensitive=False),
        default=None,
        help="Force a transport, turning ambiguity into a hard error.",
    ),
    click.option(
        "--timeout",
        type=click.IntRange(min=1),
        default=connection.DEFAULT_CONNECT_TIMEOUT,
        show_default=True,
        help="Connect timeout, in seconds.",
    ),
    click.option(
        "--ble-scan-timeout",
        type=click.FloatRange(min=0.1),
        default=discovery.DEFAULT_BLE_SCAN_TIMEOUT,
        show_default=True,
        help="BLE scan duration, in seconds.",
    ),
)


def transport_options(func: F) -> F:
    """Apply the seven shared transport-selection options to a command.

    Declared once and shared by ``mesh provision`` and ``mesh admin
    bootstrap``: the two commands' transport surface must not drift, and
    the option names correspond 1:1 to :class:`TransportOptions`'s fields.

    Args:
        func: The command function to decorate.

    Returns:
        ``func`` with every transport option attached, in help order.
    """
    for option in reversed(_TRANSPORT_OPTIONS):
        func = option(func)
    return func


@dataclass(frozen=True, slots=True)
class ProvisionOptions:
    """Operator-supplied provisioning flags shared by ``provision`` and ``admin bootstrap``.

    Attributes:
        dry_run: Whether to print the plan without touching the device or
            the database, from ``--dry-run``.
        allow_lockdown: Whether ``security.is_managed`` may be enabled,
            from ``--allow-lockdown``.
        allow_weak_admin_key: Whether admin keys that fail the weak-key
            audit may still be authorized, from
            ``--allow-weak-admin-key``.
        force_regenerate_key: Whether to regenerate the node keypair
            unconditionally, from ``--force-regenerate-key``.
        rename: Whether an already-provisioned node may be renamed, from
            ``--rename``.
        no_reconnect: Whether to verify writes against the in-memory
            interface only (a weaker guarantee), from ``--no-reconnect``.
        json_output: Whether to emit machine-readable JSON instead of
            human text, from ``--json``.
        admin_ref: Set only by ``mesh admin bootstrap``: the reference to
            additionally file this node's keys under.
        enroll: Whether to bring an observed node under template
            management, from --enroll.
    """

    dry_run: bool = False
    allow_lockdown: bool = False
    allow_weak_admin_key: bool = False
    force_regenerate_key: bool = False
    rename: bool = False
    no_reconnect: bool = False
    json_output: bool = False
    admin_ref: str | None = None
    enroll: bool = False


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


def resolve_backend(ctx: CliContext, opts: TransportOptions) -> connection.ConnectionBackend:
    """Resolve exactly one connection backend from transport flags.

    Discovery is owned by this function (never by
    :func:`meshprovision.provisioning.connection.select_backend`, which
    performs no I/O itself) -- that separation is an invariant the
    provisioning layer's own unit tests assert.

    Priority, matching ``--port`` > ``--ble-address``/``--ble-scan`` >
    ``--host`` > auto: any explicit target flag skips discovery entirely;
    a forced ``--interface`` runs only that transport's discovery and
    turns ambiguity into a hard error (cron-safe); ``--ble-scan`` alone
    forces BLE but keeps ambiguity interactive; full auto tries serial
    first, then offers an interactive BLE scan and a TCP host prompt when
    nothing is found (skipped entirely when non-interactive).

    Args:
        ctx: The shared CLI context (consulted for ``non_interactive``,
            ``chooser``, and interactive prompts).
        opts: The operator's transport-selection flags.

    Returns:
        The single resolved connection backend.

    Raises:
        AmbiguousDeviceError: If multiple candidates are found and cannot
            be disambiguated.
        DeviceNotFoundError: If no candidate device can be found at all.
        NonInteractiveError: If disambiguation would require a prompt but
            none is available.
        UnsupportedTransportError: If ``opts.interface`` names an
            unsupported transport, or BLE support (``bleak``) is
            unavailable.
    """
    request = connection.ConnectionRequest(
        interface=opts.interface,
        port=opts.port,
        ble_address=opts.ble_address,
        ble_scan=opts.ble_scan,
        host=opts.host,
        non_interactive=ctx.non_interactive,
        timeout=opts.timeout,
    )

    explicit_target = opts.port is not None or opts.ble_address is not None or opts.host is not None
    if explicit_target:
        return connection.select_backend(request, connection.DiscoveryResult(), chooser=ctx.chooser)

    if opts.interface == "serial":
        serial_ports = discovery.discover_serial_ports()
        return connection.select_backend(
            request, connection.DiscoveryResult(serial_ports=serial_ports), chooser=ctx.chooser
        )

    if opts.interface == "ble":
        ctx.info("Scanning for BLE devices...")
        ble_devices = discovery.discover_ble_devices(timeout=opts.ble_scan_timeout)
        return connection.select_backend(
            request, connection.DiscoveryResult(ble_devices=ble_devices), chooser=ctx.chooser
        )

    if opts.interface == "tcp":
        return connection.select_backend(request, connection.DiscoveryResult(), chooser=ctx.chooser)

    if opts.ble_scan:
        ctx.info("Scanning for BLE devices...")
        ble_devices = discovery.discover_ble_devices(timeout=opts.ble_scan_timeout)
        if not ble_devices:
            raise DeviceNotFoundError(
                "No BLE device found.",
                transport="ble",
                hint="Pass --ble-address, or --host <ip> for TCP.",
            )
        return connection.select_backend(
            request,
            connection.DiscoveryResult(serial_ports=(), ble_devices=ble_devices),
            chooser=ctx.chooser,
        )

    # Full auto: serial first.
    ports = discovery.discover_serial_ports()
    if len(ports) == 1:
        ctx.info(f"Using the only serial port found: {ports[0].summary()}")
        return connection.select_backend(
            request, connection.DiscoveryResult(serial_ports=ports), chooser=ctx.chooser
        )
    if len(ports) > 1:
        return connection.select_backend(
            request, connection.DiscoveryResult(serial_ports=ports), chooser=ctx.chooser
        )

    # No serial device at all: offer BLE, then a TCP host prompt, when interactive.
    scanned_ble: tuple[discovery.BleDeviceInfo, ...] = ()
    if not ctx.non_interactive and ctx.confirm(
        "No serial device found. Scan for BLE devices?", default=True
    ):
        ble_devices = discovery.discover_ble_devices(timeout=opts.ble_scan_timeout)
        scanned_ble = ble_devices
    if scanned_ble:
        return connection.select_backend(
            request, connection.DiscoveryResult(ble_devices=scanned_ble), chooser=ctx.chooser
        )
    if not ctx.non_interactive:
        host = ctx.prompt("TCP host to connect to (blank to give up)", default="")
        if host:
            request = dataclasses.replace(request, host=host)
            return connection.select_backend(request, connection.DiscoveryResult(), chooser=None)
    return connection.select_backend(request, connection.DiscoveryResult(), chooser=ctx.chooser)


@contextlib.contextmanager
def device_session(
    ctx: CliContext, backend: connection.ConnectionBackend, *, no_reconnect: bool = False
) -> Iterator[apply.DeviceSession]:
    """Open a device connection and yield a session :func:`apply.apply_plan` can drive.

    Args:
        ctx: The shared CLI context, used to print progress.
        backend: The resolved connection backend to open.
        no_reconnect: When ``True``, yields an
            :class:`~meshprovision.provisioning.apply.InPlaceSession`
            (weaker write-verification guarantee -- see firmware issue
            #7449) instead of a full
            :class:`~meshprovision.provisioning.apply.ReconnectingSession`.

    Yields:
        The open device session.

    Raises:
        ConnectionFailedError: If the connection attempt fails.
    """
    ctx.info(f"Connecting over {backend.describe()}...")
    if no_reconnect:
        ctx.warn(
            "--no-reconnect: writes are verified against the in-memory interface only "
            "(weaker guarantee; see firmware issue #7449)."
        )
    session = apply.ReconnectingSession(backend=backend)
    with session:
        if no_reconnect:
            yield apply.InPlaceSession(session.interface)
        else:
            yield session


def render_plan(
    ctx: CliContext,
    change_plan: plan_mod.ChangePlan,
    *,
    drifts: Sequence[repair.Drift] = (),
    json_output: bool = False,
) -> None:
    """Render a change plan (and any pre-existing drift) for the operator.

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
        echo_json(
            {
                "detection": {
                    "node_id": change_plan.node_id.hex,
                    "state": change_plan.state.value,
                    "is_new": change_plan.is_new,
                },
                "drifts": [
                    {
                        "kind": drift.kind.value,
                        "field": drift.field,
                        "recorded": drift.recorded,
                        "observed": drift.observed,
                    }
                    for drift in drifts
                ],
                "plan": change_plan.to_json_dict(),
            }
        )
        return

    if drifts:
        ctx.info("Drift detected:")
        for drift in drifts:
            ctx.info(drift.describe())

    if change_plan.is_empty:
        ctx.info("No changes needed.")
    else:
        ctx.info("Planned changes:")
        for line in change_plan.describe():
            ctx.print_out(line)

    for warning in change_plan.warnings:
        ctx.warn(warning.message)

    ctx.info(change_plan.summary())

    if change_plan.reboots_device:
        ctx.warn("Applying this plan reboots the device.")


def run_provision(
    ctx: CliContext,
    session: apply.DeviceSession,
    db: DbSession,
    template: TemplateConfig,
    opts: ProvisionOptions,
) -> ProvisionResult:
    """Run the full provisioning pipeline against an already-open device session.

    Detects the node's state, diffs any existing database record for
    drift, resolves and audits admin keys, builds the change plan, prints
    it, and -- unless ``opts.dry_run`` is set -- confirms, applies it to
    the device, optionally registers an admin alias, and persists the
    result to the database.

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
        LockdownRefusedError: If the template requests
            ``security.is_managed=true`` but the safety gates are not
            satisfied.
        NamespaceExhaustedError: If a name pattern's namespace is
            exhausted while allocating a new name.
        NodeNotEnrolledError: If the node's database record has
            ``management == ManagementMode.OBSERVED`` and ``opts.enroll``
            is not set.
        click.Abort: If the operator declines the confirmation prompt.
    """
    iface = session.interface
    live = detect.read_live_config(iface)

    record = db.nodes.find(live.node_id)
    detection = detect.classify(live, db_entry=record)
    ctx.info(detection.summary())

    if record is not None and record.management is ManagementMode.OBSERVED and not opts.enroll:
        raise NodeNotEnrolledError(
            f"Node {live.node_id.display} was recorded by `mesh adopt` and is not yet "
            "under template management.",
            node_id=live.node_id.display,
        )

    known_bad = weakkeys.load_known_bad_keys()

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
    node_key_compromised, node_key_reason = audit_node_key(live, known_bad=known_bad)

    db_public_key: bytes | None = None
    db_key_record = db.keys.find(f"{live.node_id.hex}_pub")
    if db_key_record is not None:
        db_public_key = db_key_record.material()

    desired_short, desired_long = allocate_names(
        db.nodes, template, existing=record, rename=opts.rename
    )

    ble_pin = (
        record.ble_pin.get_secret_value()
        if (record is not None and record.ble_pin is not None)
        else apply.generate_ble_pin()
    )

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
    )
    change_plan = plan_mod.build_plan(inputs)

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

    if change_plan.key_plan.regenerate:
        keypair: crypto_keys.KeyPair | None = crypto_keys.generate_keypair()
    elif change_plan.key_plan.adopt_device_key:
        # _plan_node_keypair only sets adopt_device_key once it has confirmed
        # both are present -- this guards the type, not a real code path.
        live_public = live.security.public_key
        live_private = live.security.private_key
        if live_public is None or live_private is None:  # pragma: no cover
            raise PlanConflictError(
                "Plan wants to adopt the device's key but the device reported none",
                field="security.public_key",
            )
        keypair = crypto_keys.KeyPair(private=live_private, public=live_public)
    else:
        keypair = None

    outcome = apply.apply_plan(change_plan, session, keypair=keypair, dry_run=False)
    for line in outcome.describe():
        ctx.info(line)

    if (
        opts.admin_ref is not None
        and opts.admin_ref != change_plan.node_id.hex
        and outcome.may_update_database
    ):
        now = datetime.now(tz=UTC)
        public_material: bytes | None
        private_material: SecretBytes | None
        if keypair is not None:
            public_material = keypair.public
            private_material = keypair.private
        else:
            pub_record = db.keys.find(f"{change_plan.node_id.hex}_pub")
            priv_record = db.keys.find(f"{change_plan.node_id.hex}_priv")
            public_material = pub_record.material() if pub_record is not None else None
            private_material = priv_record.secret() if priv_record is not None else None

        if public_material is None:
            ctx.warn(
                f"No public key material available to register alias {opts.admin_ref!r}; skipping."
            )
        else:
            db.keys.upsert(
                KeyRecord.from_material(
                    opts.admin_ref, KeyType.ADMIN_PUBLIC, public_material, created_ts=now
                )
            )
            if private_material is not None:
                db.keys.upsert(
                    KeyRecord.from_material(
                        opts.admin_ref, KeyType.ADMIN_PRIVATE, private_material, created_ts=now
                    )
                )

    persisted = apply.persist_result(
        outcome,
        nodes=db.nodes,
        keys=db.keys,
        keypair=keypair,
        admin_key_refs=change_plan.key_plan.desired_admin_key_refs,
        now=datetime.now(tz=UTC),
    )
    if persisted:
        ctx.success(f"Database updated: {db.path}")
    else:
        ctx.error("Node is in an UNCERTAIN state; the database was NOT updated.")
        for failure in outcome.failures():
            label = f"{failure.section}.{failure.field}" if failure.field else failure.section
            line = f"{label}: {failure.status.value}"
            if failure.message:
                line = f"{line} -- {failure.message}"
            ctx.error(line)

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


@click.command(name="provision", context_settings=CONTEXT_SETTINGS)
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
