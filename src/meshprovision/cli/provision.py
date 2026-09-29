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

from meshprovision.cli.common import (
    CONTEXT_SETTINGS,
    MeshCommand,
    echo_json,
    handle_cli_errors,
    pass_cli,
)
from meshprovision.cli.progress import heartbeat
from meshprovision.crypto import keys as crypto_keys
from meshprovision.crypto.redact import SecretBytes, fingerprint
from meshprovision.db import pending_keys, schema
from meshprovision.db.keys import KeyRecord
from meshprovision.db.schema import KeyOrigin, KeyType, ManagementMode
from meshprovision.errors import (
    AdminKeyRotationRefusedError,
    DeviceNotFoundError,
    ExitCode,
    KeyMaterialError,
    NodeArchivedError,
    NodeNotEnrolledError,
    PlanConflictError,
)
from meshprovision.nodeid import NodeId
from meshprovision.provisioning import apply, connection, detect, discovery, plan_render, repair
from meshprovision.provisioning import plan as plan_mod
from meshprovision.provisioning.key_registry import adopt_canonical_ref
from meshprovision.provisioning.pipeline import (
    alias_would_rotate_admin_key,
    allocate_names,
    audit_live_admin_keys,
    audit_node_key,
    is_host_generated_key,
    match_admin_key_refs,
    node_key_admin_refs,
    resolve_admin_keys,
    resolve_removed_admin_refs,
)
from meshprovision.provisioning.plan_admin_keys import KeyPlan

if TYPE_CHECKING:
    from pathlib import Path

    from meshtastic.mesh_interface import MeshInterface

    from meshprovision.cli.common import CliContext, DbSession
    from meshprovision.config.template import TemplateConfig

__all__ = [
    "ProvisionOptions",
    "ProvisionResult",
    "TransportOptions",
    "connected_with_progress",
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


def _backend_timeout(backend: connection.ConnectionBackend) -> float:
    """Best-effort connect timeout for a backend, for heartbeat display only.

    Every concrete backend (:class:`~meshprovision.provisioning.
    connection.SerialBackend`/``BLEBackend``/``TCPBackend``) carries its
    own ``timeout`` field, but :class:`~meshprovision.provisioning.
    connection.ConnectionBackend` is a bare structural ``Protocol`` with
    no such member, so a test double need not declare one. Falls back to
    :data:`~meshprovision.provisioning.connection.DEFAULT_CONNECT_TIMEOUT`
    -- this value is purely cosmetic (the heartbeat's "``/ Ns``" label);
    it never enforces anything itself.

    Args:
        backend: The backend about to be connected.

    Returns:
        ``backend.timeout`` if present, else the default connect timeout.
    """
    return float(getattr(backend, "timeout", connection.DEFAULT_CONNECT_TIMEOUT))


def _discover_ble_devices_with_progress(
    ctx: CliContext, *, timeout: float
) -> tuple[discovery.BleDeviceInfo, ...]:
    """Scan for BLE devices with a heartbeat ticking through the wait.

    Args:
        ctx: The shared CLI context.
        timeout: The scan duration, in seconds (``--ble-scan-timeout``).

    Returns:
        The discovered devices, per
        :func:`~meshprovision.provisioning.discovery.discover_ble_devices`.
    """
    with heartbeat(ctx, "scanning", timeout=timeout):
        return discovery.discover_ble_devices(timeout=timeout)


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
        ble_devices = _discover_ble_devices_with_progress(ctx, timeout=opts.ble_scan_timeout)
        return connection.select_backend(
            request, connection.DiscoveryResult(ble_devices=ble_devices), chooser=ctx.chooser
        )

    if opts.interface == "tcp":
        return connection.select_backend(request, connection.DiscoveryResult(), chooser=ctx.chooser)

    if opts.ble_scan:
        ctx.info("Scanning for BLE devices...")
        ble_devices = _discover_ble_devices_with_progress(ctx, timeout=opts.ble_scan_timeout)
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
        ble_devices = _discover_ble_devices_with_progress(ctx, timeout=opts.ble_scan_timeout)
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
    with heartbeat(ctx, "connecting", timeout=_backend_timeout(backend)):
        session.open()
    ctx.info("Connected.")
    try:
        if no_reconnect:
            yield apply.InPlaceSession(session.interface)
        else:
            yield session
    finally:
        ctx.info("Disconnecting...")
        session.close()


@contextlib.contextmanager
def connected_with_progress(
    ctx: CliContext, backend: connection.ConnectionBackend
) -> Iterator[MeshInterface]:
    """Connect once, with progress output, and always close on exit.

    The read-only sibling of :func:`device_session`: like
    :func:`meshprovision.provisioning.connection.connected`, but prints a
    "Connecting over ..." line and ticks a :func:`~meshprovision.cli.
    progress.heartbeat` while the (potentially multi-minute, entirely
    silent) ``backend.connect()`` call is in flight. Used by ``mesh
    adopt``, which -- unlike :func:`device_session` -- must never open a
    :class:`~meshprovision.provisioning.apply.ReconnectingSession`: it is
    strictly read-only against the device.

    Args:
        ctx: The shared CLI context, used to print progress.
        backend: The resolved connection backend to open.

    Yields:
        The connected interface.

    Raises:
        ConnectionFailedError: If the connection attempt fails.
    """
    ctx.info(f"Connecting over {backend.describe()}...")
    with heartbeat(ctx, "connecting", timeout=_backend_timeout(backend)):
        iface = backend.connect()
    ctx.info("Connected. Reading live config...")
    try:
        yield iface
    finally:
        ctx.info("Disconnecting...")
        connection.close_interface(iface)


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


def _select_keypair(
    change_plan: plan_mod.ChangePlan, live: detect.LiveConfig
) -> crypto_keys.KeyPair | None:
    """Choose the keypair (if any) to apply for the node's key plan.

    Args:
        change_plan: The plan being applied.
        live: The device's live-read configuration, consulted when the
            plan adopts the device's own already-existing keypair.

    Returns:
        A freshly generated keypair for ``regenerate``, the device's own
        keypair for ``adopt_device_key``, or ``None`` when the key plan
        changes nothing.

    Raises:
        PlanConflictError: If the plan wants to adopt the device's key but
            the device reported no key material.
    """
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
    return keypair


def _node_key_origin(key_plan: KeyPlan, *, pending_recovered: bool) -> KeyOrigin:
    """Decide a node's own keypair's origin for ``persist_result``/the admin alias.

    Args:
        key_plan: The plan's key decisions.
        pending_recovered: Whether this run recovered a pending key
            regeneration -- fed by
            :attr:`~meshprovision.provisioning.plan_types.PlanInputs.pending_keypair_recovered`
            via the plan (see :mod:`meshprovision.db.pending_keys`).

    Returns:
        :attr:`~meshprovision.db.schema.KeyOrigin.GENERATED` when this
        host minted the key (``key_plan.regenerate``) or this run
        recovered a pending regeneration; otherwise
        :attr:`~meshprovision.db.schema.KeyOrigin.CAPTURED` (the
        ``key_plan.adopt_device_key`` case -- the key was read from the
        device, never generated by this host).
    """
    if key_plan.regenerate or pending_recovered:
        return KeyOrigin.GENERATED
    return KeyOrigin.CAPTURED


def _register_admin_alias(
    ctx: CliContext,
    db: DbSession,
    *,
    admin_ref: str,
    node_id: NodeId,
    keypair: crypto_keys.KeyPair | None,
    node_origin: KeyOrigin,
) -> None:
    """Additionally file a node's keys under an admin alias reference.

    Used by ``mesh admin bootstrap --ref <alias>``: whatever material was
    just written for the node itself (or, when the key plan changed
    nothing, whatever material the database already holds for it) is
    copied under ``admin_ref`` too, and any stale ``observed-*`` row
    holding the same material is collapsed onto it.

    The alias rows' origin follows the material's own provenance, not a
    fixed value: when ``keypair is not None``, the same material is also
    being written to the node's own ``<node_id>_pub``/``_priv`` rows this
    run (via ``persist_result``), so the alias gets that same
    ``node_origin`` -- labeling it GENERATED only when this run actually
    generated the key, never for adopted (#7449) or otherwise-captured
    material. When ``keypair is None``, the key plan changed nothing and
    the material comes from whatever the database already holds for the
    node -- so the alias copies the existing ``<node_id>_pub`` row's own
    recorded origin via :meth:`~meshprovision.db.keys.KeyRecord.with_origin`,
    rather than guessing or reusing ``node_origin`` (which was computed
    for a key plan that did not apply here).

    Args:
        ctx: The shared CLI context.
        db: The already-open database session.
        admin_ref: The alias reference to file the keys under.
        node_id: The node whose keys are being aliased.
        keypair: The keypair just applied to the device, or ``None`` when
            the key plan changed nothing (the database's existing rows
            are used instead).
        node_origin: The origin being recorded (or already recorded) for
            the node's own keypair this run -- see :func:`_node_key_origin`.
    """
    now = datetime.now(tz=UTC)
    public_material: bytes | None
    private_material: SecretBytes | None
    alias_origin: KeyOrigin | None
    if keypair is not None:
        public_material = keypair.public
        private_material = keypair.private
        alias_origin = node_origin
    else:
        material = db.keys.keypair_for(node_id.hex)
        public_material = material.public
        private_material = material.private
        existing_public = db.keys.find(schema.ref_for(node_id.hex, KeyType.ADMIN_PUBLIC))
        alias_origin = existing_public.origin if existing_public is not None else None

    if public_material is None:
        ctx.warn(f"No public key material available to register alias {admin_ref!r}; skipping.")
    else:
        # from_material's origin kwarg is required and non-Optional (every
        # ordinary call site knows a concrete value up front); alias_origin
        # may legitimately be None (an unknown-provenance existing row), so
        # construct with a placeholder and immediately correct it via
        # with_origin, the one greppable place that propagates "unknown".
        public_record = KeyRecord.from_material(
            admin_ref,
            KeyType.ADMIN_PUBLIC,
            public_material,
            origin=alias_origin or KeyOrigin.CAPTURED,
            created_ts=now,
        ).with_origin(alias_origin)
        db.keys.upsert(public_record)
        if private_material is not None:
            private_record = KeyRecord.from_material(
                admin_ref,
                KeyType.ADMIN_PRIVATE,
                private_material,
                origin=alias_origin or KeyOrigin.CAPTURED,
                created_ts=now,
            ).with_origin(alias_origin)
            db.keys.upsert(private_record)
        # This alias's material may already sit on some other node's
        # row under a synthetic observed-* ref an earlier mesh adopt
        # minted before this alias existed -- collapse it now, same
        # as mesh admin import does.
        adopt_canonical_ref(db.nodes, db.keys, material=public_material, canonical_owner=admin_ref)


def _capture_proven_private_key(
    ctx: CliContext,
    db: DbSession,
    *,
    node_id: NodeId,
    live_private_key: SecretBytes | None,
    now: datetime,
) -> bool:
    """Record a device-proven private key into the database (CC-D1 Option A).

    Completes the out-of-band admin-key-rotation flow (``mesh admin import
    --overwrite``, batches #27-#30): that command only ever writes the new
    ``<hex>_pub`` row, so nothing records the device's matching private key
    until this runs on a later ``mesh provision``. It is not admin-specific
    -- it applies to any node's own ``<hex>_pub``/``_priv`` pair, matching
    what ``mesh provision``/``mesh adopt`` already record for every other
    captured key.

    "Proves" means the live-reported private key derives the database's
    recorded public key (:func:`~meshprovision.crypto.keys.public_key_matches`)
    -- only a party that already holds the matching private key can satisfy
    this, and the public key itself was set by a prior, separately-trusted
    step (an out-of-band import, or an earlier ``persist_result`` write).

    Args:
        ctx: The shared CLI context, for the info line.
        db: The already-open database session. Writes land in the
            in-memory session only; the caller must save.
        node_id: The node whose own ``<hex>_pub``/``_priv`` pair to check.
        live_private_key: The device's live-reported private key, or
            ``None`` when the device reported none.
        now: Timestamp to record on any row written.

    Returns:
        Whether any row was written (the caller must persist).
    """
    if live_private_key is None:
        return False
    pub_record = db.keys.find(schema.ref_for(node_id.hex, KeyType.ADMIN_PUBLIC))
    if pub_record is None:
        return False
    try:
        pub_material = pub_record.material()
        proven = crypto_keys.public_key_matches(live_private_key, pub_material)
    except KeyMaterialError:
        return False
    if not proven:
        return False

    wrote = False
    if not db.keys.has_private(node_id.hex):
        db.keys.upsert(
            KeyRecord.from_material(
                node_id.hex,
                KeyType.ADMIN_PRIVATE,
                live_private_key,
                origin=KeyOrigin.CAPTURED,
                created_ts=now,
            )
        )
        ctx.info(
            f"Recorded the device's private key for {node_id.display} "
            "(proof of possession of the recorded public key)."
        )
        wrote = True

    # Also fill any OTHER existing reference (an admin alias) holding the
    # same proven public material whose own private row is missing or
    # stale -- but never create a new alias private row that didn't
    # already exist (CC-D1 Option A / CONSISTENCY-CHECK.md #5.2).
    for alias_pub in db.keys.of_type(KeyType.ADMIN_PUBLIC):
        alias_ref = alias_pub.owner_node_id
        if alias_ref == node_id.hex or db.keys.has_private(alias_ref):
            continue
        try:
            if alias_pub.material() != pub_material:
                continue
        except KeyMaterialError:
            continue
        if db.keys.find(schema.ref_for(alias_ref, KeyType.ADMIN_PRIVATE)) is None:
            continue
        db.keys.upsert(
            KeyRecord.from_material(
                alias_ref,
                KeyType.ADMIN_PRIVATE,
                live_private_key,
                origin=KeyOrigin.CAPTURED,
                created_ts=now,
            )
        )
        ctx.info(f"Filled the stale private key recorded for alias {alias_ref!r}.")
        wrote = True

    return wrote


def _apply_and_persist(
    ctx: CliContext,
    db: DbSession,
    session: apply.DeviceSession,
    *,
    change_plan: plan_mod.ChangePlan,
    keypair: crypto_keys.KeyPair | None,
    live: detect.LiveConfig,
    opts: ProvisionOptions,
    pending_keypair_recovered: bool = False,
) -> tuple[apply.ApplyOutcome, bool]:
    """Apply a change plan to the device and persist the result to the database.

    Args:
        ctx: The shared CLI context.
        db: The already-open database session.
        session: The already-open device session.
        change_plan: The plan to apply.
        keypair: The keypair selected by :func:`_select_keypair`.
        live: The device's live-read configuration, consulted by
            :func:`_capture_proven_private_key` for the device's live
            private key -- read before this apply, but unchanged by it
            whenever ``keypair`` is ``None``, the case that matters.
        opts: The operator's provisioning flags.
        pending_keypair_recovered: Whether this run is recovering a
            pending keypair from an earlier interrupted regenerate (see
            :mod:`meshprovision.db.pending_keys`), fed through from
            :func:`run_provision`'s
            :attr:`~meshprovision.provisioning.plan_types.PlanInputs.pending_keypair_recovered`.

    Returns:
        The apply outcome, and whether the database was updated.
    """
    # A write-ahead pending-keypair file was written for this node (by
    # run_provision, before any device write) exactly when this run
    # generates a fresh keypair -- never for adopt_device_key/no-op key
    # plans, and never for a pending-keypair recovery itself (that run
    # reuses an *existing* pending file rather than writing a new one).
    wrote_pending = keypair is not None and change_plan.key_plan.regenerate
    pending_path = pending_keys.pending_key_path(db.path, change_plan.node_id)

    try:
        outcome = apply.apply_plan(
            change_plan,
            session,
            keypair=keypair,
            dry_run=False,
            on_reconnect=lambda: ctx.info(
                "Waiting for the device to reboot; do not unplug or swap it..."
            ),
        )
        for line in outcome.describe():
            ctx.info(line)
        if outcome.public_key_fingerprint is not None:
            ctx.info(f"Device public key: {outcome.public_key_fingerprint}")

        node_origin = _node_key_origin(
            change_plan.key_plan, pending_recovered=pending_keypair_recovered
        )

        if (
            opts.admin_ref is not None
            and opts.admin_ref != change_plan.node_id.hex
            and outcome.may_update_database
        ):
            _register_admin_alias(
                ctx,
                db,
                admin_ref=opts.admin_ref,
                node_id=change_plan.node_id,
                keypair=keypair,
                node_origin=node_origin,
            )

        now = datetime.now(tz=UTC)
        persisted = apply.persist_result(
            outcome,
            nodes=db.nodes,
            keys=db.keys,
            keypair=keypair,
            origin=node_origin,
            admin_key_refs=change_plan.key_plan.desired_admin_key_refs,
            now=now,
        )
    except BaseException:
        # The outcome is unknown here (Ctrl-C, or any other exception --
        # including persist_result's own AtomicWriteError, raised after the
        # device write was already confirmed): keep the pending file and
        # tell the operator it is there, unconditionally.
        if wrote_pending:
            ctx.error(
                f"The new keypair was saved to {pending_path} before the device write; "
                "the next `mesh provision` of this node recovers it automatically."
            )
        raise

    if persisted:
        ctx.success(f"Database updated: {db.path}")
        # The database and the device are now known to agree: any pending
        # keypair recorded for this node -- from this run or an earlier
        # interrupted one -- is provably no longer needed.
        pending_keys.clear_pending(db.path, change_plan.node_id)
        if _capture_proven_private_key(
            ctx,
            db,
            node_id=change_plan.node_id,
            live_private_key=live.security.private_key,
            now=now,
        ):
            db.db.save()
    else:
        if change_plan.key_plan.regenerate and not outcome.security_attempted:
            # Hygiene: the freshly generated key never reached the device
            # (the run stopped before the security section was even
            # attempted), so the pending file describes a key that was
            # never sent -- nothing to recover from it.
            pending_keys.clear_pending(db.path, change_plan.node_id)
        ctx.error("Node is in an UNCERTAIN state; the database was NOT updated.")
        for failure in outcome.failures():
            label = f"{failure.section}.{failure.field}" if failure.field else failure.section
            line = f"{label}: {failure.status.value}"
            if failure.message:
                line = f"{line} -- {failure.message}"
            ctx.error(line)

        if any(
            failure.message.startswith("reconnected to a different node")
            for failure in outcome.failures()
        ):
            ctx.error(
                "Stopped: the device that answered after the reboot is not "
                f"{change_plan.node_id.display}. Check which device is connected before "
                "re-running; nothing further was written to the other device."
            )

        not_written = [r.section for r in outcome.results if r.status is apply.WriteStatus.SKIPPED]
        if not_written:
            ctx.error(f"Not written (stopped after the failure above): {', '.join(not_written)}")
        if "security" in not_written:
            security_change = next(
                (c for c in change_plan.sections if c.section == "security"), None
            )
            sets_is_managed = security_change is not None and any(
                fc.field == "is_managed" and fc.desired is True for fc in security_change.changes
            )
            if sets_is_managed:
                ctx.info(
                    "The security section was not written: the node was not locked, "
                    "and its keys and admin keys are unchanged."
                )
            else:
                ctx.info(
                    "The security section was not written: its keys and admin keys are unchanged."
                )

        if wrote_pending:
            if outcome.security_attempted:
                ctx.error(
                    f"The new keypair was saved to {pending_path} before the device write; "
                    "the next `mesh provision` of this node recovers it automatically."
                )
            else:
                ctx.error("The new keypair was never sent to the device; nothing to recover.")

    return outcome, persisted


_ADMIN_KEY_ROTATION_DOC_HINT: Final[str] = (
    "meshprovision has no in-tool way to rotate an admin node's key. See the \"Rotating an "
    "admin node's key\" section of docs/security.md for the out-of-band procedure."
)


def _finalize_admin_key_rotation_error(
    exc: AdminKeyRotationRefusedError, live: detect.LiveConfig, *, pending_path: Path | None = None
) -> AdminKeyRotationRefusedError:
    """Attach the operator-facing hint to an admin-key-rotation refusal.

    :mod:`meshprovision.provisioning.plan` cannot import
    :mod:`meshprovision.crypto` (see its module docstring: "digests are
    the caller's job"), so it raises :class:`AdminKeyRotationRefusedError`
    with no hint at all. This is the one place that both catches the pure
    layer's refusal and has ``live`` (and a crypto import) in scope to
    compute the redacted fingerprint the operator needs to verify the
    device by hand -- never the raw base64 key.

    Args:
        exc: The refusal :func:`~meshprovision.provisioning.plan.build_plan`
            raised, with no hint set.
        live: The device's normalized live configuration, already read by
            the caller.
        pending_path: This node's pending-keypair sidecar path (see
            :mod:`meshprovision.db.pending_keys`), consulted for the
            ``"pending_key_recovered"`` reason -- a node that became
            admin-bearing between an interrupted run and its recovery.

    Returns:
        A new :class:`AdminKeyRotationRefusedError` carrying the same
        ``reason``/``admin_refs`` plus a filled-in ``hint`` and, for the
        ``"adopt"`` reason, ``reported_fingerprint``.
    """
    if exc.reason == "adopt":
        live_public = live.security.public_key
        reported_fingerprint = fingerprint(live_public) if live_public is not None else "<unknown>"
        hint = (
            f"The connected device reports a different key (fingerprint "
            f"{reported_fingerprint}) than the one recorded for this admin node. It is "
            "either a different device claiming its node id, or a genuine key loss "
            "(firmware #7449). Verify the physical device, and compare the fingerprint "
            "with the one the device itself shows. If it is genuine, register its key "
            f"with `mesh admin import --overwrite {live.node_id.hex}=<public key>` and "
            "re-run `mesh provision`."
        )
        others = ", ".join(
            ref
            for ref in exc.admin_refs
            if ref != schema.ref_for(live.node_id.hex, KeyType.ADMIN_PUBLIC)
        )
        if others:
            hint = f"{hint} Also re-import: {others}."
    elif "CVE-2025-52464" in exc.reason:
        reported_fingerprint = None
        hint = (
            "Upgrade the node's firmware to >= 2.6.11 and re-run, or follow the rotation "
            'procedure in the "Rotating an admin node\'s key" section of docs/security.md.'
        )
    elif exc.reason == "alias":
        reported_fingerprint = None
        ref = exc.admin_refs[0].removesuffix("_pub") if exc.admin_refs else "<ref>"
        hint = (
            f"{ref!r} already names a different admin key. meshprovision does not re-point "
            f"an admin ref to a new device. Bootstrap this node under a new ref "
            f"(`--ref <NEW>`), add it to `admin_nodes`, and retire {ref!r} per "
            'docs/security.md -> "Rotating an admin node\'s key". Or, if '
            f"{ref!r} must name this device's key, verify it and use "
            "`mesh admin import --overwrite`."
        )
    elif exc.reason == "pending_key_recovered":
        # Edge case: this node became admin-bearing between an earlier
        # interrupted regenerate and this run's recovery of its pending
        # keypair. The device's key genuinely matches the pending file --
        # this is not a #7449/impostor situation -- but S1 still refuses,
        # since the key is about to be (re)recorded on an admin-bearing
        # node with no operator-verified out-of-band step.
        reported_fingerprint = None
        hint = (
            "The connected device's key matches a keypair saved locally by an earlier "
            f"interrupted `mesh provision` run (at {pending_path}), but this node now backs "
            f"authorized admin key(s): {', '.join(exc.admin_refs)}. It was not recorded. "
            f"{_ADMIN_KEY_ROTATION_DOC_HINT}"
        )
    else:
        reported_fingerprint = None
        hint = _ADMIN_KEY_ROTATION_DOC_HINT

    return AdminKeyRotationRefusedError(
        exc.message,
        reason=exc.reason,
        admin_refs=exc.admin_refs,
        reported_fingerprint=reported_fingerprint,
        hint=hint,
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
        ctx.warn(
            f"A pending keypair from {pending_ts} for this node does not "
            f"match the device; it was not used. Kept at "
            f"{pending_keys.pending_key_path(db.path, live.node_id)}."
        )

    host_generated = is_host_generated_key(db.keys, live) or pending_matches
    node_key_compromised, node_key_reason = audit_node_key(
        live, known_bad=known_bad, host_generated=host_generated
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
    # _plan_node_keypair already only fires when the plan changes the key, so
    # this never produces a false refusal when nothing would change.
    if live.security.public_key is not None:
        public_key_map = db.keys.public_key_map()
        own_material_refs = (
            match_admin_key_refs(db_public_key, public_key_map) if db_public_key is not None else ()
        )
        identity_conflict_refs = tuple(
            ref
            for ref in match_admin_key_refs(live.security.public_key, public_key_map)
            if ref not in own_material_refs
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
    pending_path = pending_keys.pending_key_path(db.path, live.node_id)
    try:
        change_plan = plan_mod.build_plan(inputs)
    except AdminKeyRotationRefusedError as exc:
        raise _finalize_admin_key_rotation_error(exc, live, pending_path=pending_path) from exc

    if opts.admin_ref is not None and opts.admin_ref != change_plan.node_id.hex:
        existing_alias_pub = db.keys.find(schema.ref_for(opts.admin_ref, KeyType.ADMIN_PUBLIC))
        if existing_alias_pub is not None and alias_would_rotate_admin_key(
            existing_alias_public_key=existing_alias_pub.material(),
            plan_regenerates=change_plan.key_plan.regenerate,
            plan_adopts_device_key=change_plan.key_plan.adopt_device_key,
            live_public_key=live.security.public_key,
            db_public_key=db_public_key,
        ):
            raise _finalize_admin_key_rotation_error(
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

    keypair = _select_keypair(change_plan, live)

    if keypair is not None and change_plan.key_plan.regenerate:
        # Write-ahead, before any device write (the database's write lock
        # is already held): if the run never reaches persist_result --
        # UNCERTAIN outcome, Ctrl-C, or a kill -- this is the only record
        # of the key the device is about to receive. Deliberately outside
        # _apply_and_persist's own control flow, so a write-ahead failure
        # here propagates before apply.apply_plan ever runs.
        pending_keys.write_pending(db.path, change_plan.node_id, keypair, now=datetime.now(tz=UTC))

    outcome, persisted = _apply_and_persist(
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
