"""``mesh adopt`` -- read-only device inventory, recorded as an observed node.

This module MUST NOT reference ``apply_plan``, ``ReconnectingSession``,
``InPlaceSession``, ``device_session``, ``writeConfig``, or ``setOwner`` --
nothing here ever writes to a **device**. For a live device, it connects
through :func:`meshprovision.cli.provision.connected_with_progress`, a
plain connect/yield/close context manager (never a write-verification-
oriented session) that additionally prints progress and a heartbeat while
the connect is in flight, reads the device's live state via
:func:`meshprovision.provisioning.detect.read_live_config`, and builds an
:class:`~meshprovision.provisioning.adopt.AdoptionReport` through that
module's pure logic. With ``--from-backup``, no device is touched at
all -- the same :class:`~meshprovision.provisioning.detect.LiveConfig`
shape is built instead from an exported Meshtastic app config backup via
:func:`meshprovision.provisioning.backup.live_config_from_backup`, for a
node that cannot currently be reached.

Unlike ``cli/status.py`` -- which additionally guarantees the **live
database file** is never written to -- this module legitimately uses ``OdsDatabase``,
``NodeRepository``, ``KeyRepository``, ``ctx.open_database``, and
``upsert``: recording what was read from the device is this command's
whole purpose. The guarantee this module keeps is narrower than
``status.py``'s: never writes to the **device**, but (unless ``--dry-run``)
does write to the database.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from pathlib import Path
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
from meshprovision.datasources.loranet import LoranetSource
from meshprovision.db.keys import KeyRecord
from meshprovision.db.schema import KeyType, ManagementMode
from meshprovision.errors import (
    AdoptionRefusedError,
    DataSourceError,
    KeyMaterialError,
    NodeArchivedError,
    NodeIdentityError,
)
from meshprovision.nodeid import NodeId
from meshprovision.provisioning import adopt as adopt_mod
from meshprovision.provisioning import backup as backup_mod
from meshprovision.provisioning import connection, detect, observed_keys
from meshprovision.provisioning.key_registry import adopt_canonical_ref, register_observed_key

if TYPE_CHECKING:
    from meshprovision.cli.common import CliContext
    from meshprovision.db.keys import KeyRepository
    from meshprovision.db.nodes import NodeRepository

__all__ = ["adopt"]

_TRANSPORT_FLAG_NAMES = "--port/--ble-address/--ble-scan/--host/--interface"

_AES256_PSK_LENGTH = 32
"""The only channel-PSK byte length this project's Keys sheet can hold.

A firmware channel PSK also comes in a 0-byte (no encryption), 1-byte
("default" preset, an index into a firmware-side table, not real key
material), or 16-byte (AES128) form -- none of which fit the
:data:`~meshprovision.crypto.keys.X25519_KEY_SIZE`-shaped ``BASE64_KEY``
column every other ``Keys`` sheet row already uses.
"""


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


def _own_keypair_warnings(
    live: detect.LiveConfig, *, known_bad: frozenset[bytes]
) -> tuple[str, ...]:
    """Audit a node's own public/private keypair, when a backup reports both.

    A ``.cfg``/``.yaml`` backup is the one place ``mesh adopt`` ever sees
    a node's *private* key without touching the device (a live device
    also reports it, but ``build_adoption_report`` has never audited it --
    only the device's *admin* keys). :func:`~meshprovision.crypto.weakkeys.
    audit_keypair` covers both the structural/blocklist battery and the
    public-derived-from-private consistency check (firmware issue
    #7449) in one call.

    Args:
        live: The backup's normalized live configuration.
        known_bad: The loaded weak-key blocklist.

    Returns:
        Zero or one warning line. Silently does nothing when either key
        is absent (nothing to audit) or malformed (already surfaced
        elsewhere; :func:`~meshprovision.crypto.weakkeys.audit_keypair`
        itself would raise on a non-32-byte key, which
        :mod:`meshprovision.provisioning.detect` never guarantees).
    """
    public = live.security.public_key
    private = live.security.private_key
    if public is None or private is None:
        return ()
    try:
        audit = weakkeys.audit_keypair(
            private, public, node_id=live.node_id.display, known_bad=known_bad
        )
    except KeyMaterialError:
        return ()
    if not audit.findings:
        return ()
    return (f"the node's own keypair failed the weak-key audit: {audit.summary()}",)


def _suggest_node_ids(ctx: CliContext, long_name: str) -> tuple[NodeId, ...]:
    """Search loranet for nodes named ``long_name``, for a ``--node-id`` hint.

    loranet is the only name-searchable source (see
    :mod:`meshprovision.provisioning.backup`'s module docstring for why
    lorastats cannot be); a dead or unreachable source degrades to "no
    suggestion" with a warning, never an error -- this hint is a
    convenience on top of an already-failing resolution, not something
    worth failing harder over. Never bypasses the HTTP cache
    (``force_refresh`` is never set), so a warm cache costs zero network
    calls.

    Args:
        ctx: The shared CLI context, used to build the HTTP client and
            print the degraded-source warning.
        long_name: The backup's ``long_name`` to search for.

    Returns:
        Every matching node id, per
        :func:`meshprovision.provisioning.backup.suggest_node_ids_by_name`.
        Empty if the lookup failed or found nothing.
    """
    try:
        with ctx.http_client(require_contact=False) as client:
            observations = LoranetSource(client).fetch_all()
    except DataSourceError as exc:
        ctx.warn(f"loranet lookup for a --node-id suggestion failed, skipping: {exc.message}")
        return ()
    return backup_mod.suggest_node_ids_by_name(observations, long_name=long_name)


def resolve_node_id(
    ctx: CliContext,
    bundle: backup_mod.BackupBundle,
    *,
    node_id_opt: str | None,
    db_keys: KeyRepository,
    no_lookup: bool,
    force: bool,
) -> NodeId:
    """Resolve the authoritative node id for a ``--from-backup`` adopt.

    A backup file never asserts its own node id with any authority (a
    ``.cfg`` carries none at all; a node-db export's ``myNodeNum`` is
    exactly the kind of self-reported value a hand-edited or mismatched
    file could get wrong) -- so unlike a live device (whose id comes
    straight off the connected interface's own handshake), this
    resolution never trusts a single unconfirmed source. Precedence,
    each strictly stronger evidence than the next:

    1. ``--node-id`` -- an explicit operator assertion.
    2. A ``Keys`` sheet public-key match -- the backup's own public key
       equals an already-registered, non-``observed-*`` ``<id>_pub``
       row: a cryptographic binding to a node already in the database.
    3. A paired node-db export's ``myNodeNum``.
    4. (Advisory only, via :func:`_suggest_node_ids`) A loranet
       long-name match -- never sufficient on its own; only ever
       produces a ``--node-id`` hint on the raised error.

    Args:
        ctx: The shared CLI context.
        bundle: The merged backup bundle.
        node_id_opt: The raw ``--node-id`` value, or ``None``.
        db_keys: The open ``Keys`` sheet repository.
        no_lookup: Whether to skip the loranet long-name suggestion.
        force: Whether to proceed despite conflicting evidence, per the
            precedence order above, instead of refusing.

    Returns:
        The resolved :class:`~meshprovision.nodeid.NodeId`.

    Raises:
        NodeIdentityError: If nothing above resolves a node id, or two
            of (1)-(3) resolve to different ids and ``force`` is
            ``False``.
    """
    explicit = NodeId.parse(node_id_opt) if node_id_opt is not None else None

    pubkey_match: NodeId | None = None
    if bundle.public_key is not None:
        for ref, material in db_keys.public_key_map().items():
            if material != bundle.public_key:
                continue
            candidate = NodeId.try_parse(ref.removesuffix("_pub"))
            if candidate is not None:
                pubkey_match = candidate
                break

    nodedb_id = bundle.nodedb_entry.node_id if bundle.nodedb_entry is not None else None

    candidates: dict[str, NodeId] = {
        label: value
        for label, value in (
            ("--node-id", explicit),
            ("a registered public key", pubkey_match),
            ("the node-db export's myNodeNum", nodedb_id),
        )
        if value is not None
    }
    if len({value.num for value in candidates.values()}) > 1 and not force:
        detail = "; ".join(f"{label} says {value.display}" for label, value in candidates.items())
        raise NodeIdentityError(
            f"Conflicting node id evidence: {detail}.",
            candidates=tuple(value.display for value in candidates.values()),
            hint="Pass --force to proceed anyway (uses the highest-precedence source: "
            "--node-id, then a public-key match, then myNodeNum).",
        )

    if explicit is not None:
        return explicit
    if pubkey_match is not None:
        return pubkey_match
    if nodedb_id is not None:
        return nodedb_id

    if not no_lookup and bundle.long_name:
        suggestions = _suggest_node_ids(ctx, bundle.long_name)
        if suggestions:
            names = ", ".join(node_id.display for node_id in suggestions)
            raise NodeIdentityError(
                "Could not determine this node's id from the backup file(s), but loranet "
                f"has {len(suggestions)} node(s) named {bundle.long_name!r}: {names}.",
                candidates=tuple(node_id.display for node_id in suggestions),
                hint=(
                    f"Re-run with --node-id {suggestions[0].display} once you've confirmed "
                    "it's this node."
                ),
            )

    raise NodeIdentityError(
        "Could not determine this node's id from the backup file(s): no --node-id was given, "
        "no public key in the backup matched a node already in the database, and no paired "
        "node-db export provided myNodeNum.",
        hint="Pass --node-id explicitly, e.g. --node-id !a0cb5cc4.",
    )


def _load_backup_bundle(
    ctx: CliContext,
    paths: tuple[Path, ...],
    *,
    db_keys: KeyRepository,
    node_id_opt: str | None,
    no_lookup: bool,
    force: bool,
) -> tuple[backup_mod.BackupBundle, NodeId]:
    """Load and merge every ``--from-backup`` file, then resolve its node id.

    Args:
        ctx: The shared CLI context.
        paths: Every ``--from-backup`` path, in the order given.
        db_keys: The open ``Keys`` sheet repository.
        node_id_opt: The raw ``--node-id`` value, or ``None``.
        no_lookup: Whether to skip the loranet long-name suggestion.
        force: Whether to proceed despite conflicting node-id evidence.

    Returns:
        ``(bundle, node_id)``.

    Raises:
        click.UsageError: If more than one profile file, or more than
            one node-db file, was given.
        meshprovision.errors.BackupParseError: If a file cannot be read
            or parsed, or two backups disagree about which node they
            describe.
        NodeIdentityError: See :func:`resolve_node_id`.
    """
    profile: backup_mod.ProfileBackup | None = None
    nodedb: backup_mod.NodeDbBackup | None = None
    for path in paths:
        parsed = backup_mod.load_backup(path)
        if isinstance(parsed, backup_mod.ProfileBackup):
            if profile is not None:
                raise click.UsageError(
                    f"--from-backup was given two profile files: {profile.source} and "
                    f"{parsed.source}."
                )
            profile = parsed
        else:
            if nodedb is not None:
                raise click.UsageError(
                    f"--from-backup was given two node-db exports: {nodedb.source} and "
                    f"{parsed.source}."
                )
            nodedb = parsed

    bundle = backup_mod.merge_backups(profile=profile, nodedb=nodedb)
    node_id = resolve_node_id(
        ctx, bundle, node_id_opt=node_id_opt, db_keys=db_keys, no_lookup=no_lookup, force=force
    )
    return bundle, node_id


@click.command(name="adopt", cls=MeshCommand, context_settings=CONTEXT_SETTINGS)
@transport_options
@click.option(
    "--from-backup",
    "backup_paths",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    metavar="PATH",
    help=(
        "Adopt from an exported Meshtastic app config backup instead of a device -- "
        f"mutually exclusive with {_TRANSPORT_FLAG_NAMES}. Repeatable: pass a .cfg/.yaml "
        "profile and/or a node-db JSON export; format is auto-detected."
    ),
)
@click.option(
    "--node-id",
    "node_id_opt",
    default=None,
    metavar="ID",
    help="Authoritative node id for --from-backup (any form NodeId.parse accepts).",
)
@click.option(
    "--no-lookup",
    is_flag=True,
    default=False,
    help="With --from-backup, skip the loranet long-name lookup used to suggest --node-id.",
)
@click.option(
    "--no-channel-psk",
    is_flag=True,
    default=False,
    help="With --from-backup, do not record the channel PSK decoded from channel_url.",
)
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
    backup_paths: tuple[Path, ...],
    node_id_opt: str | None,
    no_lookup: bool,
    no_channel_psk: bool,
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

    With ``--from-backup``, no device is touched at all: the same report
    and write path is driven instead by an exported Meshtastic app config
    backup (a ``.cfg``/``.yaml`` ``DeviceProfile``, a node-db JSON export,
    or one of each -- see :mod:`meshprovision.provisioning.backup`), for
    a node the operator owns but cannot currently reach. A backup never
    asserts its own node id with authority, so one must be resolved from
    ``--node-id``, a ``Keys`` sheet public-key match, or a paired node-db
    export's ``myNodeNum`` -- see :func:`resolve_node_id`; a bare
    long-name match is only ever offered as a hint, never used to adopt.

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
        backup_paths: Backup file(s) to adopt from, from ``--from-backup``.
            Empty means adopt from a live device, as before.
        node_id_opt: The raw ``--node-id`` value, or ``None``.
        no_lookup: Whether to skip the loranet long-name suggestion, from
            ``--no-lookup``.
        no_channel_psk: Whether to skip recording a decoded channel PSK,
            from ``--no-channel-psk``.
        dry_run: Whether to skip the database write, from ``--dry-run``.
        yes: Whether to assume yes to confirmations, from ``-y``/``--yes``.
        json_output: Whether to emit JSON, from ``--json``.
        force: Whether to allow re-adopting (demoting) a template-managed
            node, and to proceed despite conflicting ``--from-backup``
            node-id evidence, from ``--force``.
        show_admin_keys: Whether to print import-ready admin key material,
            from ``--show-admin-keys``.

    Raises:
        click.UsageError: If ``--from-backup`` is combined with a
            transport flag, if ``--node-id`` is passed without
            ``--from-backup``, or if ``--from-backup`` is given more than
            one profile file or more than one node-db file.
        meshprovision.errors.BackupParseError: If a ``--from-backup`` file
            cannot be read or parsed, or two backup files disagree about
            which node they describe.
        NodeIdentityError: If ``--from-backup``'s node id cannot be
            resolved, or resolves ambiguously and ``--force`` was not
            passed. See :func:`resolve_node_id`.
        NodeArchivedError: If the node's database record was archived
            via ``mesh db forget`` -- not bypassable with ``--force``.
        AdoptionRefusedError: If the node's database record is already
            ``management=template`` and ``--force`` was not passed.
        click.Abort: If the operator declines the confirmation prompt.
    """
    transport_given = any((port, ble_address, ble_scan, host, interface))
    if backup_paths and transport_given:
        raise click.UsageError(f"--from-backup cannot be combined with {_TRANSPORT_FLAG_NAMES}.")
    if node_id_opt is not None and not backup_paths:
        raise click.UsageError("--node-id only applies together with --from-backup.")

    ctx = ctx.with_assume_yes(yes)
    template = ctx.load_template()

    with ctx.open_database(for_write=not dry_run) as db:
        known_bad = weakkeys.load_known_bad_keys()
        channel: backup_mod.ChannelInfo | None = None
        fixed_position: backup_mod.FixedPosition | None = None
        extra_warnings: tuple[str, ...] = ()

        if backup_paths:
            bundle, node_id = _load_backup_bundle(
                ctx,
                backup_paths,
                db_keys=db.keys,
                node_id_opt=node_id_opt,
                no_lookup=no_lookup,
                force=force,
            )
            live = backup_mod.live_config_from_backup(bundle, node_id=node_id)
            fixed_position = bundle.fixed_position
            extra_warnings = (*bundle.warnings, *_own_keypair_warnings(live, known_bad=known_bad))
            if not no_channel_psk and bundle.channel is not None:
                channel = bundle.channel
                if len(channel.psk) != _AES256_PSK_LENGTH:
                    extra_warnings = (
                        *extra_warnings,
                        f"channel {channel.name!r} PSK is {len(channel.psk)} byte(s), not the "
                        "32-byte AES256 form this project's Keys sheet can hold (a 1-byte PSK "
                        "is a firmware preset index, not real key material; 16 bytes is "
                        "AES128); channel_psk not recorded.",
                    )
                    channel = None
        else:
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
        if backup_paths:
            report = dataclasses.replace(
                report,
                source=f"backup: {', '.join(str(path) for path in backup_paths)}",
                gps_lat=fixed_position.latitude if fixed_position is not None else None,
                gps_lon=fixed_position.longitude if fixed_position is not None else None,
                gps_alt=fixed_position.altitude if fixed_position is not None else None,
                warnings=(*report.warnings, *extra_warnings),
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

        # A --from-backup profile's channel_url, decoded to its primary
        # channel's PSK -- only ever a 32-byte AES256 key (see the
        # channel/no-channel-psk handling above): a 1-byte "default"
        # preset or 16-byte AES128 PSK cannot round-trip through this
        # column, which was built for X25519-sized (32-byte) material.
        if channel is not None:
            db.keys.upsert(
                KeyRecord.from_material(
                    live.node_id.hex, KeyType.CHANNEL_PSK, channel.psk, created_ts=now
                )
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
