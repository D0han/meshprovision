"""``mesh adopt --from-backup``: load backup files and resolve which node they describe.

Split out of :mod:`meshprovision.cli.adopt`, which calls
:func:`read_backup_source` for its ``--from-backup`` branch and otherwise
handles a backup-built :class:`~meshprovision.provisioning.detect.LiveConfig`
exactly like one read from a device. A helper module, never a command:
it imports no ``cli`` command module. Like ``cli/adopt.py``, nothing here
ever talks to a device -- see ``tests/unit/test_readonly_adopt_boundary.py``.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import TYPE_CHECKING

import click

from meshprovision.datasources.loranet import LoranetSource
from meshprovision.db import schema
from meshprovision.db.schema import KeyType
from meshprovision.errors import DataSourceError, NodeIdentityError
from meshprovision.nodeid import NodeId
from meshprovision.provisioning import backup as backup_mod

if TYPE_CHECKING:
    from meshprovision.cli.common import CliContext
    from meshprovision.db.keys import KeyRepository
    from meshprovision.provisioning.detect import LiveConfig

__all__ = ["BackupSource", "read_backup_source", "resolve_node_id"]

_AES256_PSK_LENGTH = 32
"""The only channel-PSK byte length this project's Keys sheet can hold.

A firmware channel PSK also comes in a 0-byte (no encryption), 1-byte
("default" preset, an index into a firmware-side table, not real key
material), or 16-byte (AES128) form -- none of which fit the
:data:`~meshprovision.crypto.keys.X25519_KEY_SIZE`-shaped ``BASE64_KEY``
column every other ``Keys`` sheet row already uses.
"""


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
    node_id_opt: NodeId | None,
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
       equals an already-registered ``ADMIN_PUBLIC`` row whose
       ``owner_node_id`` is a *canonical* node id (per
       :func:`~meshprovision.db.schema.is_canonical_node_owner`; this
       excludes a short hex- or decimal-looking template ``admin_nodes``
       label or ``observed-*`` ref that happens to also satisfy
       :meth:`~meshprovision.nodeid.NodeId.try_parse`'s more permissive
       shortcut forms): a cryptographic binding to a node already in the
       database. When more than one distinct canonical owner's material
       matches (a cloned key), this tier is ambiguous: an explicit
       ``--node-id`` overrides it outright (it contributes nothing to
       the decision); with no ``--node-id``, it raises
       :class:`~meshprovision.errors.NodeIdentityError` naming every
       matching owner as a candidate, regardless of ``force``.
    3. A paired node-db export's ``myNodeNum``.
    4. (Advisory only, via :func:`_suggest_node_ids`) A loranet
       long-name match -- never sufficient on its own; only ever
       produces a ``--node-id`` hint on the raised error.

    Args:
        ctx: The shared CLI context.
        bundle: The merged backup bundle.
        node_id_opt: The ``--node-id`` value, already parsed by
            :func:`~meshprovision.cli.common.node_id_callback`, or ``None``.
        db_keys: The open ``Keys`` sheet repository.
        no_lookup: Whether to skip the loranet long-name suggestion.
        force: Whether to proceed despite conflicting evidence, per the
            precedence order above, instead of refusing.

    Returns:
        The resolved :class:`~meshprovision.nodeid.NodeId`.

    Raises:
        NodeIdentityError: If nothing above resolves a node id; if two
            of (1)-(3) resolve to different ids and ``force`` is
            ``False``; or if the public-key tier matches more than one
            distinct canonical owner and no ``--node-id`` was given
            (not bypassable with ``force``, since that tier's own
            evidence -- not a conflict between tiers -- is what is
            ambiguous).
    """
    explicit = node_id_opt

    pubkey_match: NodeId | None = None
    if bundle.public_key is not None:
        canonical_owners = {
            record.owner_node_id
            for record in db_keys.of_type(KeyType.ADMIN_PUBLIC)
            if record.material() == bundle.public_key
            and schema.is_canonical_node_owner(record.owner_node_id)
        }
        if len(canonical_owners) == 1:
            pubkey_match = NodeId.from_hex(next(iter(canonical_owners)))
        elif len(canonical_owners) > 1 and explicit is None:
            owners = tuple(NodeId.from_hex(owner) for owner in sorted(canonical_owners))
            names = ", ".join(node_id.display for node_id in owners)
            raise NodeIdentityError(
                f"The backup's public key matches {len(owners)} different node(s) already "
                f"registered in the database: {names}.",
                candidates=tuple(node_id.display for node_id in owners),
                hint=("This may indicate a cloned key; pass --node-id explicitly to disambiguate."),
            )
        # Else: either a unique canonical match (handled above), no match
        # at all, or more than one canonical owner alongside an explicit
        # --node-id -- in which case the explicit id wins outright and
        # this tier's ambiguous evidence contributes nothing further.

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
    node_id_opt: NodeId | None,
    no_lookup: bool,
    force: bool,
) -> tuple[backup_mod.BackupBundle, NodeId]:
    """Load and merge every ``--from-backup`` file, then resolve its node id.

    Args:
        ctx: The shared CLI context.
        paths: Every ``--from-backup`` path, in the order given.
        db_keys: The open ``Keys`` sheet repository.
        node_id_opt: The ``--node-id`` value, already parsed by
            :func:`~meshprovision.cli.common.node_id_callback`, or ``None``.
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
        NodeIdentityError: See :func:`resolve_node_id`; also if ``force``
            resolved an id other than a paired node-db export's
            ``myNodeNum`` while a paired profile carries that export's
            own public key.
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
    if (
        bundle.nodedb_entry is not None
        and bundle.nodedb_entry.node_id is not None
        and bundle.nodedb_entry.node_id != node_id
    ):
        # --force resolved a node id that disagrees with the paired node-db
        # export's own myNodeNum -- that export's entry (names, hw_model,
        # firmware_version, and critically its public key) describes
        # whichever node the phone was connected to when the export was
        # taken, which is by definition NOT node_id. Using it anyway would
        # write another node's identity -- including its public key -- onto
        # this one, and that mis-filed <node_id>_pub row would then
        # silently redirect every future backup adopt of the real key
        # owner (resolve_node_id's own public-key tier reads exactly that
        # row). Drop the mismatched entry; a paired profile's own data
        # still applies -- unless that profile carries the same public key
        # as the dropped entry. merge_backups only pairs files it found
        # consistent, and an equal key proves the profile is the export's
        # own node too, so keeping it would file that node's key (and
        # names, config and position) under node_id all the same. A
        # profile linked to the entry by names alone is kept: names
        # collide, and a name is never used to resolve a node id.
        mismatched_id = bundle.nodedb_entry.node_id.display
        if (
            profile is not None
            and profile.public_key is not None
            and profile.public_key == bundle.nodedb_entry.public_key
        ):
            raise NodeIdentityError(
                f"{profile.source} carries the same public key as the node-db export's own "
                f"node {mismatched_id} (its myNodeNum), so both backups describe "
                f"{mismatched_id}, not the resolved node id {node_id.display}.",
                candidates=(node_id.display, mismatched_id),
                hint=(
                    f"Pass only backup files that belong to {node_id.display}. If "
                    f"{node_id.display} really carries this key (for example a profile "
                    f"restored onto a second device), adopt {profile.source} alone with "
                    f"--node-id {node_id.display}."
                ),
            )
        bundle = dataclasses.replace(
            bundle,
            nodedb_entry=None,
            warnings=(
                *bundle.warnings,
                f"the paired node-db export's entry (myNodeNum {mismatched_id}) describes a "
                f"different node than the resolved id {node_id.display}; its names/hw_model/"
                "firmware_version/public_key are NOT used for this adopt.",
            ),
        )
    return bundle, node_id


@dataclasses.dataclass(frozen=True, slots=True)
class BackupSource:
    """Everything ``mesh adopt`` takes from ``--from-backup`` file(s).

    Attributes:
        live: The :class:`~meshprovision.provisioning.detect.LiveConfig`
            built from the merged backup for the resolved node id.
        fixed_position: The backup's fixed position, if it carries one.
        channel: The primary channel to record a ``<node>_psk`` row for,
            or ``None`` when ``--no-channel-psk`` was given, the backup
            has no channel, or its PSK is not the 32-byte AES256 form.
        warnings: The backup bundle's own warnings, plus the skipped-PSK
            warning when a channel PSK could not be recorded.
    """

    live: LiveConfig
    fixed_position: backup_mod.FixedPosition | None
    channel: backup_mod.ChannelInfo | None
    warnings: tuple[str, ...]


def read_backup_source(
    ctx: CliContext,
    paths: tuple[Path, ...],
    *,
    db_keys: KeyRepository,
    node_id_opt: NodeId | None,
    no_lookup: bool,
    force: bool,
    no_channel_psk: bool,
) -> BackupSource:
    """Load every ``--from-backup`` file and turn it into what ``mesh adopt`` records.

    Args:
        ctx: The shared CLI context.
        paths: Every ``--from-backup`` path, in the order given.
        db_keys: The open ``Keys`` sheet repository.
        node_id_opt: The ``--node-id`` value, already parsed by
            :func:`~meshprovision.cli.common.node_id_callback`, or ``None``.
        no_lookup: Whether to skip the loranet long-name suggestion.
        force: Whether to proceed despite conflicting node-id evidence.
        no_channel_psk: Whether to skip recording a decoded channel PSK.

    Returns:
        The resolved :class:`BackupSource`.

    Raises:
        click.UsageError: If more than one profile file, or more than
            one node-db file, was given.
        meshprovision.errors.BackupParseError: If a file cannot be read
            or parsed, or two backups disagree about which node they
            describe.
        NodeIdentityError: See :func:`resolve_node_id` and
            :func:`_load_backup_bundle`.
    """
    bundle, node_id = _load_backup_bundle(
        ctx,
        paths,
        db_keys=db_keys,
        node_id_opt=node_id_opt,
        no_lookup=no_lookup,
        force=force,
    )
    live = backup_mod.live_config_from_backup(bundle, node_id=node_id)
    warnings = bundle.warnings
    channel: backup_mod.ChannelInfo | None = None
    if not no_channel_psk and bundle.channel is not None:
        channel = bundle.channel
        if len(channel.psk) != _AES256_PSK_LENGTH:
            warnings = (
                *warnings,
                f"channel {channel.name!r} PSK is {len(channel.psk)} byte(s), not the "
                "32-byte AES256 form this project's Keys sheet can hold (a 1-byte PSK "
                "is a firmware preset index, not real key material; 16 bytes is "
                "AES128); channel_psk not recorded.",
            )
            channel = None
    return BackupSource(
        live=live, fixed_position=bundle.fixed_position, channel=channel, warnings=warnings
    )
