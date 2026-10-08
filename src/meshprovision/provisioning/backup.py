"""Parse a Meshtastic app config backup into a normalized live-config shape.

This is the file-based counterpart to :mod:`meshprovision.provisioning.detect`:
where ``detect.py`` reads a live device's protobuf state off a connected
``MeshInterface``, this module reads the same shape of protobuf state out
of a file the operator exported earlier -- typically from the Meshtastic
Android app, so a node that cannot currently be reached (deployed
remotely, lent out, on a roof) can still be recorded with ``mesh adopt
--from-backup``. See :func:`live_config_from_backup` for the bridge back
into :class:`~meshprovision.provisioning.detect.LiveConfig`.

Three file shapes are recognized, auto-detected by content
(:func:`sniff_format`), verified against ``meshtastic/Meshtastic-Android``
and the installed ``meshtastic==2.7.11`` protobufs:

- **A ``.cfg`` profile** -- Radio Config -> Backup & Restore -> Export in
  the app. A raw ``clientonly_pb2.DeviceProfile`` protobuf: names,
  ``channel_url``, the full ``LocalConfig``/``LocalModuleConfig``
  (including ``security.public_key``/``private_key``/``admin_key``), the
  BLE PIN, region, role, and an optional fixed position. Carries no node
  id, hw model, or firmware version.
- **A ``.yaml`` profile** -- ``meshtastic --export-config``'s YAML output
  (the Python CLI, not the app). Same content as a ``.cfg``, with
  ``owner``/``owner_short``/``location`` at the top level and key bytes
  prefixed ``"base64:"``.
- **A node-db JSON export** -- Settings -> Export node database in the
  app (``Meshtastic_nodedb_<SHORT>_<ts>.json``). Carries ``myNodeNum``
  and, for the node's own entry, ``id``/``hwModel``/``role``/``publicKey``
  (base64)/``metadata.firmwareVersion`` -- exactly what a ``.cfg`` is
  missing. Carries no private key, admin keys, region, or channel.

:func:`load_backup` is the only function here that touches the
filesystem; everything else is a pure ``bytes``/``str`` -> value parser,
mirroring the ``load_template``/``load_template_text`` split in
:mod:`meshprovision.config.template`. Node identity is never inferred by
this module -- :func:`live_config_from_backup` takes the resolved
``node_id`` as an explicit argument; deciding what that id *is* belongs
to the CLI layer (``mesh adopt --from-backup``), which alone has database
and network access to cross-check it.

Secret hygiene: :class:`ProfileBackup` never exposes its private key
except wrapped in :class:`~meshprovision.crypto.redact.SecretBytes`, and
its ``__repr__`` never prints raw public key or PSK bytes.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from meshtastic.protobuf import localonly_pb2

from meshprovision import enums
from meshprovision.errors import BackupParseError
from meshprovision.nodeid import NodeId
from meshprovision.provisioning import detect
from meshprovision.provisioning.backup_models import (
    BackupBundle,
    BackupFormat,
    ChannelInfo,
    FixedPosition,
    NodeDbBackup,
    NodeDbEntry,
    ProfileBackup,
)
from meshprovision.provisioning.backup_parse import (
    decode_channel_url,
    load_backup,
    parse_nodedb_json,
    parse_profile_cfg,
    parse_profile_yaml,
    sniff_format,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from meshprovision.datasources.models import NodeObservation

__all__ = [
    "BackupBundle",
    "BackupFormat",
    "ChannelInfo",
    "FixedPosition",
    "NodeDbBackup",
    "NodeDbEntry",
    "ProfileBackup",
    "decode_channel_url",
    "live_config_from_backup",
    "load_backup",
    "merge_backups",
    "parse_nodedb_json",
    "parse_profile_cfg",
    "parse_profile_yaml",
    "sniff_format",
    "suggest_node_ids_by_name",
]


def merge_backups(
    profile: ProfileBackup | None = None, nodedb: NodeDbBackup | None = None
) -> BackupBundle:
    """Merge a profile backup and/or a node-db backup into one bundle.

    Args:
        profile: A parsed ``.cfg``/``.yaml`` profile, or ``None``.
        nodedb: A parsed node-db JSON export, or ``None``.

    Returns:
        The merged :class:`BackupBundle`.

    Raises:
        BackupParseError: If both arguments are ``None``, or if both are
            supplied and disagree about which node they describe
            (conflicting non-empty ``long_name``, ``short_name``, or
            public key).
    """
    if profile is None and nodedb is None:
        raise BackupParseError("At least one backup file is required.")

    warnings: list[str] = list(profile.warnings) if profile is not None else []
    warnings.extend(nodedb.warnings if nodedb is not None else ())
    entry = nodedb.own_entry() if nodedb is not None else None
    if nodedb is not None and entry is None:
        warnings.append(
            f"{nodedb.source}: myNodeNum ({nodedb.my_node_num!r}) was not found among its "
            "own node entries; hw_model, firmware_version, and role from this file could "
            "not be recovered."
        )

    nodedb_source = nodedb.source if nodedb is not None else ""
    if profile is not None and entry is not None:
        # A matching public key is a cryptographic binding to the same
        # node -- strictly stronger evidence than either name. The two
        # backups are commonly snapshots taken at different times (a
        # .cfg exported months ago, a node-db export taken today), so
        # the single most likely cause of a name disagreement between
        # them, once the keys agree, is that the operator renamed the
        # node in between -- not that they describe different nodes.
        # Downgrade to a warning in that case rather than hard-refusing
        # the operator's own file history; keep the hard refusal when
        # identity is not otherwise corroborated.
        keys_corroborate_identity = (
            profile.public_key is not None
            and entry.public_key is not None
            and profile.public_key == entry.public_key
        )
        if profile.long_name and entry.long_name and profile.long_name != entry.long_name:
            if keys_corroborate_identity:
                warnings.append(
                    f"{profile.source} says long_name {profile.long_name!r}, {nodedb_source} "
                    f"says {entry.long_name!r} -- both carry the same public key, so this "
                    "looks like a rename between exports rather than different nodes; using "
                    f"{profile.source}'s name (the profile always takes precedence)."
                )
            else:
                raise BackupParseError(
                    f"Conflicting long_name between backups: {profile.source} says "
                    f"{profile.long_name!r}, {nodedb_source} says {entry.long_name!r}. These "
                    "backups may not be for the same node.",
                    source=nodedb_source,
                )
        if profile.short_name and entry.short_name and profile.short_name != entry.short_name:
            if keys_corroborate_identity:
                warnings.append(
                    f"{profile.source} says short_name {profile.short_name!r}, {nodedb_source} "
                    f"says {entry.short_name!r} -- both carry the same public key, so this "
                    "looks like a rename between exports rather than different nodes; using "
                    f"{profile.source}'s name (the profile always takes precedence)."
                )
            else:
                raise BackupParseError(
                    f"Conflicting short_name between backups: {profile.source} says "
                    f"{profile.short_name!r}, {nodedb_source} says {entry.short_name!r}. These "
                    "backups may not be for the same node.",
                    source=nodedb_source,
                )
        if (
            profile.public_key is not None
            and entry.public_key is not None
            and profile.public_key != entry.public_key
        ):
            raise BackupParseError(
                f"Conflicting public key between {profile.source} and {nodedb_source}: "
                "these backups appear to be for different nodes.",
                source=nodedb_source,
            )

    return BackupBundle(profile=profile, nodedb_entry=entry, warnings=tuple(warnings))


def live_config_from_backup(bundle: BackupBundle, *, node_id: NodeId) -> detect.LiveConfig:
    """Build a :class:`~meshprovision.provisioning.detect.LiveConfig` from a backup bundle.

    The file-based counterpart to
    :func:`meshprovision.provisioning.detect.read_live_config`: builds the
    exact same normalized shape, so every downstream consumer (``mesh
    adopt``'s report, weak-key auditing, name-pattern checking) works
    identically regardless of whether the live state came from a
    connected device or a backup file.

    Copies the profile's protobuf messages before handing them to
    :func:`~meshprovision.provisioning.detect.live_config_from_protobufs`
    (rather than mutating ``bundle.profile``'s own messages in place),
    so this function has no side effect on ``bundle`` and is safe to call
    more than once.

    Args:
        bundle: The merged backup bundle.
        node_id: The already-resolved node id (see
            :func:`meshprovision.cli.adopt_backup.resolve_node_id` --
            never inferred here).

    Returns:
        The normalized :class:`~meshprovision.provisioning.detect.LiveConfig`.
    """
    if bundle.profile is not None:
        local_config = localonly_pb2.LocalConfig()
        local_config.CopyFrom(bundle.profile.local_config)
        module_config = localonly_pb2.LocalModuleConfig()
        module_config.CopyFrom(bundle.profile.module_config)
    else:
        local_config = localonly_pb2.LocalConfig()
        module_config = localonly_pb2.LocalModuleConfig()

    entry = bundle.nodedb_entry
    role_raw: str | None = None
    role_recognized: str | None = None
    if entry is not None and entry.public_key and not bytes(local_config.security.public_key):
        local_config.security.public_key = entry.public_key
    if entry is not None and entry.role:
        role_value = enums.role_table().try_value(entry.role)
        if role_value is not None:
            local_config.device.role = role_value
            role_recognized = entry.role
        else:
            # Cannot assign an unrecognized string onto the protobuf enum
            # field at all (there is no numeric value to give it), so it
            # stays at its own default -- which is itself a *recognized*
            # name ("CLIENT"). Passed through separately so
            # build_adoption_report can tell "genuinely CLIENT" from
            # "unmappable, papered over by the protobuf default" instead
            # of silently recording the wrong role as observed.
            role_raw = entry.role

    hw_model_raw = entry.hw_model if entry is not None else None
    hw_model = (enums.hw_model_table().try_name(hw_model_raw) or "") if hw_model_raw else ""
    firmware_version = (entry.firmware_version if entry is not None else "") or ""

    result = detect.live_config_from_protobufs(
        local_config,
        module_config,
        node_id=node_id,
        short_name=bundle.short_name,
        long_name=bundle.long_name,
        hw_model=hw_model,
        hw_model_raw=hw_model_raw,
        role_raw=role_raw,
        firmware_version=firmware_version,
    )
    if bundle.profile is None:
        # No .cfg/.yaml was supplied, so local_config/module_config above
        # are bare protobuf messages with no data behind them at all --
        # every "sections"/"module_sections" scalar detect.py just read
        # off them is a protobuf zero-value (role=CLIENT, region=UNSET,
        # ...), indistinguishable downstream from a genuine observation.
        # A node-db-only export (the easiest backup for an operator to
        # produce) carries no config section whatsoever; strip the
        # fabricated section data here rather than let it masquerade as
        # observed truth. hw_model/firmware_version/security are
        # unaffected -- they come from `entry`, not these sections, and
        # remain real when `entry` itself is real. A recognized role IS
        # real too (NodeDbEntry.role is the one section-shaped field this
        # source can genuinely report -- NodeDbEntry has no region field
        # at all) so it alone survives the strip.
        kept_sections: dict[str, Mapping[str, object]] = (
            {"device": {"role": role_recognized}} if role_recognized is not None else {}
        )
        result = replace(result, sections=kept_sections, module_sections={}, module_enabled={})
    return result


def suggest_node_ids_by_name(
    observations: Mapping[NodeId, NodeObservation], *, long_name: str
) -> tuple[NodeId, ...]:
    """Find every observed node whose ``long_name`` matches, case/whitespace-insensitively.

    Pure: the caller (``mesh adopt --from-backup``) is responsible for
    fetching ``observations`` (typically from
    :meth:`~meshprovision.datasources.loranet.LoranetSource.fetch_all`,
    the only name-searchable source -- see the CLI's docstring for why
    lorastats cannot be searched by name). This is advisory only: the CLI
    must never adopt using a name match alone, only offer it as a
    ``--node-id`` hint.

    Args:
        observations: Every observed node to search, keyed by id.
        long_name: The backup's ``long_name`` to match against. An empty
            (after stripping) value always yields no matches.

    Returns:
        Every matching node id, sorted ascending by numeric value (for
        deterministic output; a node renamed to collide with another's
        old name is a real, if rare, possibility this project does not
        try to rank).
    """
    target = long_name.strip().casefold()
    if not target:
        return ()
    matches = [
        node_id
        for node_id, obs in observations.items()
        if (obs.long_name or "").strip().casefold() == target
    ]
    return tuple(sorted(matches, key=int))
