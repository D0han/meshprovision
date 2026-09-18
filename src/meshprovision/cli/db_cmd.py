"""``mesh db`` group -- ``verify``, ``backup``, ``restore``, ``list``.

``mesh db verify`` re-validates a database that may already have loaded
successfully (schema/validation/duplicate-row failures already raised out
of :meth:`~meshprovision.cli.common.CliContext.open_database` as
:class:`~meshprovision.errors.SchemaError`/
:class:`~meshprovision.errors.DbValidationError`/
:class:`~meshprovision.errors.DuplicateNodeError`/
:class:`~meshprovision.errors.DbIntegrityError`, reaching the CLI's error
boundary as exit 4) and layers on cross-reference checks, a weak-key
audit over every key row, and alias-aware cross-fleet duplicate
detection. ``mesh db backup`` writes only into the backup directory; it
never rewrites the database itself. ``mesh db restore`` is the only
command in this group that rewrites the live database directly (not via
the normal load-modify-save session), so unlike ``backup`` it *does* take
the cross-process write lock -- see :func:`~meshprovision.db.atomic_writer
.restore_backup`'s docstring and :mod:`meshprovision.db.locking`. ``mesh
db list`` is the offline counterpart to ``mesh status``: a plain dump of
the ``Nodes`` sheet's own content, with no device connection or external
data source involved. ``mesh db forget`` archives (soft-deletes) a node:
its row is never removed, only its ``archived_at`` cell is set, so
``authorized_admin_keys``/``notes`` survive for audit history while
:attr:`~meshprovision.db.nodes.NodeRecord.is_archived` gates whether
``mesh status``/``mesh provision``/``mesh admin bootstrap``/``mesh adopt``
still act on it.

Beyond the timestamped backups ``backup``/``restore`` manage, a single
known-good safety copy (see :func:`~meshprovision.db.atomic_writer
.refresh_known_good`) is refreshed by every successful database load,
anywhere in the codebase -- not just through this module. ``mesh db
restore --known-good`` restores it without needing its path, and it is
exactly what a load-failure error's hint (see
:meth:`~meshprovision.cli.common.CliContext.open_database`) points an
operator at after a hand-edit breaks the live file.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import click
from rich import box
from rich.table import Table

from meshprovision.cli.common import (
    CONTEXT_SETTINGS,
    MeshGroup,
    echo_json,
    handle_cli_errors,
    pass_cli,
)
from meshprovision.crypto import weakkeys
from meshprovision.db import atomic_writer, locking, ods, schema
from meshprovision.db.verify import ProblemSeverity, verify_database
from meshprovision.errors import (
    AdminKeyCapacityError,
    AtomicWriteError,
    ConfigError,
    MeshprovisionError,
    SchemaError,
)

if TYPE_CHECKING:
    from meshprovision.cli.common import CliContext
    from meshprovision.config.template import TemplateConfig

__all__ = [
    "db",
    "db_backup",
    "db_forget",
    "db_list",
    "db_restore",
    "db_verify",
]


@click.group(name="db", cls=MeshGroup, context_settings=CONTEXT_SETTINGS)
def db() -> None:
    """Database integrity and backup helpers for the ODS node database."""


@db.command(name="verify")
@click.option(
    "--strict",
    is_flag=True,
    default=False,
    help="Treat a bare warning (no error or critical problem) as a failing exit code too.",
)
@click.option(
    "--json", "json_output", is_flag=True, default=False, help="Emit JSON instead of human text."
)
@pass_cli
@handle_cli_errors
def db_verify(ctx: CliContext, *, strict: bool, json_output: bool) -> None:
    """Verify the ODS database's schema, cross-references, and key hygiene.

    Args:
        ctx: The shared CLI context, injected by :data:`~meshprovision.
            cli.common.pass_cli`.
        strict: Whether a bare warning also produces a non-zero exit,
            from ``--strict``.
        json_output: Whether to emit JSON, from ``--json``.

    Raises:
        SystemExit: With the report's exit code, when it is non-zero.
    """
    with ctx.open_database() as db_session:
        template: TemplateConfig | None
        template_error: str | None = None
        try:
            template = ctx.load_template()
        # Any template failure must degrade to a warning, never abort: verifying
        # a database has to work without a usable template. AdminKeyCapacityError
        # is a ProvisioningError, not a ConfigError, so ConfigError alone misses
        # it -- extend this tuple if a new TemplateConfig validator raises outside
        # the ConfigError branch. Deliberately not `except MeshprovisionError`:
        # ctx.load_template() runs inside the open database session, and a broad
        # catch here would downgrade a real DbError into "template unavailable"
        # and then report a falsely clean verification.
        except (ConfigError, AdminKeyCapacityError) as exc:
            ctx.warn(f"Could not load template for cross-checking: {exc.user_message}")
            template = None
            template_error = exc.user_message

        known_bad = weakkeys.load_known_bad_keys()
        report = verify_database(
            path=db_session.path,
            warnings=db_session.db.warnings,
            nodes=db_session.nodes,
            keys=db_session.keys,
            template=template,
            known_bad=known_bad,
            template_error=template_error,
        )

    if json_output:
        echo_json(report.to_json_dict())
    elif not report.problems:
        ctx.success("Database OK.")
    else:
        emitters: tuple[tuple[ProblemSeverity, Callable[[str], None]], ...] = (
            (ProblemSeverity.CRITICAL, ctx.error),
            (ProblemSeverity.ERROR, ctx.error),
            (ProblemSeverity.WARNING, ctx.warn),
        )
        for severity, emit in emitters:
            items = [problem for problem in report.problems if problem.severity is severity]
            if not items:
                continue
            emit(f"{len(items)} {severity} problem(s):")
            for problem in items:
                location = (
                    f"{problem.sheet}.{problem.ref}" if problem.sheet else (problem.ref or "")
                )
                prefix = f"{location}: " if location else ""
                emit(f"  {prefix}{problem.message}")

    code = report.exit_code(strict=strict)
    if code:
        raise SystemExit(code)


@db.command(name="backup")
@click.option(
    "--backup-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Directory to store backups under. Defaults to data/backups.",
)
@click.option(
    "--retention",
    type=click.IntRange(min=0),
    default=atomic_writer.DEFAULT_RETENTION,
    show_default=True,
    help="Number of backups to retain.",
)
@click.option(
    "--list",
    "list_only",
    is_flag=True,
    default=False,
    help="List existing backups instead of creating one.",
)
@click.option(
    "--json", "json_output", is_flag=True, default=False, help="Emit JSON instead of human text."
)
@pass_cli
@handle_cli_errors
def db_backup(
    ctx: CliContext, *, backup_dir: Path | None, retention: int, list_only: bool, json_output: bool
) -> None:
    """Create an on-demand backup of the ODS database, or list existing backups.

    Writes only into the backup directory; never rewrites the database
    itself. Deliberately does not take the cross-process write lock (see
    :mod:`meshprovision.db.locking`): ``shutil.copy2`` (used by
    :func:`~meshprovision.db.atomic_writer.create_backup`) reads whichever
    inode it opened through to completion even if a concurrent writer's
    ``os.replace`` re-points the path mid-copy, so the backup is always a
    consistent snapshot of some version of the database. Do not "fix"
    this by adding a lock.

    ``--list`` also reports the known-good safety copy (see
    :func:`~meshprovision.db.atomic_writer.refresh_known_good`), when one
    exists, ahead of the timestamped backups it is not one of --
    ``mesh db restore --known-good`` restores it directly, without
    needing to name its path.

    Args:
        ctx: The shared CLI context, injected by :data:`~meshprovision.
            cli.common.pass_cli`.
        backup_dir: Backup directory override, from ``--backup-dir``.
        retention: Number of backups to retain, from ``--retention``.
        list_only: Whether to list existing backups instead of creating
            one, from ``--list``.
        json_output: Whether to emit JSON, from ``--json``.

    Raises:
        AtomicWriteError: If the database file does not exist (nothing to
            back up), or the backup copy fails.
    """
    path = ctx.settings.db_path
    resolved_backup_dir = backup_dir if backup_dir is not None else atomic_writer.DEFAULT_BACKUP_DIR

    if list_only:
        infos = atomic_writer.list_backups(path, backup_dir=resolved_backup_dir)
        # Deliberately not resolved_backup_dir: the known-good copy is a
        # single, global safety net refreshed by every successful load
        # (load_database() never sees a per-invocation --backup-dir
        # override), so it always lives under the default location
        # regardless of what this specific --backup-dir names.
        known_good = atomic_writer.known_good_info(path)
        if json_output:
            payload: dict[str, object] = {
                "backups": [
                    {
                        "path": str(info.path),
                        "created_at": schema.utc_timestamp(info.created_at),
                        "size_bytes": info.size_bytes,
                    }
                    for info in infos
                ]
            }
            if known_good is not None:
                payload["known_good"] = {
                    "path": str(known_good.path),
                    "created_at": schema.utc_timestamp(known_good.created_at),
                    "size_bytes": known_good.size_bytes,
                }
            echo_json(payload)
        else:
            if known_good is not None:
                ctx.print_out(
                    f"known-good: {known_good.path}  "
                    f"{schema.utc_timestamp(known_good.created_at)}  "
                    f"{known_good.size_bytes} bytes"
                )
            if not infos:
                ctx.print_out("No backups found.")
            else:
                for info in infos:
                    ctx.print_out(
                        f"{info.path}  {schema.utc_timestamp(info.created_at)}  "
                        f"{info.size_bytes} bytes"
                    )
        return

    if not path.is_file():
        raise AtomicWriteError(f"Nothing to back up: {path} does not exist.", path=str(path))

    backup_info = atomic_writer.create_backup(
        path, backup_dir=resolved_backup_dir, retention=retention
    )
    if backup_info is None:
        raise AtomicWriteError(f"Nothing to back up: {path} does not exist.", path=str(path))

    ctx.success(f"Backed up {path} -> {backup_info.path} ({backup_info.size_bytes} bytes)")
    if json_output:
        echo_json(
            {
                "source": str(path),
                "backup": str(backup_info.path),
                "created_at": schema.utc_timestamp(backup_info.created_at),
                "size_bytes": backup_info.size_bytes,
            }
        )


@db.command(name="restore")
@click.argument(
    "backup", required=False, type=click.Path(exists=True, dir_okay=False, path_type=Path)
)
@click.option(
    "--known-good",
    "use_known_good",
    is_flag=True,
    default=False,
    help="Restore the known-good safety copy instead of naming a BACKUP path.",
)
@click.option("-y", "--yes", is_flag=True, default=False, help="Assume yes to the confirmation.")
@click.option(
    "--backup-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Directory the pre-restore safety backup is stored under. Defaults to data/backups.",
)
@click.option(
    "--json", "json_output", is_flag=True, default=False, help="Emit JSON instead of human text."
)
@pass_cli
@handle_cli_errors
def db_restore(
    ctx: CliContext,
    *,
    backup: Path | None,
    use_known_good: bool,
    yes: bool,
    backup_dir: Path | None,
    json_output: bool,
) -> None:
    """Restore the ODS database from a backup file, overwriting the live database.

    Unlike ``mesh db backup``, this rewrites the live database directly,
    so it holds the cross-process write lock for the whole operation --
    excluding a concurrent ``mesh provision``/``mesh admin`` run the same
    way those commands exclude each other. The current database is
    itself backed up first (by :func:`~meshprovision.db.atomic_writer
    .restore_backup`), so a restore is always reversible via
    ``mesh db backup --list``. After restoring, the result is loaded back
    to confirm it is actually a valid database -- a bad ``backup`` file
    is caught here, not on the next unrelated ``mesh`` command.

    Pass either ``BACKUP`` (a specific file, typically copied from
    ``mesh db backup --list``) or ``--known-good``, never both: the
    latter restores the safety copy every successful database load
    refreshes (see :func:`~meshprovision.db.atomic_writer
    .refresh_known_good`) -- exactly what a load-failure error's hint
    points at, without needing to first hunt down its path.

    Args:
        ctx: The shared CLI context, injected by :data:`~meshprovision.
            cli.common.pass_cli`.
        backup: Path to the backup file to restore from, or ``None`` when
            ``--known-good`` is used instead.
        use_known_good: Whether to restore the known-good safety copy,
            from ``--known-good``.
        yes: Whether to assume yes to the confirmation, from ``-y``/``--yes``.
        backup_dir: Pre-restore safety-backup directory override, from
            ``--backup-dir``. Also where the known-good copy itself is
            looked up, when ``--known-good`` is used.
        json_output: Whether to emit JSON, from ``--json``.

    Raises:
        click.UsageError: If neither ``BACKUP`` nor ``--known-good`` is
            given, or both are.
        AtomicWriteError: If the resolved backup file cannot be read, the
            restore write fails, or ``--known-good`` was given but no
            known-good copy exists yet.
        SchemaError: If the restored file does not load as a valid
            database. The pre-restore backup is still available via
            ``mesh db backup --list``.
    """
    ctx = ctx.with_assume_yes(yes)
    path = ctx.settings.db_path
    resolved_backup_dir = backup_dir if backup_dir is not None else atomic_writer.DEFAULT_BACKUP_DIR

    if use_known_good and backup is not None:
        raise click.UsageError("Pass either BACKUP or --known-good, not both.")
    if use_known_good:
        # Deliberately not resolved_backup_dir -- see the matching
        # comment in db_backup(): the known-good copy always lives at
        # the default location, independent of --backup-dir (which here
        # only controls where the *pre-restore* safety backup lands).
        known_good = atomic_writer.known_good_info(path)
        if known_good is None:
            raise AtomicWriteError(
                f"No known-good copy exists yet under {atomic_writer.DEFAULT_BACKUP_DIR}.",
                path=str(path),
            )
        resolved_backup = known_good.path
    elif backup is not None:
        resolved_backup = backup
    else:
        raise click.UsageError("Pass either BACKUP or --known-good.")

    question = (
        f"Restore {path} from {resolved_backup}? The current database is backed up first, "
        "but this overwrites the live database."
    )
    if not ctx.confirm(question, default=False):
        raise click.Abort()

    with locking.exclusive_lock(path):
        atomic_writer.restore_backup(resolved_backup, path, backup_dir=resolved_backup_dir)
        try:
            ods.load_database(path)
        except MeshprovisionError as exc:
            raise SchemaError(
                f"Restored {resolved_backup} but it does not load as a valid database: "
                f"{exc.user_message}",
                hint=(
                    "The previous database was backed up before the restore; "
                    "run `mesh db backup --list` to find it and restore again."
                ),
            ) from exc

    ctx.success(f"Restored {path} from {resolved_backup}.")
    if json_output:
        echo_json({"target": str(path), "restored_from": str(resolved_backup)})


@db.command(name="list")
@click.option(
    "--json", "json_output", is_flag=True, default=False, help="Emit JSON instead of a table."
)
@pass_cli
@handle_cli_errors
def db_list(ctx: CliContext, *, json_output: bool) -> None:
    """List every node recorded in the database, with no device or network dependency.

    The offline counterpart to ``mesh status``: a plain dump of the
    ``Nodes`` sheet's own content -- for when an operator just wants to
    see what's recorded without opening the ``.ods`` by hand, without
    ``MESHPROVISION_CONTACT`` configured, or without any of the fleet
    actually reachable over the network.

    Args:
        ctx: The shared CLI context, injected by :data:`~meshprovision.
            cli.common.pass_cli`.
        json_output: Whether to emit JSON, from ``--json``.
    """
    with ctx.open_database() as db:
        records = db.nodes.all()

    if json_output:
        echo_json(
            {
                "nodes": [
                    {
                        "node_id": record.node_id,
                        "short_name": record.short_name,
                        "long_name": record.long_name,
                        "hw_model": record.hw_model,
                        "firmware_type": record.firmware_type.value,
                        "firmware_version": record.firmware_version,
                        "management": record.management.value,
                        "region": record.region,
                        "role": record.role,
                        "authorized_admin_keys": list(record.authorized_admin_keys),
                        "notes": record.notes,
                        "archived_at": (
                            None
                            if record.archived_at is None
                            else schema.utc_timestamp(record.archived_at)
                        ),
                    }
                    for record in records
                ]
            }
        )
        return

    if not records:
        ctx.print_out("No nodes found.")
        return

    table = Table(box=box.SIMPLE_HEAVY, header_style="bold")
    table.add_column("Node")
    table.add_column("Short")
    table.add_column("Long")
    table.add_column("Mgmt")
    table.add_column("HW model")
    table.add_column("Firmware")
    table.add_column("Region")
    table.add_column("Role")
    table.add_column("Admin keys")
    table.add_column("Archived")
    for record in records:
        table.add_row(
            record.node_id,
            record.short_name or "-",
            record.long_name or "-",
            record.management.value,
            record.hw_model or "-",
            record.firmware_version or "-",
            record.region or "-",
            record.role or "-",
            ", ".join(record.authorized_admin_keys) or "-",
            schema.utc_timestamp(record.archived_at) if record.archived_at else "-",
        )
    ctx.err.print(table, markup=False, highlight=False)


@db.command(name="forget")
@click.argument("node_id")
@click.option("-y", "--yes", is_flag=True, default=False, help="Assume yes to the confirmation.")
@click.option(
    "--json", "json_output", is_flag=True, default=False, help="Emit JSON instead of human text."
)
@pass_cli
@handle_cli_errors
def db_forget(ctx: CliContext, *, node_id: str, yes: bool, json_output: bool) -> None:
    """Archive (soft-delete) a node -- exclude it from mesh status/provision/adopt/admin bootstrap.

    Never deletes the row: every field, including ``authorized_admin_keys``
    and ``notes``, is preserved for audit history -- only ``archived_at``
    is set. ``mesh db list`` still shows an archived node (with its
    ``Archived`` column filled in) by default.

    Args:
        ctx: The shared CLI context, injected by :data:`~meshprovision.
            cli.common.pass_cli`.
        node_id: The node id to archive, in any form
            :meth:`~meshprovision.nodeid.NodeId.parse` accepts.
        yes: Whether to assume yes to the confirmation, from ``-y``/``--yes``.
        json_output: Whether to emit JSON, from ``--json``.

    Raises:
        NodeNotFoundError: If ``node_id`` does not resolve to a row in
            the database.
    """
    ctx = ctx.with_assume_yes(yes)

    with ctx.open_database(for_write=True) as db:
        record = db.nodes.get(node_id)
        display = record.node

        if record.is_archived:
            ctx.info(f"Node {display.display} is already archived; nothing to do.")
            return

        question = (
            f"Archive {display.display}? It will be excluded from `mesh status` and refused "
            "by `mesh provision`/`mesh admin bootstrap`/`mesh adopt`, but its row (admin keys, "
            "notes) stays in the database."
        )
        if not ctx.confirm(question, default=False):
            raise click.Abort()

        now = datetime.now(tz=UTC)
        db.nodes.upsert(record.with_updates(archived_at=now))
        db.db.save()

    ctx.success(f"Archived {display.display}.")
    if json_output:
        echo_json({"node_id": display.hex, "archived_at": schema.utc_timestamp(now)})
