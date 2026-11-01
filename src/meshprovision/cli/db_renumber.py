"""``mesh db renumber``: move a node's database row to the id firmware 2.8 gave it.

Firmware >= 2.8 derives a node's id from its public key, so a node upgraded
from 2.7, or one whose key changed, comes back under a new id. This command
moves everything the database keys by node id (see
:mod:`meshprovision.db.renumber`), then the pending-keypair file and the
lorastats region memo entry. Offline: no device, no network. Registered on
the ``mesh db`` group by :mod:`meshprovision.cli.db_cmd`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import click

from meshprovision.cli.common import (
    CONTEXT_SETTINGS,
    echo_json,
    handle_cli_errors,
    node_id_callback,
    pass_cli,
)
from meshprovision.cli.help_format import MeshCommand
from meshprovision.datasources.region_memo import REGION_MEMO_FILENAME, RegionMemo
from meshprovision.db import pending_keys
from meshprovision.db.renumber import check_renumber, renumber_rows
from meshprovision.db.schema import KeyType, ref_for
from meshprovision.errors import AtomicWriteError

if TYPE_CHECKING:
    from pathlib import Path

    from meshprovision.cli.common import CliContext
    from meshprovision.nodeid import NodeId

__all__ = ["db_renumber"]


def _move_pending(ctx: CliContext, db_path: Path, old: NodeId, new: NodeId) -> Path | None:
    """Move ``old``'s pending keypair to ``new`` after the save, warning (not failing) on error."""
    try:
        return pending_keys.move_pending(db_path, old, new)
    except AtomicWriteError as exc:
        ctx.warn(
            f"The pending keypair of {old.display} could not be moved to {new.display} ({exc}); "
            f"it stays at {pending_keys.pending_key_path(db_path, old)}."
        )
        return None


@click.command(name="renumber", cls=MeshCommand, context_settings=CONTEXT_SETTINGS)
@click.argument("old", callback=node_id_callback)
@click.argument("new", callback=node_id_callback)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Move the row even when NEW is not the id derived from a key OLD is known to hold.",
)
@click.option("-y", "--yes", is_flag=True, default=False, help="Assume yes to the confirmation.")
@click.option(
    "--json", "json_output", is_flag=True, default=False, help="Emit JSON instead of human text."
)
@pass_cli
@handle_cli_errors
def db_renumber(
    ctx: CliContext, *, old: NodeId, new: NodeId, force: bool, yes: bool, json_output: bool
) -> None:
    """Move a node's row, keys and key references from OLD to NEW (firmware 2.8 renumbering).

    NEW must be the id firmware >= 2.8 derives from OLD's recorded public
    key (or from the pending keypair an interrupted ``mesh provision``
    left), unless ``--force``. The row gets a note saying which id it had
    until today. The pending-keypair file and the lorastats region memo
    follow; the health history stays under OLD.

    Args:
        ctx: The shared CLI context, injected by :data:`~meshprovision.
            cli.common.pass_cli`.
        old: The node id whose row moves.
        new: The node id it moves to.
        force: Whether to skip the key-derived-id proof, from ``--force``.
        yes: Whether to assume yes to the confirmation, from ``-y``/``--yes``.
        json_output: Whether to emit JSON, from ``--json``.

    Raises:
        NodeNotFoundError: If OLD has no row.
        RenumberRefusedError: If a guard refuses the move (exit code 4).
        click.Abort: If the operator declines the confirmation prompt.
    """
    ctx = ctx.with_assume_yes(yes)
    with ctx.open_database(for_write=True) as db:
        pending = pending_keys.load_pending(db.path, old)
        check_renumber(
            db.nodes,
            db.keys,
            old=old,
            new=new,
            pending_public=pending.public if pending is not None else None,
            new_has_pending=pending_keys.load_pending(db.path, new) is not None,
            force=force,
        )
        question = (
            f"Move {old.display}'s row, keys and key references to {new.display}? "
            "Do this only for the same device, now reporting the new id."
        )
        if not ctx.confirm(question, default=False):
            raise click.Abort()
        moved = renumber_rows(db.nodes, db.keys, old=old, new=new, now=datetime.now(tz=UTC))
        db.db.save()
        pending_path = _move_pending(ctx, db.path, old, new) if pending is not None else None
    region = RegionMemo(ctx.settings.cache_dir / REGION_MEMO_FILENAME).move(old, new)

    ctx.success(f"Renumbered {old.display} to {new.display}.")
    if moved.keys:
        ctx.info(f"Keys: {', '.join(moved.keys)}.")
    if moved.referencing:
        ctx.info(f"Admin key references rewritten on: {', '.join(moved.referencing)}.")
    if moved.referencing or ref_for(new.hex, KeyType.ADMIN_PUBLIC) in moved.keys:
        # The template is not loaded: whenever the node's public key moved,
        # an admin_nodes entry naming it would now name nothing.
        ctx.info(f"If your template's admin_nodes names {old.hex}, change it to {new.hex}.")
    if pending_path is not None:
        ctx.info(f"Pending keypair moved to {pending_path}.")
    if json_output:
        echo_json(
            {
                "old": old.hex,
                "new": new.hex,
                "keys": list(moved.keys),
                "referencing": list(moved.referencing),
                "note": moved.note,
                "pending_keypair": str(pending_path) if pending_path is not None else None,
                "region_memo": region,
            }
        )
