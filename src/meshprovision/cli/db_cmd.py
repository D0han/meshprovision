"""``mesh db`` group -- ``verify`` (schema + weak-key audit) and ``backup``.

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
never rewrites the database itself.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import click

from meshprovision.cli.common import CONTEXT_SETTINGS, echo_json, handle_cli_errors, pass_cli
from meshprovision.config.template import admin_public_key_ref
from meshprovision.crypto import weakkeys
from meshprovision.db import atomic_writer, schema
from meshprovision.db.schema import KeyType
from meshprovision.errors import AtomicWriteError, ConfigError, ExitCode, KeyMaterialError
from meshprovision.nodeid import NodeId

if TYPE_CHECKING:
    from meshprovision.cli.common import CliContext, DbSession
    from meshprovision.config.template import TemplateConfig

__all__ = ["DbProblem", "VerifyReport", "db", "db_backup", "db_verify", "verify_database"]


@dataclass(frozen=True, slots=True)
class DbProblem:
    """One finding surfaced by :func:`verify_database`.

    Attributes:
        kind: One of ``"integrity_warning"``, ``"unresolved_admin_ref"``,
            ``"unresolved_template_ref"``, ``"duplicate_public_key"``,
            ``"alias_public_key"``, ``"weak_key"``,
            ``"admin_key_mismatch"``, or ``"insecure_permissions"`` (POSIX
            only).
        severity: ``"critical"``, ``"error"``, or ``"warning"``.
        message: Human-readable description of the finding.
        sheet: Name of the offending sheet, when known.
        ref: Reference or cell identifying the offending row, when known.
    """

    kind: str
    severity: str
    message: str
    sheet: str | None = None
    ref: str | None = None

    def to_json_dict(self) -> dict[str, object]:
        """Render this problem as a JSON-safe dict.

        Returns:
            A mapping covering every field.
        """
        return {
            "kind": self.kind,
            "severity": self.severity,
            "message": self.message,
            "sheet": self.sheet,
            "ref": self.ref,
        }


@dataclass(frozen=True, slots=True)
class VerifyReport:
    """The full outcome of one :func:`verify_database` run.

    Attributes:
        path: Path to the database that was verified.
        node_count: Number of rows in the ``Nodes`` sheet.
        key_count: Number of rows in the ``Keys`` sheet.
        problems: Every finding, in the order it was discovered.
    """

    path: Path
    node_count: int
    key_count: int
    problems: tuple[DbProblem, ...]

    @property
    def has_critical(self) -> bool:
        """Whether any problem is critical.

        Returns:
            ``True`` if any :attr:`problems` entry has
            ``severity == "critical"``.
        """
        return any(problem.severity == "critical" for problem in self.problems)

    @property
    def has_error(self) -> bool:
        """Whether any problem is an error.

        Returns:
            ``True`` if any :attr:`problems` entry has
            ``severity == "error"``.
        """
        return any(problem.severity == "error" for problem in self.problems)

    def exit_code(self, *, strict: bool) -> int:
        """Compute the process exit code ``mesh db verify`` should return.

        Args:
            strict: Whether a bare warning (with no error or critical
                problem present) should also produce a non-zero exit.

        Returns:
            :attr:`~meshprovision.errors.ExitCode.CRYPTO` (6) when
            :attr:`has_critical`; else :attr:`~meshprovision.errors.
            ExitCode.DB` (4) when :attr:`has_error`; else
            :attr:`~meshprovision.errors.ExitCode.DB` when ``strict`` and
            any problem is a warning; else
            :attr:`~meshprovision.errors.ExitCode.OK`.
        """
        if self.has_critical:
            return int(ExitCode.CRYPTO)
        if self.has_error:
            return int(ExitCode.DB)
        if strict and any(problem.severity == "warning" for problem in self.problems):
            return int(ExitCode.DB)
        return int(ExitCode.OK)

    def to_json_dict(self) -> dict[str, object]:
        """Render this report as a JSON-safe dict.

        Returns:
            A mapping with ``path``, ``node_count``, ``key_count``, and a
            list of :meth:`DbProblem.to_json_dict` entries.
        """
        return {
            "path": str(self.path),
            "node_count": self.node_count,
            "key_count": self.key_count,
            "problems": [problem.to_json_dict() for problem in self.problems],
        }


def verify_database(
    db: DbSession, template: TemplateConfig | None, *, known_bad: frozenset[bytes]
) -> VerifyReport:
    """Run every cross-reference and weak-key check over an already-loaded database.

    Cross-fleet duplicate detection is alias-aware: ``mesh admin
    bootstrap --ref LABEL`` deliberately files one physical node's public
    key under both ``<node_id>_pub`` and ``<LABEL>_pub``, so a duplicate
    group is classified CRITICAL (the CVE-2025-52464 vendor
    key-cloning signature) only when it contains two or more *distinct*
    owners that are real nodes in the ``Nodes`` sheet; a node-plus-label
    group (or a labels-only group) is reported as an informational alias
    warning instead. Each duplicate group produces exactly one problem,
    keyed by its sorted member tuple, so a two-member group never
    produces two lines.

    Args:
        db: The already-open, already-loaded database session.
        template: The validated provisioning template, when available.
            ``None`` skips the template-reference cross-check -- verifying
            a database must work even without a template on disk.
        known_bad: The loaded weak-key blocklist.

    Returns:
        The full :class:`VerifyReport`.
    """
    problems: list[DbProblem] = []

    if os.name == "posix":
        mode = db.path.stat().st_mode & 0o777
        if mode & 0o077:
            problems.append(
                DbProblem(
                    kind="insecure_permissions",
                    severity="warning",
                    message=(
                        f"Database file mode is {mode:04o}; it holds private key material "
                        f"and should be 0600. Run `chmod 600 {db.path}`."
                    ),
                    ref=str(db.path),
                )
            )

    for warning in db.db.warnings:
        problems.append(
            DbProblem(
                kind="integrity_warning",
                severity="warning",
                message=warning.message(),
                sheet=warning.sheet,
                ref=warning.cell,
            )
        )

    unresolved = db.nodes.unresolved_admin_refs(db.keys)
    for node_id, missing_refs in unresolved.items():
        problems.append(
            DbProblem(
                kind="unresolved_admin_ref",
                severity="error",
                message=(
                    f"Node {node_id} authorizes unresolved admin key reference(s): "
                    f"{', '.join(missing_refs)}."
                ),
                sheet="Nodes",
                ref=node_id,
            )
        )

    if template is not None:
        for ref in template.admin_nodes:
            key_ref = admin_public_key_ref(ref)
            if db.keys.find(key_ref) is None:
                problems.append(
                    DbProblem(
                        kind="unresolved_template_ref",
                        severity="error",
                        message=(
                            f"Template admin_nodes entry {ref!r} does not resolve to a "
                            f"{key_ref!r} row in the Keys sheet."
                        ),
                        sheet="Keys",
                        ref=ref,
                    )
                )

    for record in db.keys.all():
        try:
            if record.key_type is KeyType.ADMIN_PUBLIC:
                audit = weakkeys.audit_public_key(
                    record.material(), key_ref=record.key_ref, known_bad=known_bad
                )
            else:
                audit = weakkeys.audit_private_key(
                    record.secret(),
                    key_ref=record.key_ref,
                    known_bad=known_bad,
                    check_clamping=False,
                )
        except KeyMaterialError:
            problems.append(
                DbProblem(
                    kind="weak_key",
                    severity="critical",
                    message="malformed key material",
                    sheet="Keys",
                    ref=record.key_ref,
                )
            )
            continue
        for finding in audit.findings:
            problems.append(
                DbProblem(
                    kind="weak_key",
                    severity=finding.severity,
                    message=f"{finding.check.value}: {finding.reason}",
                    sheet="Keys",
                    ref=record.key_ref,
                )
            )

    for record in db.keys.of_type(KeyType.ADMIN_PRIVATE):
        admin_ref = record.key_ref.removesuffix("_priv")
        if db.keys.find(admin_public_key_ref(admin_ref)) is None:
            continue
        if db.keys.private_key_mismatch(admin_ref):
            problems.append(
                DbProblem(
                    kind="admin_key_mismatch",
                    severity="error",
                    message=(
                        f"{record.key_ref} does not derive "
                        f"{admin_public_key_ref(admin_ref)}; the pair is inconsistent."
                    ),
                    sheet="Keys",
                    ref=record.key_ref,
                )
            )

    groups = weakkeys.find_duplicate_public_keys(db.keys.public_key_map())
    seen_groups: set[tuple[str, ...]] = set()
    for key_ref, others in groups.items():
        group = tuple(sorted({key_ref, *others}))
        if group in seen_groups:
            continue
        seen_groups.add(group)

        node_owners: set[str] = set()
        for member_ref in group:
            member = db.keys.find(member_ref)
            owner = member.owner_node_id if member is not None else member_ref
            parsed = NodeId.try_parse(owner)
            if parsed is not None and db.nodes.exists(parsed):
                node_owners.add(owner)

        rest = tuple(member_ref for member_ref in group if member_ref != group[0])
        if len(node_owners) >= 2:
            problems.append(
                DbProblem(
                    kind="duplicate_public_key",
                    severity="critical",
                    message=(
                        f"Public key shared across distinct nodes: "
                        f"{', '.join(sorted(node_owners))} -- the CVE-2025-52464 vendor "
                        "key-cloning signature."
                    ),
                    sheet="Keys",
                    ref=",".join(group),
                )
            )
        else:
            problems.append(
                DbProblem(
                    kind="alias_public_key",
                    severity="warning",
                    message=(
                        f"{group[0]} shares its public key with {', '.join(rest)} "
                        "(alias for the same node)."
                    ),
                    sheet="Keys",
                    ref=",".join(group),
                )
            )

    return VerifyReport(
        path=db.path,
        node_count=len(db.nodes.all()),
        key_count=len(db.keys.all()),
        problems=tuple(problems),
    )


@click.group(name="db", context_settings=CONTEXT_SETTINGS)
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
    db_session = ctx.open_database()

    template: TemplateConfig | None
    try:
        template = ctx.load_template()
    except ConfigError as exc:
        ctx.warn(f"Could not load template for cross-checking: {exc.user_message}")
        template = None

    known_bad = weakkeys.load_known_bad_keys()
    report = verify_database(db_session, template, known_bad=known_bad)

    if json_output:
        echo_json(report.to_json_dict())
    elif not report.problems:
        ctx.success("Database OK.")
    else:
        emitters: tuple[tuple[str, Callable[[str], None]], ...] = (
            ("critical", ctx.error),
            ("error", ctx.error),
            ("warning", ctx.warn),
        )
        for severity, emit in emitters:
            items = [problem for problem in report.problems if problem.severity == severity]
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
    itself.

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
        if json_output:
            echo_json(
                {
                    "backups": [
                        {
                            "path": str(info.path),
                            "created_at": schema.utc_timestamp(info.created_at),
                            "size_bytes": info.size_bytes,
                        }
                        for info in infos
                    ]
                }
            )
        elif not infos:
            ctx.print_out("No backups found.")
        else:
            for info in infos:
                ctx.print_out(
                    f"{info.path}  {schema.utc_timestamp(info.created_at)}  {info.size_bytes} bytes"
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
