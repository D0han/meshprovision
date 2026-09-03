"""Cross-reference and key-hygiene checks over an already-loaded database.

The compute half of ``mesh db verify``: :func:`verify_database` re-checks
a database that may already have loaded successfully (schema/validation/
duplicate-row failures already raised out of
:meth:`~meshprovision.cli.common.CliContext.open_database` as
:class:`~meshprovision.errors.SchemaError`/
:class:`~meshprovision.errors.DbValidationError`/
:class:`~meshprovision.errors.DuplicateNodeError`/
:class:`~meshprovision.errors.DbIntegrityError`) and layers on
cross-reference checks, a weak-key audit over every key row, and
alias-aware cross-fleet duplicate detection. ``cli/db_cmd.py`` stays a
thin wrapper that opens the database, calls this, and either prints the
report or emits JSON via :meth:`VerifyReport.to_json_dict`.

Takes a :class:`~meshprovision.db.nodes.NodeRepository`/
:class:`~meshprovision.db.keys.KeyRepository` pair directly (mirroring
:func:`meshprovision.provisioning.admin_custody.collect_admins`'s same
choice) rather than the whole :class:`~meshprovision.cli.common.
DbSession`, so this module depends only on :mod:`meshprovision.db` and
:mod:`meshprovision.config.template`, never on :mod:`meshprovision.cli`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from meshprovision.config.template import admin_public_key_ref
from meshprovision.crypto import weakkeys
from meshprovision.db.ods import IntegrityWarningKind
from meshprovision.db.schema import KeyType
from meshprovision.errors import ExitCode, KeyMaterialError, WeakKeySeverity
from meshprovision.nodeid import NodeId

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from meshprovision.config.template import TemplateConfig
    from meshprovision.db.keys import KeyRepository
    from meshprovision.db.nodes import NodeRepository
    from meshprovision.db.ods import IntegrityWarning

__all__ = [
    "DbProblem",
    "DbProblemKind",
    "ProblemSeverity",
    "VerifyReport",
    "verify_database",
]


class DbProblemKind(StrEnum):
    """The category of one finding surfaced by :func:`verify_database`."""

    INTEGRITY_WARNING = "integrity_warning"
    COERCED_CELL = "coerced_cell"
    UNRESOLVED_ADMIN_REF = "unresolved_admin_ref"
    UNRESOLVED_TEMPLATE_REF = "unresolved_template_ref"
    DUPLICATE_PUBLIC_KEY = "duplicate_public_key"
    ALIAS_PUBLIC_KEY = "alias_public_key"
    WEAK_KEY = "weak_key"
    ADMIN_KEY_MISMATCH = "admin_key_mismatch"
    INSECURE_PERMISSIONS = "insecure_permissions"
    TEMPLATE_UNAVAILABLE = "template_unavailable"


class ProblemSeverity(StrEnum):
    """Severity of one :class:`DbProblem`."""

    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"

    @classmethod
    def from_weak_key_severity(cls, severity: WeakKeySeverity) -> ProblemSeverity:
        """Convert a :class:`~meshprovision.errors.WeakKeySeverity` finding severity.

        The single, explicit place this project's two independent
        severity vocabularies are bridged -- ``WeakKeySeverity`` has no
        ``"error"`` tier, so this can only ever produce ``CRITICAL`` or
        ``WARNING``.

        Args:
            severity: The weak-key audit finding's severity.

        Returns:
            :attr:`CRITICAL` for :attr:`WeakKeySeverity.CRITICAL`,
            otherwise :attr:`WARNING`.
        """
        return cls.CRITICAL if severity is WeakKeySeverity.CRITICAL else cls.WARNING


@dataclass(frozen=True, slots=True)
class DbProblem:
    """One finding surfaced by :func:`verify_database`.

    Attributes:
        kind: The category of this finding. Serializes as its bare
            string value, so the ``--json`` wire format is unchanged.
        severity: This finding's severity. Serializes as its bare string
            value, same as :attr:`kind`.
        message: Human-readable description of the finding.
        sheet: Name of the offending sheet, when known.
        ref: Reference or cell identifying the offending row, when known.
    """

    kind: DbProblemKind
    severity: ProblemSeverity
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
        return any(problem.severity is ProblemSeverity.CRITICAL for problem in self.problems)

    @property
    def has_error(self) -> bool:
        """Whether any problem is an error.

        Returns:
            ``True`` if any :attr:`problems` entry has
            ``severity == "error"``.
        """
        return any(problem.severity is ProblemSeverity.ERROR for problem in self.problems)

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
        if strict and any(problem.severity is ProblemSeverity.WARNING for problem in self.problems):
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
    *,
    path: Path,
    warnings: Sequence[IntegrityWarning],
    nodes: NodeRepository,
    keys: KeyRepository,
    template: TemplateConfig | None,
    known_bad: frozenset[bytes],
    template_error: str | None = None,
) -> VerifyReport:
    """Run every cross-reference and weak-key check over an already-loaded database.

    Cross-fleet duplicate detection is alias-aware: ``mesh admin
    bootstrap --ref LABEL`` deliberately files one physical node's public
    key under both ``<node_id>_pub`` and ``<LABEL>_pub``, so a duplicate
    group is classified CRITICAL (the CVE-2025-52464 vendor
    key-cloning signature) only when it contains two or more *distinct*
    owners whose ``Keys`` sheet ref names an actual node id (``schema.
    ref_for`` only ever files a device's own key under ``<node_id>_pub``,
    never a template ``admin_nodes`` label) -- checked by the *canonical*
    8-lowercase-hex-digit form specifically
    (:meth:`~meshprovision.nodeid.NodeId.hex`'s own zero-padded shape),
    not merely whether the owner is parseable as *some* node id form:
    ``NodeId.try_parse`` alone also accepts a 1-7 character all-hex
    string, which a short hex-looking template label (``"cafe"``,
    ``"face"``) could satisfy by coincidence; a node-plus-label group (or
    a labels-only group) is reported as an informational alias warning
    instead. Deliberately does **not** additionally require that node to
    already have a ``Nodes`` sheet row: an admin key registered via
    ``mesh admin import`` ahead of the device being adopted or
    provisioned is exactly this project's own documented onboarding
    order, and a genuine clone between two such not-yet-adopted devices
    must not be downgraded to a warning just because neither is in
    ``Nodes`` yet. Each duplicate group produces exactly one problem,
    keyed by its sorted member tuple, so a two-member group never
    produces two lines.

    Args:
        path: Path to the database file being verified.
        warnings: Integrity warnings collected while loading the
            database (:attr:`~meshprovision.db.ods.OdsDatabase.warnings`).
        nodes: The already-open node repository.
        keys: The already-open key repository.
        template: The validated provisioning template, when available.
            ``None`` skips the template-reference cross-check -- verifying
            a database must work even without a template on disk.
        known_bad: The loaded weak-key blocklist.
        template_error: Set (to anything) by the caller when ``template``
            is ``None`` because loading it raised, as opposed to no
            template being configured at all. When set, a
            ``TEMPLATE_UNAVAILABLE`` problem is added so a ``--json``
            consumer can tell "the template cross-check ran clean" apart
            from "the template cross-check never ran" -- the problem's
            message deliberately doesn't repeat the caller's full error
            text (which the caller has typically already printed to
            stderr on its own) to avoid a duplicated wall of text in
            ``mesh db verify``'s plain-text output.

    Returns:
        The full :class:`VerifyReport`.
    """
    problems: list[DbProblem] = []

    if template is None and template_error is not None:
        problems.append(
            DbProblem(
                kind=DbProblemKind.TEMPLATE_UNAVAILABLE,
                severity=ProblemSeverity.WARNING,
                message=(
                    "Template cross-check skipped: the template failed to load "
                    "(admin_nodes references were not verified against the Keys sheet)."
                ),
            )
        )

    if os.name == "posix":
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            problems.append(
                DbProblem(
                    kind=DbProblemKind.INSECURE_PERMISSIONS,
                    severity=ProblemSeverity.WARNING,
                    message=(
                        f"Database file mode is {mode:04o}; it holds private key material "
                        f"and should be 0600. Run `chmod 600 {path}`."
                    ),
                    ref=str(path),
                )
            )

    for warning in warnings:
        problems.append(
            DbProblem(
                kind=(
                    DbProblemKind.COERCED_CELL
                    if warning.kind == IntegrityWarningKind.COERCED_CELL
                    else DbProblemKind.INTEGRITY_WARNING
                ),
                severity=ProblemSeverity.WARNING,
                message=warning.message(),
                sheet=warning.sheet,
                ref=warning.cell,
            )
        )

    unresolved = nodes.unresolved_admin_refs(keys)
    for node_id, missing_refs in unresolved.items():
        problems.append(
            DbProblem(
                kind=DbProblemKind.UNRESOLVED_ADMIN_REF,
                severity=ProblemSeverity.ERROR,
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
            if keys.find(key_ref) is None:
                problems.append(
                    DbProblem(
                        kind=DbProblemKind.UNRESOLVED_TEMPLATE_REF,
                        severity=ProblemSeverity.ERROR,
                        message=(
                            f"Template admin_nodes entry {ref!r} does not resolve to a "
                            f"{key_ref!r} row in the Keys sheet."
                        ),
                        sheet="Keys",
                        ref=ref,
                    )
                )

    for record in keys.all():
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
                    kind=DbProblemKind.WEAK_KEY,
                    severity=ProblemSeverity.CRITICAL,
                    message="malformed key material",
                    sheet="Keys",
                    ref=record.key_ref,
                )
            )
            continue
        for finding in audit.findings:
            problems.append(
                DbProblem(
                    kind=DbProblemKind.WEAK_KEY,
                    severity=ProblemSeverity.from_weak_key_severity(finding.severity),
                    message=f"{finding.check.value}: {finding.reason}",
                    sheet="Keys",
                    ref=record.key_ref,
                )
            )

    for record in keys.of_type(KeyType.ADMIN_PRIVATE):
        admin_ref = record.key_ref.removesuffix("_priv")
        if keys.find(admin_public_key_ref(admin_ref)) is None:
            continue
        if keys.private_key_mismatch(admin_ref):
            problems.append(
                DbProblem(
                    kind=DbProblemKind.ADMIN_KEY_MISMATCH,
                    # Matches weakkeys.audit_keypair's own CONSISTENCY finding
                    # severity for this exact condition -- a mismatched pair
                    # means corruption or a partial restore (firmware issue
                    # #7449), the same real-world risk either detection path
                    # reports; only private_key_mismatch is actually reachable
                    # from `mesh db verify` today, but that shouldn't make it
                    # a lesser finding.
                    severity=ProblemSeverity.CRITICAL,
                    message=(
                        f"{record.key_ref} does not derive "
                        f"{admin_public_key_ref(admin_ref)}; the pair is inconsistent "
                        "(corruption or a partial restore -- firmware issue #7449)."
                    ),
                    sheet="Keys",
                    ref=record.key_ref,
                )
            )

    groups = weakkeys.find_duplicate_public_keys(keys.public_key_map())
    seen_groups: set[tuple[str, ...]] = set()
    for key_ref, others in groups.items():
        group = tuple(sorted({key_ref, *others}))
        if group in seen_groups:
            continue
        seen_groups.add(group)

        node_owners: set[str] = set()
        for member_ref in group:
            member = keys.find(member_ref)
            owner = member.owner_node_id if member is not None else member_ref
            # NodeId.try_parse() alone is too permissive here: it also
            # accepts 1-7 character all-hex strings (NodeId.parse's case
            # (e), meant for lorastats/human-typed shortcuts elsewhere),
            # so a short hex-looking template label like "cafe" or
            # "face" would satisfy it and be wrongly counted as a real
            # device. schema.ref_for() only ever files a device's own
            # key under its *canonical* NodeId.hex form -- always
            # exactly 8 lowercase hex digits, zero-padded -- so the
            # round-trip check (parses, AND the parse's own canonical
            # form equals the string as-is) is what actually proves
            # "this owner IS a node id," not merely "looks hex-shaped."
            parsed = NodeId.try_parse(owner)
            if parsed is not None and parsed.hex == owner:
                node_owners.add(owner)

        rest = tuple(member_ref for member_ref in group if member_ref != group[0])
        if len(node_owners) >= 2:
            problems.append(
                DbProblem(
                    kind=DbProblemKind.DUPLICATE_PUBLIC_KEY,
                    severity=ProblemSeverity.CRITICAL,
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
                    kind=DbProblemKind.ALIAS_PUBLIC_KEY,
                    severity=ProblemSeverity.WARNING,
                    message=(
                        f"{group[0]} shares its public key with {', '.join(rest)} "
                        "(alias for the same node)."
                    ),
                    sheet="Keys",
                    ref=",".join(group),
                )
            )

    return VerifyReport(
        path=path,
        node_count=len(nodes.all()),
        key_count=len(keys.all()),
        problems=tuple(problems),
    )
