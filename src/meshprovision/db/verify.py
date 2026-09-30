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

from meshprovision.crypto import redact, weakkeys
from meshprovision.db import observed_keys, schema
from meshprovision.db.ods import IntegrityWarningKind
from meshprovision.db.schema import KeyType
from meshprovision.errors import ExitCode, KeyMaterialError, WeakKeySeverity

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
    UNIMPORTED_ADMIN_KEY = "unimported_admin_key"


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

    ``security.admin_key`` holding the *same* admin public key on many
    devices is the normal, intended fleet setup -- one admin key, many
    nodes it can administer -- not the CVE-2025-52464 vendor
    key-cloning signature, which is two *devices* sharing their own
    node-identity keypair (exactly what :func:`_check_duplicate_keys`
    detects, over each node's own ``<node_id>_pub`` row).
    :func:`_check_duplicate_observed_refs` and
    :func:`_check_unregistered_duplicate_keys` instead flag an admin key
    that is authorized on more than one node but has never been given a
    real ref via ``mesh admin import`` -- a ``UNIMPORTED_ADMIN_KEY``
    :class:`~meshprovision.db.verify.ProblemSeverity.WARNING`, not a
    CRITICAL alarm, since the shared-admin-key shape alone proves
    nothing about device cloning. :func:`_check_duplicate_observed_refs`
    looks at this by ref rather than by material: any ``observed-*`` ref
    (see :mod:`meshprovision.db.observed_keys`) appearing in
    more than one node's ``authorized_admin_keys`` is content-addressed,
    so the *same* key observed on several devices resolves to one shared
    ``Keys`` row every one of them authorizes, not several rows holding
    equal material -- the shape :func:`_check_duplicate_keys` looks for.
    :func:`_check_unregistered_duplicate_keys` folds every node's legacy
    :meth:`~meshprovision.db.nodes.NodeRecord.unregistered_admin_key_materials`
    into the same comparison -- data only a database written before the
    ``observed-*`` feature, and not yet re-adopted, still carries; a
    fresh adopt always resolves this material to a ref instead.

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
    problems: list[DbProblem] = [
        *_check_template_unavailable(template, template_error),
        *_check_permissions(path),
        *_check_integrity_warnings(warnings),
        *_check_unresolved_admin_refs(nodes, keys),
        *_check_template_refs(keys, template),
        *_check_weak_keys(keys, known_bad),
        *_check_admin_key_mismatch(keys),
        *_check_duplicate_keys(keys),
        *_check_duplicate_observed_refs(nodes),
        *_check_unregistered_duplicate_keys(nodes, keys),
    ]

    return VerifyReport(
        path=path,
        node_count=len(nodes.all()),
        key_count=len(keys.all()),
        problems=tuple(problems),
    )


def _check_template_unavailable(
    template: TemplateConfig | None, template_error: str | None
) -> list[DbProblem]:
    """Flag that the template cross-check was skipped because loading it failed."""
    if template is not None or template_error is None:
        return []
    return [
        DbProblem(
            kind=DbProblemKind.TEMPLATE_UNAVAILABLE,
            severity=ProblemSeverity.WARNING,
            message=(
                "Template cross-check skipped: the template failed to load "
                "(admin_nodes references were not verified against the Keys sheet)."
            ),
        )
    ]


def _check_permissions(path: Path) -> list[DbProblem]:
    """Flag a database file mode that is readable/writable beyond the owner."""
    if os.name != "posix":
        return []
    mode = path.stat().st_mode & 0o777
    if not mode & 0o077:
        return []
    return [
        DbProblem(
            kind=DbProblemKind.INSECURE_PERMISSIONS,
            severity=ProblemSeverity.WARNING,
            message=(
                f"Database file mode is {mode:04o}; it holds private key material "
                f"and should be 0600. Run `chmod 600 {path}`."
            ),
            ref=str(path),
        )
    ]


def _check_integrity_warnings(warnings: Sequence[IntegrityWarning]) -> list[DbProblem]:
    """Translate load-time integrity warnings (stale formulas, coerced cells) into problems."""
    return [
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
        for warning in warnings
    ]


def _check_unresolved_admin_refs(nodes: NodeRepository, keys: KeyRepository) -> list[DbProblem]:
    """Flag a node authorizing an admin key reference absent from the Keys sheet."""
    unresolved = nodes.unresolved_admin_refs(keys)
    return [
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
        for node_id, missing_refs in unresolved.items()
    ]


def _check_template_refs(keys: KeyRepository, template: TemplateConfig | None) -> list[DbProblem]:
    """Flag a template admin_nodes entry that does not resolve to a Keys sheet row."""
    if template is None:
        return []
    problems: list[DbProblem] = []
    for ref in template.admin_nodes:
        key_ref = schema.ref_for(ref, KeyType.ADMIN_PUBLIC)
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
    return problems


def _check_weak_keys(keys: KeyRepository, known_bad: frozenset[bytes]) -> list[DbProblem]:
    """Run the weak-key audit over every Keys sheet row."""
    problems: list[DbProblem] = []
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
        except KeyMaterialError as exc:
            problems.append(
                DbProblem(
                    kind=DbProblemKind.WEAK_KEY,
                    severity=ProblemSeverity.CRITICAL,
                    message=f"malformed key material: {exc.reason}",
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
    return problems


def _check_admin_key_mismatch(keys: KeyRepository) -> list[DbProblem]:
    """Flag an admin private key that does not derive its registered public key."""
    problems: list[DbProblem] = []
    for record in keys.of_type(KeyType.ADMIN_PRIVATE):
        admin_ref = record.key_ref.removesuffix("_priv")
        if keys.find(schema.ref_for(admin_ref, KeyType.ADMIN_PUBLIC)) is None:
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
                        f"{schema.ref_for(admin_ref, KeyType.ADMIN_PUBLIC)}; the pair is "
                        "inconsistent (corruption or a partial restore -- firmware issue "
                        "#7449)."
                    ),
                    sheet="Keys",
                    ref=record.key_ref,
                )
            )
    return problems


def _check_duplicate_keys(keys: KeyRepository) -> list[DbProblem]:
    """Detect cross-fleet duplicate public keys, alias-aware.

    See :func:`verify_database`'s own docstring for the full alias-vs-
    duplicate classification rationale -- this helper only implements it.
    """
    problems: list[DbProblem] = []
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
            if schema.is_canonical_node_owner(owner):
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
            # A group can legitimately mix an observed-* ref with a real
            # one here: adopt_canonical_ref() deletes the observed row as
            # soon as it registers the real one, so this state is
            # reachable only from a hand-edited file (an observed-* row
            # restored or added by hand) rather than normal operation --
            # still worth calling out explicitly, since the fix is a
            # rename, not "these are both legitimately yours."
            stale_refs = tuple(ref for ref in group if observed_keys.is_observed_ref(ref))
            stale_note = (
                f" {', '.join(stale_refs)} looks like a stale mesh-adopt-minted ref that "
                "should have been superseded by now; re-run `mesh admin import` for its "
                "real owner to clean it up."
                if stale_refs
                else ""
            )
            problems.append(
                DbProblem(
                    kind=DbProblemKind.ALIAS_PUBLIC_KEY,
                    severity=ProblemSeverity.WARNING,
                    message=(
                        f"{group[0]} shares its public key with {', '.join(rest)} "
                        f"(alias for the same node).{stale_note}"
                    ),
                    sheet="Keys",
                    ref=",".join(group),
                )
            )
    return problems


def _check_duplicate_observed_refs(nodes: NodeRepository) -> list[DbProblem]:
    """Detect an ``observed-*`` admin-key ref authorized on more than one node.

    Under the current scheme (see :mod:`meshprovision.db.
    observed_keys`/:mod:`meshprovision.provisioning.key_registry`), the
    same admin key observed on several devices resolves to the *same*
    content-addressed ``Keys`` sheet row every one of them authorizes --
    so this is not two distinct ``Keys`` rows holding equal material
    (:func:`_check_duplicate_keys`'s job, and the only shape that is
    actually the CVE-2025-52464 vendor key-cloning signature); it is one
    ``observed-*`` ref shared across more than one node's
    ``authorized_admin_keys``, which is exactly what ``security.
    admin_key`` authorized on many nodes is *supposed* to look like
    before an operator has run ``mesh admin import`` to give it a real
    ref.

    Args:
        nodes: The already-open node repository.

    Returns:
        One WARNING :class:`DbProblem` per ``observed-*`` ref authorized
        on two or more distinct nodes.
    """
    owners: dict[str, list[str]] = {}
    for record in nodes.all():
        for ref in record.authorized_admin_keys:
            if observed_keys.is_observed_ref(ref):
                owners.setdefault(ref, []).append(record.node_id)

    problems: list[DbProblem] = []
    for ref, node_ids in owners.items():
        if len(node_ids) < 2:
            continue
        sorted_ids = tuple(sorted(node_ids))
        problems.append(
            DbProblem(
                kind=DbProblemKind.UNIMPORTED_ADMIN_KEY,
                severity=ProblemSeverity.WARNING,
                message=(
                    f"Admin key {ref} is authorized, under the same observed ref, on "
                    f"{len(sorted_ids)} nodes ({', '.join(sorted_ids)}) but has not been "
                    "imported; run `mesh admin import` to give it a real ref."
                ),
                sheet="Nodes",
                ref=",".join(sorted_ids),
            )
        )
    return problems


def _check_unregistered_duplicate_keys(
    nodes: NodeRepository, keys: KeyRepository
) -> list[DbProblem]:
    """Detect an unimported admin key shared by more than one node.

    :func:`_check_duplicate_keys` only ever compares ``Keys`` sheet rows,
    so an admin key that ``mesh adopt`` observed but nobody ran ``mesh
    admin import`` on is invisible to it. This walks every node's legacy
    :meth:`~meshprovision.db.nodes.NodeRecord.unregistered_admin_key_materials`
    (data only a database written before the ``observed-*`` feature, and
    not yet re-adopted, still carries) and unions it with every node
    that *authorizes* the same raw material under a real ``Keys`` sheet
    ref, grouping by the key's own material rather than by node pair: an
    admin key N nodes hold -- whether unregistered on all of them, or
    unregistered on some and already registered under one real ref -- is
    one fleet-wide fact ("this key needs importing"), not one finding
    per pairwise combination of the nodes that hold it.

    Args:
        nodes: The already-open node repository.
        keys: The already-open key repository.

    Returns:
        One WARNING :class:`DbProblem` per distinct key material shared
        by two or more nodes, where at least one of those nodes has the
        material unregistered.
    """
    public_keys = keys.public_key_map()
    records = nodes.all()
    unregistered_owners: dict[bytes, set[str]] = {}
    registered_owners: dict[bytes, set[str]] = {}
    for record in records:
        for material in record.unregistered_admin_key_materials():
            unregistered_owners.setdefault(material, set()).add(record.node_id)
        for ref in record.authorized_admin_keys:
            registered_material = public_keys.get(ref)
            if registered_material is not None:
                registered_owners.setdefault(registered_material, set()).add(record.node_id)

    problems: list[DbProblem] = []
    for material, unregistered_ids in unregistered_owners.items():
        node_ids = unregistered_ids | registered_owners.get(material, set())
        if len(node_ids) < 2:
            continue
        fingerprint = redact.fingerprint(material)
        sorted_ids = tuple(sorted(node_ids))
        problems.append(
            DbProblem(
                kind=DbProblemKind.UNIMPORTED_ADMIN_KEY,
                severity=ProblemSeverity.WARNING,
                message=(
                    f"Admin key {fingerprint} is authorized on {len(sorted_ids)} nodes "
                    f"({', '.join(sorted_ids)}) but has not been imported; run `mesh admin "
                    "import` to give it a real ref."
                ),
                sheet="Nodes",
                ref=",".join(sorted_ids),
            )
        )
    return problems
