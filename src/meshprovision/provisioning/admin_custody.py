"""Admin-key custody: who is configured, who is on hand, who is pending.

The compute half of what ``mesh admin list`` shows: given the template's
``admin_nodes`` plus whatever admin keys the fleet's own ``authorized_
admin_keys`` columns reveal, :func:`collect_admins` resolves each admin's
custody status (present in the ``Keys`` sheet, private half on hand, weak-
key audit result, which nodes authorize it, which of the admin's own
nodes still don't) into a plain, presentation-agnostic
:class:`AdminSummary`. :func:`build_admin_table` is the one presentation
form this module owns; ``cli/admin.py`` stays a thin wrapper that opens
the database, calls these two, and either prints the table or emits
JSON via :meth:`AdminSummary.to_json_dict`.

Serves the same purpose :mod:`meshprovision.status.report`/
:mod:`meshprovision.status.render`'s two-module split does for node
status -- keep compute and presentation separate from the CLI's argument
parsing and I/O orchestration, so either half can be reused or tested
without going through Click -- but deliberately as a single module
rather than a matching two-file split: the presentation surface here is
one table (``build_admin_table``) with no JSON-rendering logic of its
own (:meth:`AdminSummary.to_json_dict` lives on the compute-side
dataclass, since it is itself pure data transformation, not
``rich``-driven presentation), so a second file would be a near-empty
wrapper around one function. Unlike ``status/report.py``, this module is
not read-only-asserted -- callers of `mesh admin bootstrap`/`import` are
free to write -- but :func:`collect_admins` and :func:`build_admin_table`
themselves only ever read, taking already-open repositories rather than
opening or writing anything.

Depends only on :mod:`meshprovision.db` and :mod:`meshprovision.config.
template`, never on :mod:`meshprovision.cli` -- so this stays reusable
by any future non-CLI consumer instead of only ``cli/admin.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from rich import box
from rich.table import Table

from meshprovision.config.template import admin_public_key_ref
from meshprovision.crypto import weakkeys
from meshprovision.db.schema import KeyType
from meshprovision.errors import WeakKeySeverity
from meshprovision.nodeid import NodeId

if TYPE_CHECKING:
    from meshprovision.config.template import TemplateConfig
    from meshprovision.db.keys import KeyRepository
    from meshprovision.db.nodes import NodeRepository

__all__ = [
    "AUDIT_LABELS",
    "AUDIT_STYLES",
    "AdminSummary",
    "build_admin_table",
    "collect_admins",
]

AUDIT_LABELS: Final[MappingProxyType[WeakKeySeverity, str]] = MappingProxyType(
    {WeakKeySeverity.CRITICAL: "compromised", WeakKeySeverity.WARNING: "warning"}
)
"""Display label for the ``Audit`` column, by highest finding severity."""

AUDIT_STYLES: Final[MappingProxyType[WeakKeySeverity, str]] = MappingProxyType(
    {WeakKeySeverity.CRITICAL: "red", WeakKeySeverity.WARNING: "yellow"}
)
"""``rich`` style name applied to an admin's table row, by finding severity."""


def _audit_cell(audit: weakkeys.AuditResult | None) -> tuple[str, str | None]:
    """Render an admin's weak-key audit as a table cell and a row style.

    Args:
        audit: The admin's audit result, or ``None`` when no public key
            row exists to audit.

    Returns:
        A ``(label, style)`` pair. ``style`` is ``None`` for the two
        unremarkable states, leaving those rows unstyled.
    """
    if audit is None:
        return "-", None
    severity = audit.severity
    if severity is None:
        return "clean", None
    return AUDIT_LABELS[severity], AUDIT_STYLES[severity]


@dataclass(frozen=True, slots=True)
class AdminSummary:
    """A configured (or fleet-discovered) admin's custody status.

    Attributes:
        ref: The admin node reference.
        key_ref: The reference's public-key row in the ``Keys`` sheet
            (``f"{ref}_pub"``).
        present: Whether a row exists at ``key_ref``.
        fingerprint: A redacted fingerprint of the public key, when
            present.
        has_private: Whether the private counterpart is also on hand.
        in_template: Whether ``ref`` appears in ``template.admin_nodes``.
        node_id: The hex node id this admin resolves to, when known.
        audit: The weak-key audit result for the public key, when
            present.
        authorized_on: Hex node ids that authorize this admin.
        pending_on: Admin-owned node ids that do NOT yet authorize this
            admin.
    """

    ref: str
    key_ref: str
    present: bool
    fingerprint: str | None
    has_private: bool
    in_template: bool
    node_id: str | None
    audit: weakkeys.AuditResult | None
    authorized_on: tuple[str, ...]
    pending_on: tuple[str, ...] = ()

    def to_json_dict(self) -> dict[str, object]:
        """Render this summary as a JSON-safe, redaction-safe dict.

        Returns:
            A mapping covering every field; ``audit`` is reduced to
            ``compromised``/``severity``/``summary`` rather than the raw
            findings, and never carries key material.
        """
        return {
            "ref": self.ref,
            "key_ref": self.key_ref,
            "present": self.present,
            "fingerprint": self.fingerprint,
            "has_private": self.has_private,
            "in_template": self.in_template,
            "node_id": self.node_id,
            "audit": (
                {
                    "compromised": self.audit.compromised,
                    "severity": self.audit.severity,
                    "summary": self.audit.summary(),
                }
                if self.audit is not None
                else None
            ),
            "authorized_on": list(self.authorized_on),
            "pending_on": list(self.pending_on),
        }


def collect_admins(
    nodes: NodeRepository,
    keys: KeyRepository,
    template: TemplateConfig,
    *,
    known_bad: frozenset[bytes],
) -> tuple[AdminSummary, ...]:
    """Build the custody summary for every configured and fleet-discovered admin.

    The reference set is ``template.admin_nodes`` (in template order),
    then every additional reference ``R`` (sorted) such that
    ``f"{R}_pub"`` exists in the ``Keys`` sheet and that key reference is
    authorized on at least one node's ``authorized_admin_keys`` -- ``R``
    is always derived from a :class:`~meshprovision.db.keys.KeyRecord`'s
    ``owner_node_id``, never by string-stripping a suffix.

    Args:
        nodes: The already-open node repository.
        keys: The already-open key repository.
        template: The validated provisioning template.
        known_bad: The loaded weak-key blocklist.

    Returns:
        One :class:`AdminSummary` per resolved reference, in the order
        described above.
    """
    all_nodes = nodes.all()
    template_refs = list(template.admin_nodes)
    template_set = set(template_refs)

    extra_refs: set[str] = set()
    for admin_public_record in keys.of_type(KeyType.ADMIN_PUBLIC):
        owner = admin_public_record.owner_node_id
        if owner in template_set:
            continue
        if any(admin_public_record.key_ref in node.authorized_admin_keys for node in all_nodes):
            extra_refs.add(owner)

    refs = [*template_refs, *sorted(extra_refs)]

    provisional: list[AdminSummary] = []
    for ref in refs:
        key_ref = admin_public_key_ref(ref)
        record = keys.find(key_ref)
        audit = (
            weakkeys.audit_public_key(
                record.material(), key_ref=record.key_ref, known_bad=known_bad
            )
            if record is not None
            else None
        )

        node_id: str | None = None
        parsed = NodeId.try_parse(ref)
        if parsed is not None and nodes.exists(parsed):
            node_id = parsed.hex
        elif record is not None:
            material = record.material()
            for node in all_nodes:
                node_pub = keys.find(node.public_key_ref)
                if node_pub is not None and node_pub.material() == material:
                    node_id = node.node_id
                    break

        authorized_on = tuple(
            sorted(node.node_id for node in all_nodes if key_ref in node.authorized_admin_keys)
        )

        provisional.append(
            AdminSummary(
                ref=ref,
                key_ref=key_ref,
                present=record is not None,
                fingerprint=record.fingerprint if record is not None else None,
                has_private=keys.has_private(ref),
                in_template=ref in template_set,
                node_id=node_id,
                audit=audit,
                authorized_on=authorized_on,
                pending_on=(),
            )
        )

    owned_nodes = {s.node_id for s in provisional if s.node_id is not None}
    finalized: list[AdminSummary] = []
    for summary in provisional:
        others = owned_nodes - ({summary.node_id} if summary.node_id is not None else set())
        pending = tuple(sorted(others - set(summary.authorized_on)))
        finalized.append(replace(summary, pending_on=pending))

    return tuple(finalized)


def build_admin_table(summaries: tuple[AdminSummary, ...]) -> Table:
    """Render admin custody summaries as a ``rich`` table.

    Args:
        summaries: The summaries to render, in display order.

    Returns:
        A ``rich.table.Table``, one row per summary, styled by weak-key
        audit severity.
    """
    table = Table(box=box.SIMPLE_HEAVY, header_style="bold")
    table.add_column("Ref")
    table.add_column("Present")
    table.add_column("Fingerprint")
    table.add_column("Private held")
    table.add_column("In template")
    table.add_column("Node")
    table.add_column("Audit")
    table.add_column("Authorized on")
    table.add_column("Pending on")
    for summary in summaries:
        audit_label, audit_style = _audit_cell(summary.audit)
        table.add_row(
            summary.ref,
            "yes" if summary.present else "no",
            summary.fingerprint or "-",
            "yes" if summary.has_private else "no",
            "yes" if summary.in_template else "no",
            summary.node_id or "-",
            audit_label,
            ", ".join(summary.authorized_on) or "-",
            ", ".join(summary.pending_on) or "-",
            style=audit_style,
        )
    return table
