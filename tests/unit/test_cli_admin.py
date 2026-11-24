"""Tests for meshprovision.cli.admin's table rendering."""

from __future__ import annotations

import io
from typing import TYPE_CHECKING

import pytest
from rich.console import Console

from meshprovision.cli import admin
from meshprovision.crypto.weakkeys import AuditResult, WeakKeyCheck, WeakKeyFinding
from meshprovision.errors import SettingsError, WeakKeySeverity
from meshprovision.provisioning import admin_custody

if TYPE_CHECKING:
    pass

pytestmark = pytest.mark.unit

_CLEAN = AuditResult(findings=())
_WARNING = AuditResult(
    findings=(
        WeakKeyFinding(
            check=WeakKeyCheck.LOW_ENTROPY,
            severity=WeakKeySeverity.WARNING,
            reason="low Hamming weight",
        ),
    )
)
_CRITICAL = AuditResult(
    findings=(
        WeakKeyFinding(
            check=WeakKeyCheck.BLOCKLIST,
            severity=WeakKeySeverity.CRITICAL,
            reason="known-bad key",
        ),
    )
)


@pytest.mark.parametrize(
    ("audit", "expected"),
    [
        (None, ("-", None)),
        (_CLEAN, ("clean", None)),
        (_WARNING, ("warning", "yellow")),
        (_CRITICAL, ("compromised", "red")),
    ],
)
def test_audit_cell_maps_severity_to_a_label_and_row_style(
    audit: AuditResult | None, expected: tuple[str, str | None]
) -> None:
    assert admin_custody._audit_cell(audit) == expected


@pytest.mark.parametrize("ref", ["", "1bad start", "ADMIN 1", "ADMIN!", " "])
def test_validate_admin_ref_rejects_an_invalid_shape(ref: str) -> None:
    """Reject a malformed admin ref, shared by import and bootstrap --ref.

    Only the reserved-suffix branch (_pub/_priv/_psk) had a test before
    this.
    """
    with pytest.raises(SettingsError):
        admin._validate_admin_ref(ref)


@pytest.mark.parametrize("ref", ["observed-ab12cd34", "observed-", "observed-anything"])
def test_validate_admin_ref_rejects_the_reserved_observed_prefix(ref: str) -> None:
    """A human-chosen ref must never collide with mesh adopt's own namespace."""
    with pytest.raises(SettingsError):
        admin._validate_admin_ref(ref)


def test_validate_admin_ref_accepts_a_ref_that_merely_contains_observed() -> None:
    """Only a leading observed- is reserved; the substring elsewhere is fine."""
    admin._validate_admin_ref("pre-observed")


def test_admin_list_table_column_order() -> None:
    # An empty admin list prints "No admins found." instead, so the header is
    # read off the table itself.
    table = admin_custody.build_admin_table(())

    assert [str(column.header) for column in table.columns] == [
        "Ref",
        "Present",
        "Fingerprint",
        "Private held",
        "In template",
        "Node",
        "Audit",
        "Authorized\non",
        "Pending\non",
    ]


def test_admin_list_at_80_columns_keeps_every_id_whole_one_per_line() -> None:
    summary = admin_custody.AdminSummary(
        ref="example-admin",
        key_ref="example-admin_pub",
        present=True,
        fingerprint="sha256:091f6e9d",
        has_private=False,
        in_template=True,
        node_id="cafe0001",
        audit=None,
        authorized_on=("deadbe01", "deadbe02"),
        pending_on=("deadbe03",),
    )
    buffer = io.StringIO()

    Console(file=buffer, width=80, color_system=None).print(
        admin_custody.build_admin_table((summary,))
    )

    lines = buffer.getvalue().splitlines()
    assert all(len(line) <= 80 for line in lines)
    text = "\n".join(lines)
    for node in ("cafe0001", "deadbe01", "deadbe02", "deadbe03"):
        assert node in text
    assert not any("deadbe01" in line and "deadbe02" in line for line in lines)
