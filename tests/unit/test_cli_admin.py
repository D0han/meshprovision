"""Tests for meshprovision.cli.admin's table rendering."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from meshprovision.cli.main import cli
from meshprovision.crypto.weakkeys import AuditResult, WeakKeyCheck, WeakKeyFinding
from meshprovision.errors import WeakKeySeverity
from meshprovision.provisioning import admin_custody

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

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


def test_admin_list_table_column_order(
    cli_env: dict[str, str], empty_ods: Path, write_template: Callable[..., Path]
) -> None:
    env = dict(cli_env)
    env["MESHPROVISION_DB_PATH"] = str(empty_ods)
    env["MESHPROVISION_TEMPLATE_PATH"] = str(write_template(admin_nodes=[]))

    result = CliRunner().invoke(cli, ["admin", "list"], env=env, catch_exceptions=False)

    assert result.exit_code == 0
    header = next(line for line in result.stderr.splitlines() if "Ref" in line)
    assert header.split() == [
        "Ref",
        "Present",
        "Fingerprint",
        "Private",
        "held",
        "In",
        "template",
        "Node",
        "Audit",
        "Authorized",
        "on",
        "Pending",
        "on",
    ]
