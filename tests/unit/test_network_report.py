"""``mesh network``'s orchestration: our nodes from the database, exit codes."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from meshprovision.crypto.redact import fingerprint
from meshprovision.db import ods_write
from meshprovision.db.keys import KeyRecord
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import KeyType, ref_for
from meshprovision.network.keys import FindingKind, FleetKey, KeyFinding, KeyScan, Severity
from meshprovision.network.refresh import NetworkRefresh, RegionFailure
from meshprovision.network.report import FleetNode, NetworkReport, RegionReport, load_fleet
from tests.unit.network_fixtures import NOW

pytestmark = pytest.mark.unit

_KEY = hashlib.sha256(b"ours").digest()


def test_the_fleet_is_every_active_node_with_its_key_digest(empty_ods: Path) -> None:
    ods_write.write_database(
        empty_ods,
        nodes=[
            NodeRecord(node_id="ab446357", short_name="A", long_name="Alpha").to_row(),
            NodeRecord(node_id="979ed146", short_name="B", long_name="Bravo").to_row(),
            NodeRecord(
                node_id="11111111",
                short_name="Gone",
                long_name="Gone",
                archived_at=datetime(2026, 1, 1, tzinfo=UTC),
            ).to_row(),
        ],
        keys=[
            KeyRecord(
                key_ref=ref_for("ab446357", KeyType.ADMIN_PUBLIC),
                owner_node_id="ab446357",
                key_type=KeyType.ADMIN_PUBLIC,
                key_value=base64.b64encode(_KEY).decode(),
            ).to_row()
        ],
        backup=False,
    )

    fleet = load_fleet(empty_ods)

    assert fleet == (
        FleetNode("ab446357", "A", FleetKey("ab446357", fingerprint(_KEY, chars=16))),
        FleetNode("979ed146", "B", FleetKey("979ed146")),
    )


def _scan(*, critical_ours: bool = False) -> KeyScan:
    findings = (
        (KeyFinding(FindingKind.CLONE, Severity.CRITICAL, "sha256:" + "0" * 16, ("a",), True),)
        if critical_ours
        else ()
    )
    return KeyScan(seen=(), findings=findings, fleet_seen=(), derived=())


def _report(
    *fetched: float | None, failures: int = 0, critical_ours: bool = False
) -> NetworkReport:
    regions = tuple(
        RegionReport(f"R{i}", when, None, _scan(critical_ours=critical_ours))
        for i, when in enumerate(fetched)
    )
    refresh = NetworkRefresh(failures=tuple(RegionFailure("R0", "down") for _ in range(failures)))
    return NetworkReport(NOW, 1, (), regions, refresh)


@pytest.mark.parametrize(
    ("report", "crypto", "code"),
    [
        pytest.param(_report(None, None, failures=1), False, 3, id="no-data-anywhere"),
        pytest.param(_report(None, None, critical_ours=True), True, 3, id="no-data-beats-crypto"),
        pytest.param(_report(None, NOW, failures=1, critical_ours=True), True, 6, id="crypto"),
        pytest.param(_report(None, NOW, failures=1), False, 7, id="degraded"),
        pytest.param(_report(NOW), False, 0, id="ok"),
    ],
)
def test_exit_codes(report: NetworkReport, crypto: bool, code: int) -> None:
    assert report.keys_critical is crypto
    assert report.exit_code(crypto=report.keys_critical) == code


def test_without_fetching_nothing_failed() -> None:
    report = NetworkReport(NOW, 1, (), (RegionReport("R", NOW, None, _scan()),), None)

    assert report.exit_code() == 0
    assert report.start == NOW - 24 * 3600
