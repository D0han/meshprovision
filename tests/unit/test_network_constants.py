"""The ``mesh network`` constants are the ones docs/commands.md and the module docs state.

Each module's tunables are pinned to their documented values, and each
value's wording in ``docs/commands.md`` is checked to be there, so that
changing one without the other fails here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from meshprovision.datasources import lorastats_region
from meshprovision.network import (
    buckets,
    graph,
    impact,
    keys,
    keystore,
    maintenance,
    rawpackets,
    refresh,
    relays,
    report,
    resolve,
    store,
)

pytestmark = pytest.mark.unit

_MIB = 1024 * 1024
_ROOT = Path(__file__).resolve().parents[2]
_DOCS = (_ROOT / "docs" / "commands.md").read_text(encoding="utf-8")
_NETWORK_DOCS = _DOCS[_DOCS.index("## `mesh network`") : _DOCS.index("## `mesh admin`")]
_PROVISION_DOCS = _DOCS[_DOCS.index("## `mesh provision`") : _DOCS.index("## `mesh adopt`")]


def _flat(text: str) -> str:
    return " ".join(text.split())


def test_the_feed_and_store_sizes() -> None:
    assert (
        lorastats_region.REGION_RAW_MAX_BYTES,
        lorastats_region.REGION_NODES_MAX_BYTES,
        lorastats_region.REGION_NODES_TTL_SECONDS,
        rawpackets.RAW_DATA_MAX_CHARS,
        rawpackets.PUBLIC_KEY_BYTES,
    ) == (48 * _MIB, 4 * _MIB, 3600.0, 1024, 32)
    assert (
        buckets.NETWORK_RETENTION_DAYS,
        store.DAY_MAX_BYTES,
        store.REGION_MAX_BYTES,
        store.STORE_MAX_TOTAL_BYTES,
        store.LEARNED_RELAY_MAX_AGE_SECONDS,
        keystore.KEYS_MAX_BYTES,
        keys.KEY_DIGEST_CHARS,
        keys.MAX_KEY_HOURS,
    ) == (30, 8 * _MIB, 64 * _MIB, 256 * _MIB, 7 * 24 * 3600.0, 2 * _MIB, 16, 168)


def test_the_request_budget_and_windows() -> None:
    assert (
        refresh.NETWORK_REFRESH_INTERVAL_SECONDS,
        refresh.NETWORK_FORCED_REFRESH_INTERVAL_SECONDS,
        refresh.NETWORK_DEFAULT_MAX_REGIONS,
        report.DEFAULT_KEYS_DAYS,
        report.DEFAULT_TRAFFIC_DAYS,
        report.MAX_DAYS,
    ) == (900.0, 60.0, 4, 30, 1, 30)


def test_the_relay_resolution_thresholds() -> None:
    assert (
        resolve.RESOLVE_MIN_COVERAGE,
        resolve.RESOLVE_MAX_DISTANCE_DB,
        resolve.RESOLVE_COVERAGE_MARGIN,
        resolve.RESOLVE_DISTANCE_MARGIN_DB,
        resolve.RESOLVE_MAX_GATEWAY_WEIGHT,
        resolve.RESOLVE_MIN_GATEWAY_RECEPTIONS,
    ) == (0.5, 4.0, 3.0, 4.0, 50, 2)


def test_the_dependence_thresholds() -> None:
    assert (
        relays.SOLE_FIRST_HOP_SHARE,
        relays.SOLE_FIRST_HOP_MIN_EVENTS,
        relays.SOLE_FIRST_HOP_MIN_EVENTS_OURS,
        relays.MIN_RELAYED,
        relays.RELYING_SHARE,
    ) == (0.9, 20, 5, 20, 0.5)
    assert (
        impact.HIGH_SHARE,
        impact.HIGH_CARRIED,
        impact.MEDIUM_CARRIED,
        impact.ONLY_GATEWAY_SHARE,
        impact.ONLY_GATEWAY_MIN_PACKETS,
    ) == (0.8, 0.10, 0.03, 0.5, 5)
    assert (graph.MIN_OBSERVED, graph.MIN_ORIGIN_RECEPTIONS, graph.MAX_PATHS) == (2, 20, 4)


def test_the_maintenance_warning_windows() -> None:
    assert (
        maintenance.MAINTENANCE_MAX_AGE_SECONDS,
        maintenance.MAINTENANCE_WINDOW_SECONDS,
    ) == (48 * 3600.0, 24 * 3600.0)


@pytest.mark.parametrize(
    "phrase",
    [
        "at most once every 15 minutes (once a minute with `--refresh`)",
        "at most 48 MiB each",
        "The node list is capped at 4 MiB",
        "at least an hour",
        "the region of most nodes first, at most 4",
        (
            "Bounds: 30 days; a day file at most 8 MiB, a region at most 64 MiB, "
            "all regions at most 256 MiB"
        ),
        (
            "`--days N` | Window of the stored data, 1 to 30 days "
            "(default: 30 for `keys`, 1 for the others)"
        ),
        (
            "coverage at least 50 %, distance at most 4 dB, and every other candidate "
            "covers less than a third of that or is at least 4 dB farther"
        ),
        "resolved `high` in the last week",
        "at least 90 % of at least 5 first-hop events",
        "gateways with at least 20 relayed receptions that got at least half of them through it",
        "other nodes with at least 20 relayed receptions that got at least 50 % of them through it",
        "other nodes with at least 20 first-hop events that went at least 90 % through it",
        "other nodes with at least 5 packets of which at least half were uplinked by it alone",
        "relies on it for 80 % or more",
        "it carried 10 % of the region's relayed receptions; `medium` when it carried 3 %",
        "each kept from 2 observations",
        "senders with at least 20 first-hop events (5 for ours)",
        "Only nodes with at least 20 receptions as an origin are counted as cut off",
        "(counted up to 4)",
        "the newest 168 distinct hours it was heard in",
    ],
)
def test_the_network_docs_state_these_values(phrase: str) -> None:
    assert _flat(phrase) in _flat(_NETWORK_DOCS)


def test_the_security_docs_state_how_long_key_evidence_lasts() -> None:
    security = (_ROOT / "docs" / "security.md").read_text(encoding="utf-8")

    assert "newest 168 distinct hours it was heard in (a week's worth), kept for 30 days" in (
        _flat(security)
    )


def test_the_provision_docs_state_the_maintenance_windows() -> None:
    text = _flat(_PROVISION_DOCS)

    assert "in the 24 hours before a region's last fetch (at most 48 hours ago)" in text
    assert "was `medium` or `high`" in text
