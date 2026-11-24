"""The ``mesh network`` constants are the ones docs/commands.md and the module docs state.

Each module's tunables are pinned to their documented values, and each
value, rendered from its constant, is checked to occur in the docs, so
that changing one without the other fails here.
"""

from __future__ import annotations

import re
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
_SECURITY_DOCS = (_ROOT / "docs" / "security.md").read_text(encoding="utf-8")


def _flat(text: str) -> str:
    return " ".join(text.split())


def test_the_feed_and_store_sizes() -> None:
    assert (
        lorastats_region.REGION_RAW_MAX_BYTES,
        lorastats_region.REGION_NODES_MAX_BYTES,
        lorastats_region.REGION_NODES_TTL_SECONDS,
        rawpackets.RAW_DATA_MAX_CHARS,
        rawpackets.PUBLIC_KEY_BYTES,
    ) == (128 * _MIB, 4 * _MIB, 3600.0, 1024, 32)
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


def _mib(size: int) -> str:
    return f"{size // _MIB} MiB"


def _hours(seconds: float) -> str:
    return f"{seconds / 3600:g} hours"


def _percent(share: float) -> str:
    return f"{share * 100:g} %"


def _standalone(phrase: str, docs: str) -> int:
    """Count the occurrences of ``phrase`` not inside a longer number or word."""
    pattern = r"(?<![0-9A-Za-z.])" + re.escape(_flat(phrase)) + r"(?![0-9])"
    return len(re.findall(pattern, _flat(docs)))


_RELYING = _percent(relays.RELYING_SHARE)
_SOLE = _percent(relays.SOLE_FIRST_HOP_SHARE)


@pytest.mark.parametrize(
    ("docs", "phrase"),
    [
        pytest.param(
            _NETWORK_DOCS,
            f"at most once every {refresh.NETWORK_REFRESH_INTERVAL_SECONDS / 60:g} minutes",
            id="refresh-interval",
        ),
        pytest.param(
            _NETWORK_DOCS,
            f"fetched fresh, at most {_mib(lorastats_region.REGION_RAW_MAX_BYTES)} each",
            id="region-raw-max",
        ),
        pytest.param(
            _NETWORK_DOCS,
            f"The node list is capped at {_mib(lorastats_region.REGION_NODES_MAX_BYTES)}",
            id="region-nodes-max",
        ),
        pytest.param(
            _NETWORK_DOCS,
            f"most nodes first, at most {refresh.NETWORK_DEFAULT_MAX_REGIONS}",
            id="max-regions",
        ),
        pytest.param(
            _NETWORK_DOCS, f"Bounds: {buckets.NETWORK_RETENTION_DAYS} days", id="retention"
        ),
        pytest.param(
            _NETWORK_DOCS, f"a day file at most {_mib(store.DAY_MAX_BYTES)}", id="day-max"
        ),
        pytest.param(
            _NETWORK_DOCS, f"a region at most {_mib(store.REGION_MAX_BYTES)}", id="region-max"
        ),
        pytest.param(
            _NETWORK_DOCS,
            f"all regions at most {_mib(store.STORE_MAX_TOTAL_BYTES)}",
            id="store-max",
        ),
        pytest.param(_NETWORK_DOCS, f"1 to {report.MAX_DAYS} days", id="max-days"),
        pytest.param(
            _NETWORK_DOCS,
            f"default: {report.DEFAULT_KEYS_DAYS} for `keys`, "
            f"{report.DEFAULT_TRAFFIC_DAYS} for the others",
            id="default-days",
        ),
        pytest.param(
            _NETWORK_DOCS,
            f"`high` | coverage at least {_percent(resolve.RESOLVE_MIN_COVERAGE)}, "
            f"distance at most {resolve.RESOLVE_MAX_DISTANCE_DB:g} dB",
            id="resolve-high",
        ),
        pytest.param(
            _NETWORK_DOCS,
            f"its distance (above {resolve.RESOLVE_MAX_DISTANCE_DB:g} dB) contradicts it; "
            f"or coverage at least {_percent(resolve.RESOLVE_MIN_COVERAGE)} with no rival",
            id="resolve-medium",
        ),
        pytest.param(
            _NETWORK_DOCS,
            f"at least {resolve.RESOLVE_DISTANCE_MARGIN_DB:g} dB farther",
            id="resolve-distance-margin",
        ),
        pytest.param(
            _NETWORK_DOCS,
            f"only first hop: at least {_SOLE} of at least "
            f"{relays.SOLE_FIRST_HOP_MIN_EVENTS_OURS} first-hop events",
            id="sole-first-hop-ours",
        ),
        pytest.param(
            _NETWORK_DOCS,
            f"other nodes with at least {relays.SOLE_FIRST_HOP_MIN_EVENTS} first-hop events "
            f"that went at least {_SOLE} through it",
            id="sole-first-hop-others",
        ),
        pytest.param(
            _NETWORK_DOCS,
            f"senders with at least {relays.SOLE_FIRST_HOP_MIN_EVENTS} first-hop events "
            f"({relays.SOLE_FIRST_HOP_MIN_EVENTS_OURS} for ours) that went at least {_SOLE} "
            "through one relay",
            id="sole-first-hops-graph",
        ),
        pytest.param(
            _NETWORK_DOCS,
            f"Gateways>={relays.RELYING_SHARE * 100:g}%** (gateways with at least "
            f"{relays.MIN_RELAYED} relayed receptions that got at least half",
            id="gateways-relying",
        ),
        pytest.param(
            _NETWORK_DOCS,
            f"other nodes with at least {relays.MIN_RELAYED} relayed receptions that got at "
            f"least {_RELYING} of them through it",
            id="origins-relying",
        ),
        pytest.param(
            _NETWORK_DOCS,
            f"relies on it for {_percent(impact.HIGH_SHARE)} or more",
            id="high-share",
        ),
        pytest.param(
            _NETWORK_DOCS,
            f"it carried {_percent(impact.HIGH_CARRIED)} of the region's relayed receptions; "
            f"`medium` when it carried {_percent(impact.MEDIUM_CARRIED)}, or anyone relies on "
            f"it for {_RELYING};",
            id="impact-levels",
        ),
        pytest.param(
            _NETWORK_DOCS,
            f"rely on us for {_RELYING} and {_percent(impact.HIGH_SHARE)}",
            id="fleet-relying",
        ),
        pytest.param(
            _NETWORK_DOCS,
            f"at least {impact.ONLY_GATEWAY_MIN_PACKETS} packets of which at least half",
            id="only-gateway-min-packets",
        ),
        pytest.param(
            _NETWORK_DOCS, f"each kept from {graph.MIN_OBSERVED} observations", id="min-observed"
        ),
        pytest.param(
            _NETWORK_DOCS,
            f"Only nodes with at least {graph.MIN_ORIGIN_RECEPTIONS} receptions as an origin",
            id="min-origin-receptions",
        ),
        pytest.param(_NETWORK_DOCS, f"(counted up to {graph.MAX_PATHS})", id="max-paths"),
        pytest.param(
            _NETWORK_DOCS,
            f"the newest {keys.MAX_KEY_HOURS} distinct hours it was heard in",
            id="max-key-hours",
        ),
        pytest.param(
            _SECURITY_DOCS,
            f"newest {keys.MAX_KEY_HOURS} distinct hours it was heard in (a week's worth), "
            f"kept for {buckets.NETWORK_RETENTION_DAYS} days",
            id="security-key-evidence",
        ),
        pytest.param(
            _PROVISION_DOCS,
            f"in the {_hours(maintenance.MAINTENANCE_WINDOW_SECONDS)} before a region's last "
            f"fetch (at most {_hours(maintenance.MAINTENANCE_MAX_AGE_SECONDS)} ago)",
            id="maintenance-windows",
        ),
    ],
)
def test_the_docs_state_each_value(docs: str, phrase: str) -> None:
    # Exactly once: a value inside a longer number, or repeated in another
    # sentence, would let a change to this one go unnoticed.
    assert _standalone(phrase, docs) == 1


def test_the_region_cap_is_the_http_clients_ceiling() -> None:
    """A higher cap would be clamped quietly by the client's own min()."""
    from meshprovision.cache.http import MAX_RESPONSE_BYTES
    from meshprovision.datasources.lorastats_region import REGION_RAW_MAX_BYTES

    assert REGION_RAW_MAX_BYTES <= MAX_RESPONSE_BYTES
