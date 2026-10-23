"""``HealthRefresher``: bring our nodes' health histories up to date, within a request budget.

**Request budget, per node.** A refresh costs two lorastats requests
(``PacketReports`` and ``PacketsParsed``, both from ``since``) plus, only
when asked for (``mesh health NODE``), one gateway check, at most once per
:data:`GATEWAY_CHECK_INTERVAL_SECONDS`. A node is refreshed at most once
per :data:`REFRESH_INTERVAL_SECONDS` (once per
:data:`FORCED_REFRESH_INTERVAL_SECONDS`, the lorastats TTL floor, when
forced), counted from the refresh stored in its history and, within one
process (a ``--watch`` loop), from the last one this refresher made even
when it could not be stored. A node without a known lorastats region is
never asked about: no region is looked for here. So ``N`` due nodes cost at
most ``2 N`` requests (``3 N`` with gateway checks), plus the client's
retries of a failed request; a 429 answer makes the client refuse every
further request to lorastats.pl for its cool-down.

**Incremental, idempotent.** Each refresh asks from one hour before the
start of the hour of the previous refresh (the extra hour absorbs a
misread Warsaw time around a DST change) and replaces that hour onwards
(see :func:`~meshprovision.health.history.merge`), so nothing is counted
twice. A failed request leaves the history as it was and is reported.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from meshprovision.datasources.lorastats import LORASTATS_MIN_TTL_SECONDS
from meshprovision.errors import DataSourceError, NodeIdError
from meshprovision.health.history import (
    HOUR_SECONDS,
    GatewayCheck,
    NodeHistory,
    merge,
    replace_from,
    summarize,
    with_boot,
    with_gateway_check,
)
from meshprovision.health.packets import FUTURE_SKEW_SECONDS, parse_decoded, parse_receptions
from meshprovision.nodeid import NodeId

if TYPE_CHECKING:
    from meshprovision.datasources.lorastats_packets import LorastatsPackets
    from meshprovision.health.store import HistoryStore

__all__ = [
    "FORCED_REFRESH_INTERVAL_SECONDS",
    "GATEWAY_CHECK_INTERVAL_SECONDS",
    "GATEWAY_CHECK_WINDOW_SECONDS",
    "REFRESH_INTERVAL_SECONDS",
    "SINCE_MARGIN_SECONDS",
    "STATUS_REFRESH_INTERVAL_SECONDS",
    "HealthRefresher",
    "RefreshFailure",
    "RefreshOutcome",
]

_logger = logging.getLogger(__name__)

REFRESH_INTERVAL_SECONDS: Final[float] = 600.0
"""A node's history is refreshed at most once per this (10 minutes)."""

FORCED_REFRESH_INTERVAL_SECONDS: Final[float] = LORASTATS_MIN_TTL_SECONDS
"""When forced, at most once per this (lorastats' 60 s TTL floor)."""

STATUS_REFRESH_INTERVAL_SECONDS: Final[float] = 3600.0
"""``mesh status`` (without ``--detail full``) refreshes a history older than this."""

GATEWAY_CHECK_INTERVAL_SECONDS: Final[float] = 3600.0
"""A node's gateway check is repeated at most once per this."""

GATEWAY_CHECK_WINDOW_SECONDS: Final[float] = 3600.0
"""How far back a gateway check asks."""

SINCE_MARGIN_SECONDS: Final[float] = HOUR_SECONDS
"""How much earlier than needed a refresh asks from (one hour, for DST)."""


@dataclass(frozen=True, slots=True)
class RefreshFailure:
    """A node whose refresh failed.

    Attributes:
        node: The node.
        message: The error's message.
        hint: The error's hint, when it has one.
    """

    node: NodeId
    message: str
    hint: str | None = None


@dataclass(frozen=True, slots=True)
class RefreshOutcome:
    """What one :meth:`HealthRefresher.refresh` call did.

    Attributes:
        histories: Every node's history after it, refreshed or not.
        refreshed: The nodes lorastats was asked about.
        no_region: The nodes without a known lorastats region.
        failures: The nodes whose refresh failed.
        skipped_rows: Rows that could not be used.
    """

    histories: Mapping[NodeId, NodeHistory]
    refreshed: tuple[NodeId, ...] = ()
    no_region: tuple[NodeId, ...] = ()
    failures: tuple[RefreshFailure, ...] = ()
    skipped_rows: int = 0


class HealthRefresher:
    """Refreshes histories through one :class:`~meshprovision.health.store.HistoryStore`."""

    def __init__(
        self,
        store: HistoryStore,
        packets: LorastatsPackets,
        *,
        force: bool = False,
        interval: float | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """Initialize the refresher. Keep one per process, to keep its refresh times.

        Args:
            store: Where the histories are kept.
            packets: What fetches the rows.
            force: Refresh once per :data:`FORCED_REFRESH_INTERVAL_SECONDS`
                instead of :data:`REFRESH_INTERVAL_SECONDS`.
            interval: Refresh once per this many seconds instead (wins over
                ``force``).
            clock: Callable returning the current unix epoch seconds.
        """
        self._store = store
        self._interval = interval
        self._packets = packets
        self._force = force
        self._clock = clock
        self._refreshed_at: dict[NodeId, float] = {}
        self._checked_at: dict[NodeId, float] = {}

    def refresh(
        self,
        nodes: Iterable[tuple[NodeId, str | None]],
        *,
        boots: Mapping[NodeId, float] | None = None,
        gateway_check: bool = False,
    ) -> RefreshOutcome:
        """Refresh every due node and record the boot times given.

        Args:
            nodes: ``(node, lorastats region or None)`` pairs.
            boots: Boot times (lorastats ``LastBoot``) to record.
            gateway_check: Also check what each node uplinked as a gateway.

        Returns:
            What was done, with every node's history.
        """
        histories: dict[NodeId, NodeHistory] = {}
        refreshed: list[NodeId] = []
        no_region: list[NodeId] = []
        failures: list[RefreshFailure] = []
        skipped = 0
        for node, region in nodes:
            history = self._store.load(node)
            boot = (boots or {}).get(node)
            update: Callable[[NodeHistory], NodeHistory] | None = None
            if boot is not None and boot not in history.boots:
                update = _with_boot(boot)
            if region is None:
                no_region.append(node)
            elif self._due(node, history):
                try:
                    fetched, rows_skipped = self._fetch(node, region, history)
                except DataSourceError as exc:
                    failures.append(RefreshFailure(node, exc.message, exc.hint))
                    _logger.warning("lorastats packets for %s failed: %s", node.hex, exc.message)
                else:
                    refreshed.append(node)
                    skipped += rows_skipped
                    update = _then(update, fetched)
            if region is not None and gateway_check and self._check_due(node, history):
                try:
                    check = self._gateway_check(node, region)
                except DataSourceError as exc:
                    failures.append(RefreshFailure(node, exc.message, exc.hint))
                else:
                    update = _then(update, _with_check(check))
            if update is not None:
                history = self._store.update(node, update)
            histories[node] = history
        return RefreshOutcome(
            histories=histories,
            refreshed=tuple(refreshed),
            no_region=tuple(no_region),
            failures=tuple(failures),
            skipped_rows=skipped,
        )

    def _due(self, node: NodeId, history: NodeHistory) -> bool:
        """Tell whether ``node`` may be refreshed now."""
        now = self._clock()
        interval = self._interval
        if interval is None:
            interval = FORCED_REFRESH_INTERVAL_SECONDS if self._force else REFRESH_INTERVAL_SECONDS
        times = [t for t in (history.fetched_at, self._refreshed_at.get(node)) if t is not None]
        times = [t for t in times if t <= now + FUTURE_SKEW_SECONDS]
        return not times or now - max(times) >= interval

    def _check_due(self, node: NodeId, history: NodeHistory) -> bool:
        """Tell whether ``node``'s gateway check may be repeated now."""
        now = self._clock()
        times = [c.time for c in history.gateway_checks]
        if node in self._checked_at:
            times.append(self._checked_at[node])
        times = [t for t in times if t <= now + FUTURE_SKEW_SECONDS]
        return not times or now - max(times) >= GATEWAY_CHECK_INTERVAL_SECONDS

    def _fetch(
        self, node: NodeId, region: str, history: NodeHistory
    ) -> tuple[Callable[[NodeHistory], NodeHistory], int]:
        """Fetch the rows of ``node`` since its previous refresh.

        Returns:
            The change to apply to its stored history, and how many rows
            could not be used.

        Raises:
            meshprovision.errors.DataSourceError: If a request fails.
        """
        now = self._clock()
        self._refreshed_at[node] = now
        since = replace_from(history, now=now)
        asked = None if since is None else since - SINCE_MARGIN_SECONDS
        report_rows = self._packets.reports(node, region, since=asked)
        decoded_rows = self._packets.decoded(node, region, since=asked)
        receptions, skipped_reports = parse_receptions(report_rows, node, now=now)
        decoded, skipped_decoded = parse_decoded(decoded_rows, node, now=now)
        new = summarize(node, receptions, decoded, since=since, fetched_at=now)
        _logger.info(
            "lorastats: %d reception(s), %d decoded packet(s) for %s",
            len(receptions),
            len(decoded),
            node.hex,
        )
        return (lambda old: merge(old, new)), skipped_reports + skipped_decoded

    def _gateway_check(self, node: NodeId, region: str) -> GatewayCheck:
        """Count what ``node`` uplinked as a gateway in the last check window.

        Raises:
            meshprovision.errors.DataSourceError: If the request fails.
        """
        now = self._clock()
        self._checked_at[node] = now
        rows = self._packets.uplinked(node, region, since=now - GATEWAY_CHECK_WINDOW_SECONDS)
        senders = {sender for sender in map(_sender, rows) if sender is not None}
        return GatewayCheck(now, GATEWAY_CHECK_WINDOW_SECONDS, len(rows), len(senders))


def _sender(row: Any) -> str | None:
    """Return the canonical hex id of a report row's ``FromNode``, else ``None``."""
    raw = row.get("FromNode") if isinstance(row, dict) else None
    if not isinstance(raw, str):
        return None
    try:
        return NodeId.from_hex(raw).hex
    except NodeIdError:
        return None


def _with_boot(boot: float) -> Callable[[NodeHistory], NodeHistory]:
    """Build the change that records a boot time."""
    return lambda history: with_boot(history, boot)


def _with_check(check: GatewayCheck) -> Callable[[NodeHistory], NodeHistory]:
    """Build the change that records a gateway check."""
    return lambda history: with_gateway_check(history, check)


def _then(
    first: Callable[[NodeHistory], NodeHistory] | None, second: Callable[[NodeHistory], NodeHistory]
) -> Callable[[NodeHistory], NodeHistory]:
    """Chain two history changes (the first may be absent)."""
    if first is None:
        return second
    return lambda history: second(first(history))
