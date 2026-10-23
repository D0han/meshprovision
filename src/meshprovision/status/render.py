"""Presentation for a :class:`~meshprovision.status.report.StatusReport`.

Two output forms, and nothing else: a ``rich`` terminal table
(:func:`build_table`, :func:`render_console`) and a stable JSON
serialization (:func:`report_to_json_dict`, :func:`render_json`). This
module imports nothing that can write anything -- it only ever reads a
:class:`~meshprovision.status.report.StatusReport` and either builds a
``rich`` renderable or returns a string.

:func:`render_console` is the only function in this module permitted to
touch a ``Console`` -- so that ``mesh status --json`` can call
:func:`render_json` and ``click.echo`` the result with nothing else ever
written to stdout.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from rich import box
from rich.console import Console, JustifyMethod, RenderableType
from rich.table import Table
from rich.text import Text

from meshprovision.status import timefmt
from meshprovision.status.cadence import Cadence, CadenceSource, interval_text
from meshprovision.status.merge import Availability, MergedNode, Thresholds, humanize_age
from meshprovision.status.report import StatusReport
from meshprovision.status.trend import NodeTrends, Trend
from meshprovision.termsafe import json_dumps_safe, terminal_safe

if TYPE_CHECKING:
    from meshprovision.nodeid import NodeId

__all__ = [
    "AGE_STYLES",
    "AVAILABILITY_LABELS",
    "BRIEF_COLUMNS",
    "DEFAULT_HIDDEN_COLUMNS",
    "ExtraColumns",
    "age_style",
    "build_table",
    "every_cell",
    "render_console",
    "render_json",
    "report_to_json_dict",
]

AGE_STYLES: Final[tuple[tuple[timedelta, str], ...]] = (
    (timedelta(hours=24), "green"),
    (timedelta(days=2), "yellow"),
    (timedelta(days=7), "dark_orange"),
)
"""``rich`` style by how recent a timestamp is: ``(max_age, style)``, ascending.

A timestamp within ``max_age`` (inclusive) gets that tier's style; the
first matching tier wins.
"""

_OLDEST_STYLE: Final[str] = "red"
"""Style for a timestamp older than the last tier of :data:`AGE_STYLES`."""

_UNKNOWN_STYLE: Final[str] = "grey50"
"""Style for a value or timestamp that is unknown (never seen, no timestamp)."""

_ALARM_STYLE: Final[str] = "bold red"
"""Style for a value that needs attention now (see the ``*_THRESHOLD`` constants)."""

_WARN_STYLE: Final[str] = "bold dark_orange"
"""Style for a value that is suspicious or getting there."""

BATTERY_ALARM_PERCENT: Final[int] = 10
BATTERY_WARN_PERCENT: Final[int] = 20
VOLTAGE_ALARM_VOLTS: Final[float] = 3.3
VOLTAGE_WARN_VOLTS: Final[float] = 3.5
CHANNEL_UTILIZATION_ALARM_PERCENT: Final[float] = 40.0
CHANNEL_UTILIZATION_WARN_PERCENT: Final[float] = 25.0
AIR_UTIL_TX_ALARM_PERCENT: Final[float] = 10.0
AIR_UTIL_TX_WARN_PERCENT: Final[float] = 5.0
UPTIME_WARN_BELOW: Final[timedelta] = timedelta(hours=1)
"""Thresholds past which a table cell is drawn in the alarm or warning style.

Heuristics, not firmware limits: a battery at or below 10% / 20%, a cell
voltage below 3.3 V / 3.5 V, channel utilization above 40% / 25%,
transmit air utilization above 10% (the common duty-cycle ceiling) / 5%,
an uptime under an hour (a recent reboot). Boundaries are exclusive of the
healthy side: exactly the warn value is not flagged for the "above"
checks and is flagged for the "at or below" battery checks.
"""


_SEEN_BY_HEADER: Final[str] = "Seen By\n1d/7d/30d"

BRIEF_COLUMNS: Final[frozenset[str]] = frozenset(
    {"Node", "Short", "Status", "Last seen", "Batt", _SEEN_BY_HEADER, "Uptime"}
)
"""The columns ``mesh status --detail brief`` keeps: which node, whether and when it
was last heard, its battery, whether gateways still relay it, and whether it rebooted."""


DEFAULT_HIDDEN_COLUMNS: Final[frozenset[str]] = frozenset({"Node", "Mgmt"})
"""The columns ``mesh status --detail default`` leaves out: the names identify a node,
and the management mode is in ``--json`` and ``--detail full``."""

_TREND_ARROWS: Final[Mapping[Trend, tuple[str, str]]] = MappingProxyType(
    {
        Trend.UP: ("\u2191", "green"),
        Trend.DOWN: ("\u2193", "red"),
        Trend.FLAT: ("~", "yellow"),
    }
)
"""The arrow and its style that follow a reading that went up, down or stayed."""


@dataclass(frozen=True, slots=True)
class ExtraColumns:
    """Columns appended to the table (``mesh status --detail full``).

    Attributes:
        headers: ``(header, justify)`` of each column.
        cells: Each node's cells, one per header.
        caption: More caption lines, when any.
    """

    headers: Sequence[tuple[str, JustifyMethod]]
    cells: Mapping[NodeId, Sequence[RenderableType]]
    caption: Text | None = None


def _stretched_tiers(thresholds: Thresholds) -> tuple[tuple[timedelta, str], ...]:
    """Stretch :data:`AGE_STYLES` to a node's own thresholds.

    Args:
        thresholds: The node's thresholds.

    Returns:
        The green tier up to at least ``stale_after`` and the yellow tier up
        to at least ``offline_after`` (which leaves the orange tier empty
        when ``offline_after`` is longer than it), the rest as they are.
    """
    (green_age, green), (yellow_age, yellow), *rest = AGE_STYLES
    return (
        (max(green_age, thresholds.stale_after), green),
        (max(yellow_age, thresholds.offline_after), yellow),
        *rest,
    )


def age_style(age: timedelta | None, thresholds: Thresholds | None = None) -> str:
    """Pick a ``rich`` style from how long ago a timestamp was.

    Used for the ``Last seen`` and ``Timestamp`` cells (the node's last
    activity) and for the device-metrics cells (how old the battery,
    voltage and utilization readings are). With ``thresholds`` (the
    node's own), a node expected to be heard rarely keeps its colors
    longer: green at least until it is stale, yellow at least until it
    is offline.

    Args:
        age: ``now - timestamp``, or ``None`` when the timestamp is unknown.
        thresholds: The node's thresholds, or ``None`` for the fixed tiers.

    Returns:
        ``green`` within 24 hours, ``yellow`` within 2 days, ``dark_orange``
        within a week (each tier stretched to ``thresholds``), ``red``
        beyond that, and gray for ``None``.
    """
    if age is None:
        return _UNKNOWN_STYLE
    tiers = AGE_STYLES if thresholds is None else _stretched_tiers(thresholds)
    for max_age, style in tiers:
        if age <= max_age:
            return style
    return _OLDEST_STYLE


AVAILABILITY_LABELS: Final[MappingProxyType[Availability, str]] = MappingProxyType(
    {
        Availability.ONLINE: "online",
        Availability.STALE: "stale",
        Availability.OFFLINE: "offline",
        Availability.UNKNOWN: "unknown",
    }
)
"""Display label for the ``Status`` column, by availability."""

_AVAILABILITY_STYLES: Final[MappingProxyType[Availability, str]] = MappingProxyType(
    {
        Availability.ONLINE: "green",
        Availability.STALE: "yellow",
        Availability.OFFLINE: "red",
        Availability.UNKNOWN: _UNKNOWN_STYLE,
    }
)

_DASH: Final[str] = "-"

_POWERED_BATTERY_THRESHOLD: Final[int] = 100
"""A Meshtastic ``battery_level`` above this means external power, not a percentage."""

_LAST_BOOT_TOLERANCE: Final[timedelta] = timedelta(minutes=65)
"""How much longer than the device's own uptime the time from ``LastBoot`` to
its metrics may be before that ``LastBoot`` counts as contradicted (a newer
reboot). Over an hour, so a one-hour DST error in lorastats' naive Warsaw
``LastBoot`` never trips it."""


def _text_cell(value: str | None) -> str:
    """Render an optional string cell, never as the literal ``"None"``.

    Args:
        value: The cell's value, or ``None``/blank. May be sourced from
            a datasource or a live device, so it is passed through
            :func:`~meshprovision.termsafe.terminal_safe` before display.

    Returns:
        ``value``, terminal-escaped, when truthy; otherwise :data:`_DASH`.
    """
    return terminal_safe(value) if value else _DASH


def _int_cell(value: int | None) -> str:
    """Render an optional integer cell.

    Args:
        value: The cell's value, or ``None``.

    Returns:
        ``str(value)``, or :data:`_DASH` when ``value`` is ``None``.
    """
    return _DASH if value is None else str(value)


def _battery_cell(value: int | None) -> str:
    """Render an optional battery-percentage cell.

    Args:
        value: The battery level percentage, or ``None``. Meshtastic
            reports a level above 100 (101) for a node on external power.

    Returns:
        ``"powered"`` above :data:`_POWERED_BATTERY_THRESHOLD`,
        ``f"{value}%"`` otherwise, or :data:`_DASH` when ``value`` is
        ``None`` or not above 0 (no reading: a node without a battery
        sensor reports 0, as it reports 0 V).
    """
    if value is None or value <= 0:
        return _DASH
    if value > _POWERED_BATTERY_THRESHOLD:
        return "powered"
    return f"{value}%"


def _voltage_cell(value: float | None) -> str:
    """Render an optional voltage cell.

    Args:
        value: The voltage, or ``None``.

    Returns:
        ``f"{value:.2f}V"``, or :data:`_DASH` when ``value`` is ``None``.
    """
    return _DASH if value is None else f"{value:.2f}V"


def _percent_cell(value: float | None) -> str:
    """Render an optional one-decimal percentage cell.

    Args:
        value: The percentage, or ``None``.

    Returns:
        ``f"{value:.1f}%"``, or :data:`_DASH` when ``value`` is ``None``.
    """
    return _DASH if value is None else f"{value:.1f}%"


def _timestamp_cell(value: datetime | None, *, reference: datetime) -> str:
    """Render an optional timestamp cell in the machine's local timezone.

    Args:
        value: The timestamp, or ``None``.
        reference: The instant the column header's own zone abbreviation
            was taken from (``report.generated_at``) -- compared against
            ``value``'s own zone to decide whether this cell needs to
            state its zone explicitly.

    Returns:
        For example ``"2026-08-25 05:14:10"`` when ``value`` shares
        ``reference``'s local zone (the header already states it), or
        ``"2026-08-25 05:14:10 CET"`` when it doesn't (a long-offline
        node whose ``last_seen`` falls on the other side of a DST
        transition from ``reference``) -- a shared header-only zone
        would otherwise be silently false for that row, and would
        collapse two instants an hour apart during a repeated
        (DST-fallback) hour into an identical-looking string, since
        exactly one side of that transition still matches the header
        and states nothing further. :data:`_DASH` when ``value`` is
        ``None``. Always the full date/time form (no same-day
        shortening: unlike the summary caption's ``data as of`` clause,
        table rows have no single shared reference date to collapse
        against). See Round 35's status-reporting review, Finding 1,
        and the follow-up discussion that led to this hybrid form.
    """
    if value is None:
        return _DASH
    differs = timefmt.local_tz_abbreviation(value) != timefmt.local_tz_abbreviation(reference)
    return timefmt.format_local(value, include_zone=differs)


def _cell(text: str, style: str | None) -> Text:
    """Build a styled cell.

    Args:
        text: The already-rendered, terminal-safe cell text.
        style: A ``rich`` style, or ``None`` for the default style.

    Returns:
        The cell as a :class:`~rich.text.Text`.
    """
    return Text(text, style=style or "")


def _value_cell(text: str, *, flag: str | None, freshness: str) -> Text:
    """Build a measured-value cell: an alarm/warning style wins over freshness.

    Args:
        text: The rendered value, or :data:`_DASH` when unknown.
        flag: :data:`_ALARM_STYLE` / :data:`_WARN_STYLE` when the value
            itself is alarming or suspicious, else ``None``.
        freshness: The :func:`age_style` of the reading's timestamp.

    Returns:
        A dim hyphen when the value is unknown, else the cell styled by
        ``flag`` if set, otherwise by ``freshness``.
    """
    if text == _DASH:
        return _cell(text, _UNKNOWN_STYLE)
    return _cell(text, flag or freshness)


def _severity(value: float | None, *, alarm: float, warn: float, low_is_bad: bool) -> str | None:
    """Pick the alarm/warning style for a measured value.

    Args:
        value: The measurement, or ``None`` (never flagged).
        alarm: The alarm threshold.
        warn: The warning threshold.
        low_is_bad: ``True`` when a value at or below the threshold is the
            bad side (battery, voltage); ``False`` when a value above the
            threshold is (utilization).

    Returns:
        :data:`_ALARM_STYLE`, :data:`_WARN_STYLE` or ``None``.
    """
    if value is None:
        return None
    if low_is_bad:
        return _ALARM_STYLE if value <= alarm else _WARN_STYLE if value <= warn else None
    return _ALARM_STYLE if value > alarm else _WARN_STYLE if value > warn else None


def _battery_flag(value: int | None) -> str | None:
    """Flag a low battery; external power or no reading (0 or less) is never flagged."""
    if value is None or value <= 0 or value > _POWERED_BATTERY_THRESHOLD:
        return None
    return _severity(value, alarm=BATTERY_ALARM_PERCENT, warn=BATTERY_WARN_PERCENT, low_is_bad=True)


def _voltage_flag(value: float | None) -> str | None:
    """Flag a low cell voltage (a reading of 0 V is an absent sensor, not a flat battery)."""
    if value is None or value <= 0:
        return None
    return _severity(value, alarm=VOLTAGE_ALARM_VOLTS, warn=VOLTAGE_WARN_VOLTS, low_is_bad=True)


def _seen_by_cell(counts: tuple[int, int, int] | None) -> Text:
    """Render the ``Seen By`` cell as ``day/week/month`` gateway counts.

    Args:
        counts: :attr:`~meshprovision.status.merge.MergedNode.seen_by_counts`.

    Returns:
        ``"x/y/z"`` -- gateway topics that relayed the node within the last
        1 / 7 / 30 days -- in the alarm style when no gateway relayed it
        in 30 days, in the warning style when none did in 7 days, or a
        dim hyphen when no source reported ``seenBy``.
    """
    if counts is None:
        return _cell(_DASH, _UNKNOWN_STYLE)
    day, week, month = counts
    flag = _ALARM_STYLE if month == 0 else _WARN_STYLE if week == 0 else None
    return _cell(f"{day}/{week}/{month}", flag)


def _duration_text(duration: timedelta) -> str:
    """Render a duration compactly: ``"3d 4h"``, ``"5h 12m"``, ``"42m"`` or ``"<1m"``.

    Args:
        duration: The duration; negative values (clock skew) render as ``"<1m"``.

    Returns:
        The two most significant units.
    """
    minutes = max(int(duration.total_seconds()), 0) // 60
    days, minutes = divmod(minutes, 24 * 60)
    hours, minutes = divmod(minutes, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m" if minutes else "<1m"


def every_cell(cadence: Cadence) -> Text:
    """Render the ``Every`` cell: the node's expected interval.

    Args:
        cadence: :attr:`~meshprovision.status.merge.MergedNode.cadence`.

    Returns:
        The interval, gray when it is only the role's default.
    """
    style = _UNKNOWN_STYLE if cadence.source is CadenceSource.ROLE else None
    return _cell(interval_text(cadence.interval), style)


def _last_boot_contradicted(node: MergedNode) -> bool:
    """Tell whether the device's own metrics show a reboot newer than ``LastBoot``.

    Args:
        node: The merged node.

    Returns:
        ``True`` when the time from ``last_boot`` to ``last_device_metrics``
        exceeds the ``uptime_seconds`` reported with those metrics by more
        than :data:`_LAST_BOOT_TOLERANCE`; ``False`` when any of the three
        is unknown, or when the uptime is the longer one (not a reboot).
    """
    if node.last_boot is None or node.uptime_seconds is None or node.last_device_metrics is None:
        return False
    since_boot = node.last_device_metrics - node.last_boot
    return since_boot > timedelta(seconds=node.uptime_seconds) + _LAST_BOOT_TOLERANCE


def _uptime_cell(node: MergedNode, now: datetime) -> Text:
    """Render the ``Uptime`` cell: the time since the node's last known boot.

    Only a reported boot time (lorastats ``LastBoot``) is used. The uptime
    figure a device sends with its metrics is deliberately not used as a
    fallback: it is as old as those metrics, and extrapolating it to now
    can show an uptime that no longer holds (the node may have rebooted
    since). It is only used to notice that ``LastBoot`` is out of date
    (see :func:`_last_boot_contradicted`). A node that is not online may
    have gone down since it was last seen, so its uptime is counted only
    up to ``last_seen`` (up to ``now`` when that is unknown).

    Args:
        node: The merged node.
        now: The report time.

    Returns:
        A gray hyphen when no boot time is known or the device's metrics
        contradict it; for a node that is not online, the uptime as of
        ``last_seen`` in gray; otherwise the duration in the warning style
        when it is under :data:`UPTIME_WARN_BELOW` (a recent reboot), or
        unstyled.
    """
    if node.last_boot is None or _last_boot_contradicted(node):
        return _cell(_DASH, _UNKNOWN_STYLE)
    if node.availability is not Availability.ONLINE:
        end = now if node.last_seen is None else node.last_seen
        return _cell(_duration_text(end - node.last_boot), _UNKNOWN_STYLE)
    uptime = now - node.last_boot
    return _cell(_duration_text(uptime), _WARN_STYLE if uptime < UPTIME_WARN_BELOW else None)


def build_table(
    report: StatusReport,
    *,
    brief: bool = False,
    extra: ExtraColumns | None = None,
    trends: Mapping[NodeId, NodeTrends] | None = None,
    hidden: frozenset[str] = frozenset(),
) -> Table:
    """Build the ``rich`` table rendering of a status report.

    Every ``None`` field renders as a single dim hyphen, never the
    literal ``"None"``. Numeric columns are right-justified. Rows are not
    colored as a whole; individual cells are. ``Last seen`` and
    ``Timestamp`` use :func:`age_style` on the node's last activity,
    ``Status`` follows the availability (judged against the node's own
    thresholds), ``Every`` is the node's expected interval (gray when
    only its role's default is known), and ``Metrics`` plus the
    ``Batt``/``Volt``/``ChUtil``/``AirTx`` readings use :func:`age_style`
    on when the device last reported its metrics (gray when unknown) --
    except that a reading that is itself alarming or suspicious (see the
    ``*_ALARM_*`` / ``*_WARN_*`` constants) is drawn bold red or bold
    orange instead. ``Seen By`` shows how many MQTT gateways relayed the
    node within 1 / 7 / 30 days (warning when none did in 7 days, alarm
    when none did in 30), and ``Uptime`` is the time since the last boot
    (from ``LastBoot`` only; warning when under an hour; gray and counted
    only up to ``Last seen`` for a node that is not online; a dim hyphen
    when the device's metrics show a newer reboot, see
    :func:`_uptime_cell`). A battery level of 0 or less is no reading and
    renders as a dim hyphen. A caption is attached below the table:
    :meth:`~meshprovision.status.report.StatusReport.summary`, plus --
    when the report has any source failures -- one dim red line per
    failure, plus -- when any source skipped an unparsable entry -- one
    dim yellow line per affected source. A database with zero *reported*
    nodes still gets this same caption (never discarded: a degraded,
    empty run is exactly when an operator most needs the failure/skip
    lines, since the table itself offers no other clue) with an
    empty-state line prepended -- ``"No nodes in the database"`` when it
    is genuinely empty, or ``"No active nodes (N archived)"`` when every
    record in it is archived (see :attr:`~meshprovision.status.report.
    StatusReport.archived_count`).

    The ``Timestamp`` column header names the local zone at
    ``report.generated_at`` (for example ``"Timestamp (CEST)"``); a row
    only repeats that zone explicitly when its own instant genuinely
    falls on the other side of a DST transition from ``generated_at``
    (see :func:`_timestamp_cell`) -- the common case stays uncluttered,
    while a long-offline node's row is never silently mislabeled by a
    header that no longer applies to it.

    ``brief`` keeps only :data:`BRIEF_COLUMNS`; ``hidden`` drops the named
    columns (:data:`DEFAULT_HIDDEN_COLUMNS` for ``--detail default``);
    ``extra`` appends its columns (a dim hyphen for a node it has no cells
    for) and its caption. A reading that has a known ``trends`` entry is
    followed by a green up arrow, a red down arrow or a yellow ``~``
    (little change) -- the direction it moved, not whether that is good.

    Args:
        report: The report to render.
        brief: Keep only the essential columns (``--detail brief``).
        extra: More columns to append (``--detail full``).
        trends: Each node's metric trends, when known.
        hidden: Headers of the columns to leave out.

    Returns:
        The built, not-yet-printed ``rich`` table.
    """
    columns: list[tuple[str, JustifyMethod]] = [
        ("Node", "left"),
        ("Short", "left"),
        ("Long", "left"),
        ("Mgmt", "left"),
        ("Status", "left"),
        ("Last seen", "left"),
        ("Every", "right"),
        (f"Timestamp ({timefmt.local_tz_abbreviation(report.generated_at)})", "left"),
        ("Metrics", "left"),
        ("Batt", "right"),
        ("Volt", "right"),
        ("ChUtil", "right"),
        ("AirTx", "right"),
        (_SEEN_BY_HEADER, "right"),
        ("Uptime", "right"),
    ]
    rows = [
        _row(node, report.generated_at, (trends or {}).get(node.node_id, NodeTrends()))
        for node in report.nodes
    ]
    if brief or hidden:
        kept = [
            index
            for index, (header, _) in enumerate(columns)
            if (not brief or header in BRIEF_COLUMNS) and header not in hidden
        ]
        columns = [columns[index] for index in kept]
        rows = [[row[index] for index in kept] for row in rows]
    if extra is not None:
        columns.extend(extra.headers)
        dashes = [_cell(_DASH, _UNKNOWN_STYLE) for _ in extra.headers]
        rows = [
            [*row, *extra.cells.get(node.node_id, dashes)]
            for row, node in zip(rows, report.nodes, strict=True)
        ]

    table = Table(title=None, box=box.SIMPLE_HEAVY, header_style="bold")
    for header, justify in columns:
        table.add_column(header, justify=justify)
    for row in rows:
        table.add_row(*row)
    table.caption = _caption(report, extra)
    return table


def _with_trend(cell: Text, trend: Trend | None) -> Text:
    """Follow a reading with its trend arrow (nothing for an unknown reading or trend)."""
    if trend is None or cell.plain == _DASH:
        return cell
    arrow, style = _TREND_ARROWS[trend]
    cell.append(arrow, style=style)
    return cell


def _row(node: MergedNode, now: datetime, trends: NodeTrends) -> list[RenderableType]:
    """Build one node's cells of the default table, in column order."""
    seen_style = age_style(node.age, node.thresholds)
    metrics_age = None if node.last_device_metrics is None else now - node.last_device_metrics
    fresh = age_style(metrics_age, node.thresholds)
    return [
        node.node_id.display,
        _text_cell(node.short_name),
        _text_cell(node.long_name),
        _text_cell(node.management),
        _cell(AVAILABILITY_LABELS[node.availability], _AVAILABILITY_STYLES[node.availability]),
        _cell(node.age_text, seen_style),
        every_cell(node.cadence),
        _cell(_timestamp_cell(node.last_seen, reference=now), seen_style),
        _cell(_DASH if metrics_age is None else humanize_age(metrics_age), fresh),
        _with_trend(
            _value_cell(
                _battery_cell(node.battery_level),
                flag=_battery_flag(node.battery_level),
                freshness=fresh,
            ),
            trends.battery,
        ),
        _with_trend(
            _value_cell(
                _voltage_cell(node.voltage), flag=_voltage_flag(node.voltage), freshness=fresh
            ),
            trends.voltage,
        ),
        _with_trend(
            _value_cell(
                _percent_cell(node.channel_utilization),
                flag=_severity(
                    node.channel_utilization,
                    alarm=CHANNEL_UTILIZATION_ALARM_PERCENT,
                    warn=CHANNEL_UTILIZATION_WARN_PERCENT,
                    low_is_bad=False,
                ),
                freshness=fresh,
            ),
            trends.channel_utilization,
        ),
        _with_trend(
            _value_cell(
                _percent_cell(node.air_util_tx),
                flag=_severity(
                    node.air_util_tx,
                    alarm=AIR_UTIL_TX_ALARM_PERCENT,
                    warn=AIR_UTIL_TX_WARN_PERCENT,
                    low_is_bad=False,
                ),
                freshness=fresh,
            ),
            trends.air_util_tx,
        ),
        _seen_by_cell(node.seen_by_counts),
        _uptime_cell(node, now),
    ]


def _caption(report: StatusReport, extra: ExtraColumns | None) -> Text:
    """Build the caption below the table (see :func:`build_table`)."""
    caption = Text(report.summary())
    for failure in report.failures:
        caption.append("\n")
        caption.append(f"{failure.source}: {failure.message}", style="dim red")
    for source, count in report.skipped_entries.items():
        caption.append("\n")
        caption.append(f"{source}: {count} entrie(s) could not be parsed", style="dim yellow")
    for source, count in report.field_coercions.items():
        caption.append("\n")
        caption.append(f"{source}: {count} field(s) could not be coerced", style="dim yellow")
    if not report.nodes:
        empty_state = (
            f"No active nodes ({report.archived_count} archived)"
            if report.archived_count
            else "No nodes in the database"
        )
        caption = Text(empty_state) + Text("\n") + caption
    if extra is not None and extra.caption is not None:
        caption.append("\n")
        caption.append_text(extra.caption)
    return caption


def render_console(
    report: StatusReport,
    *,
    console: Console | None = None,
    brief: bool = False,
    extra: ExtraColumns | None = None,
    trends: Mapping[NodeId, NodeTrends] | None = None,
    hidden: frozenset[str] = frozenset(),
) -> None:
    """Print a status report's table and summary caption to a console.

    The only function in this module permitted to touch a ``Console``.

    Args:
        report: The report to render.
        console: The ``rich`` console to print to. Defaults to a new
            :class:`~rich.console.Console`.
        brief: See :func:`build_table`.
        extra: See :func:`build_table`.
        trends: See :func:`build_table`.
        hidden: See :func:`build_table`.
    """
    active_console = console if console is not None else Console()
    table = build_table(report, brief=brief, extra=extra, trends=trends, hidden=hidden)
    active_console.print(table, markup=False, highlight=False)


def report_to_json_dict(report: StatusReport) -> dict[str, object]:
    """Render a status report to its stable, diffable JSON-able shape.

    Key order is fixed and insertion-ordered (never ``sort_keys``), so
    successive runs against unchanged data produce byte-identical output.
    Never emits ``ble_pin``, key material, or a ``key_ref`` -- each
    node's ``record`` is never serialized wholesale (see
    :meth:`~meshprovision.status.merge.MergedNode.to_json_dict`).

    Args:
        report: The report to render.

    Returns:
        A mapping shaped as::

            {
                "generated_at": "2026-08-25T03:14:10Z",
                "thresholds": {"stale_after_seconds": 7200, "offline_after_seconds": 86400},
                "counts": {"online": 3, "stale": 1, "offline": 0, "unknown": 2},
                "cache": {"hits": 2, "misses": 1, "network_requests": 1},
                "data_as_of": {"loranet": "2026-08-25T02:58:03Z"},
                "failures": [{"source": "lorastats", "message": "...", "hint": None}],
                "skipped_entries": {"loranet": 12},
                "field_coercions": {"loranet": 5},
                "nodes": [...],
            }

        ``data_as_of`` stays UTC/``Z``-suffixed like every other
        timestamp here, so this document stays byte-identical across
        timezones and DST -- only the ``rich`` table (:func:`build_table`)
        localizes.
    """
    counts = report.counts
    generated_at = report.generated_at.astimezone(UTC).isoformat(timespec="seconds")
    return {
        "generated_at": generated_at.replace("+00:00", "Z"),
        "thresholds": {
            "stale_after_seconds": int(report.thresholds.stale_after.total_seconds()),
            "offline_after_seconds": int(report.thresholds.offline_after.total_seconds()),
        },
        "counts": {availability.value: counts[availability] for availability in Availability},
        "cache": {
            "hits": report.cache_hits,
            "misses": report.cache_misses,
            "network_requests": report.network_requests,
        },
        "data_as_of": {
            source: timefmt.isoformat_z(timestamp)
            for source, timestamp in report.data_as_of.items()
        },
        "skipped_entries": dict(report.skipped_entries),
        "field_coercions": dict(report.field_coercions),
        "failures": [
            {"source": failure.source, "message": failure.message, "hint": failure.hint}
            for failure in report.failures
        ],
        "nodes": [node.to_json_dict() for node in report.nodes],
    }


def render_json(report: StatusReport, *, indent: int = 2) -> str:
    r"""Render a status report as a stable, indented JSON string.

    Args:
        report: The report to render.
        indent: ``json.dumps`` indent level.

    Returns:
        ``json_dumps_safe(report_to_json_dict(report), indent=indent)`` --
        non-ASCII names kept literal, terminal control characters
        ``\uNNNN``-escaped -- with insertion-ordered (never sorted) keys.
    """
    return json_dumps_safe(report_to_json_dict(report), indent=indent)
