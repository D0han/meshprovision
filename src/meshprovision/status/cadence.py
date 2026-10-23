"""How often a node is expected to be heard, and the thresholds that follow. Pure.

A node's *expected interval* is the longest gap a healthy node of its
configuration leaves between two packets our observers can see. It is
resolved per node, first match wins (:func:`resolve_cadence`):

1. an operator override (``--expected-interval``);
2. learned from the node's local health history (:func:`learned_interval`);
3. the provisioning template's node-info interval, for a template-managed
   node (:func:`template_interval`);
4. the role's firmware default (:func:`role_interval`).

The node-info broadcast is the anchor of 3 and 4: every role but
``CLIENT_HIDDEN`` sends it by default (every 3 hours, 24 for the TAK
roles), and unlike telemetry and position the firmware never stretches
it on a crowded mesh, so it holds whatever the preset or the mesh size.

:func:`availability_thresholds` turns an interval into stale/offline
thresholds: a few missed intervals plus a grace, never below the fixed
floors (``mesh status --stale-after``/``--offline-after``). Every number
is a named constant below; ``docs/commands.md`` gives the reasons.

This module imports nothing but the standard library;
``tests/unit/test_import_contracts.py`` holds it to that.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from typing import Final

__all__ = [
    "GRACE_SHARE",
    "LEARN_MIN_HEARD_HOURS",
    "LEARN_WINDOW_DAYS",
    "MAX_EXPECTED_INTERVAL",
    "NODE_INFO_DEFAULT",
    "NODE_INFO_MIN",
    "OFFLINE_MISSED",
    "SILENT_ROLES",
    "STALE_MISSED",
    "TAK_NODE_INFO",
    "TAK_ROLES",
    "Cadence",
    "CadenceHint",
    "CadenceSource",
    "availability_thresholds",
    "interval_text",
    "learned_interval",
    "resolve_cadence",
    "role_interval",
    "template_interval",
]

NODE_INFO_DEFAULT: Final[timedelta] = timedelta(hours=3)
"""The firmware's default node-info interval (``default_node_info_broadcast_secs``)."""

NODE_INFO_MIN: Final[timedelta] = timedelta(hours=1)
"""The firmware's shortest node-info interval (a shorter setting is raised to it)."""

TAK_NODE_INFO: Final[timedelta] = timedelta(hours=24)
"""The node-info interval the firmware sets for the TAK roles."""

TAK_ROLES: Final[frozenset[str]] = frozenset({"TAK", "TAK_TRACKER"})
"""Roles whose firmware default node-info interval is :data:`TAK_NODE_INFO`."""

SILENT_ROLES: Final[frozenset[str]] = frozenset({"CLIENT_HIDDEN", "REPEATER"})
"""Roles that send no node info of their own: expected at :data:`MAX_EXPECTED_INTERVAL`."""

MAX_EXPECTED_INTERVAL: Final[timedelta] = timedelta(hours=48)
"""The longest expected interval (twice the longest firmware default, the TAK roles')."""

STALE_MISSED: Final[int] = 2
"""Missed intervals before a node is stale (the firmware forgets a neighbour after 2)."""

OFFLINE_MISSED: Final[int] = 5
"""Missed intervals before a node is offline (5 losses in a row are rare even at 30% loss)."""

GRACE_SHARE: Final[float] = 0.25
"""The grace added to both thresholds, as a share of the interval (jitter, upload delays)."""

LEARN_WINDOW_DAYS: Final[int] = 7
"""The days of history an interval is learned from."""

LEARN_MIN_HEARD_HOURS: Final[int] = 3
"""Fewest heard hours an interval is learned from (two gaps)."""

_DAY_SECONDS: Final[int] = 86400


class CadenceSource(StrEnum):
    """Where a node's expected interval came from.

    Attributes:
        OVERRIDE: The operator's ``--expected-interval``.
        HISTORY: Learned from the node's local health history.
        TEMPLATE: The provisioning template's node-info interval.
        ROLE: The role's firmware default.
    """

    OVERRIDE = "override"
    HISTORY = "history"
    TEMPLATE = "template"
    ROLE = "role"


@dataclass(frozen=True, slots=True)
class Cadence:
    """A node's expected interval and where it came from.

    Attributes:
        interval: The longest gap a healthy node is expected to leave.
        source: Where it came from.
    """

    interval: timedelta
    source: CadenceSource


@dataclass(frozen=True, slots=True)
class CadenceHint:
    """What is known about a node's interval besides its role.

    Attributes:
        override: The operator's interval, when given.
        learned: The interval learned from its history, when there is one.
        configured: The template's interval, when it is template-managed.
    """

    override: timedelta | None = None
    learned: timedelta | None = None
    configured: timedelta | None = None


def _capped(interval: timedelta) -> timedelta:
    """Bound an interval by :data:`MAX_EXPECTED_INTERVAL`."""
    return min(interval, MAX_EXPECTED_INTERVAL)


def role_interval(role: str | None) -> timedelta:
    """Return a role's firmware default node-info interval.

    Args:
        role: The canonical role name, when known.

    Returns:
        :data:`TAK_NODE_INFO` for the TAK roles,
        :data:`MAX_EXPECTED_INTERVAL` for the roles that send no node info,
        else :data:`NODE_INFO_DEFAULT` (also for an unknown role).
    """
    if role in SILENT_ROLES:
        return MAX_EXPECTED_INTERVAL
    if role in TAK_ROLES:
        return TAK_NODE_INFO
    return NODE_INFO_DEFAULT


def template_interval(node_info_seconds: int | None, role: str | None) -> timedelta:
    """Return the node-info interval a template configures.

    Args:
        node_info_seconds: The template's ``device.node_info_broadcast_secs``
            (``None`` or 0: the device's default).
        role: The template's ``device.role``.

    Returns:
        The role's default when no interval is set or the role sends no
        node info, else the interval raised to :data:`NODE_INFO_MIN` and
        capped at :data:`MAX_EXPECTED_INTERVAL`.
    """
    if not node_info_seconds or role in SILENT_ROLES:
        return role_interval(role)
    return _capped(max(timedelta(seconds=node_info_seconds), NODE_INFO_MIN))


def learned_interval(hours: Iterable[tuple[int, int]], *, now: float) -> timedelta | None:
    """Learn a node's interval from the hours its history covers.

    The mean gap between heard hours: the covered hours after the first
    heard hour up to the last one, over the gaps between them. Only the
    last :data:`LEARN_WINDOW_DAYS` days count, and hours after the last
    heard one do not (a node that is down now does not stretch its own
    interval).

    Args:
        hours: ``(hour start, receptions)`` of each covered hour, epoch
            seconds (hours lorastats was not asked about are absent).
        now: The current time, epoch seconds.

    Returns:
        The interval, capped at :data:`MAX_EXPECTED_INTERVAL`, or ``None``
        with fewer than :data:`LEARN_MIN_HEARD_HOURS` heard hours in the
        window.
    """
    start = now - LEARN_WINDOW_DAYS * _DAY_SECONDS
    in_window = {hour: receptions for hour, receptions in hours if start <= hour <= now}
    covered = sorted(in_window.items())
    heard = [hour for hour, receptions in covered if receptions > 0]
    if len(heard) < LEARN_MIN_HEARD_HOURS:
        return None
    span = sum(1 for hour, _ in covered if heard[0] < hour <= heard[-1])
    return _capped(timedelta(hours=span / (len(heard) - 1)))


def resolve_cadence(hint: CadenceHint, role: str | None) -> Cadence:
    """Pick a node's expected interval: override, history, template, role.

    Args:
        hint: What is known besides the role.
        role: The node's role, when known.

    Returns:
        The first available interval (capped at
        :data:`MAX_EXPECTED_INTERVAL`) with its source.
    """
    if hint.override is not None:
        return Cadence(_capped(hint.override), CadenceSource.OVERRIDE)
    if hint.learned is not None:
        return Cadence(_capped(hint.learned), CadenceSource.HISTORY)
    if hint.configured is not None:
        return Cadence(_capped(hint.configured), CadenceSource.TEMPLATE)
    return Cadence(role_interval(role), CadenceSource.ROLE)


def interval_text(interval: timedelta) -> str:
    """Render an expected interval: ``"3h"``, ``"3h 30m"`` or ``"45m"``.

    Args:
        interval: The interval (a few days at most, so hours suffice).

    Returns:
        Whole hours and the remaining whole minutes, each left out when 0
        (``"0m"`` for an interval under a minute).
    """
    hours, minutes = divmod(int(interval.total_seconds()) // 60, 60)
    if not hours:
        return f"{minutes}m"
    return f"{hours}h {minutes}m" if minutes else f"{hours}h"


def availability_thresholds(
    interval: timedelta, *, stale_floor: timedelta, offline_floor: timedelta
) -> tuple[timedelta, timedelta]:
    """Turn an expected interval into stale and offline thresholds.

    Args:
        interval: The node's expected interval.
        stale_floor: The shortest stale threshold.
        offline_floor: The shortest offline threshold.

    Returns:
        ``(stale_after, offline_after)``: :data:`STALE_MISSED` and
        :data:`OFFLINE_MISSED` intervals plus a grace of
        :data:`GRACE_SHARE` of one, each at least its floor.
    """
    grace = interval * GRACE_SHARE
    return (
        max(stale_floor, interval * STALE_MISSED + grace),
        max(offline_floor, interval * OFFLINE_MISSED + grace),
    )
