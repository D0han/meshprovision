"""Timestamp display helpers shared by :mod:`status.report` and :mod:`status.render`.

Deliberately dependency-free (stdlib only), so both a report-assembly
module and a presentation module can import it without creating a cycle
between them. Nothing here reads the clock or any other external state --
every function takes its timestamp as an explicit, timezone-aware
argument and is otherwise pure.

Two families of rendering live here, for two different audiences:

- :func:`isoformat_z` -- UTC, ``Z``-suffixed, machine-stable. Used for
  every ``--json`` field, so JSON output stays byte-identical across
  timezones and DST.
- :func:`format_local`/:func:`local_tz_abbreviation` -- the machine's
  local timezone (``datetime.astimezone()`` with no argument; the
  standard ``TZ`` environment variable already overrides this for free).
  Used for the human-facing ``rich`` table and summary caption.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final

__all__ = ["format_local", "isoformat_z", "local_tz_abbreviation"]

_LOCAL_DATETIME_FORMAT: Final[str] = "%Y-%m-%d %H:%M:%S %Z"
_LOCAL_TIME_ONLY_FORMAT: Final[str] = "%H:%M:%S"


def isoformat_z(value: datetime | None) -> str | None:
    """Render a timezone-aware datetime as ISO-8601 UTC with a ``Z`` suffix.

    Args:
        value: The datetime to render, or ``None``.

    Returns:
        For example ``"2026-08-25T03:14:10Z"``, or ``None`` when ``value``
        is ``None``.
    """
    if value is None:
        return None
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def format_local(value: datetime, *, reference: datetime | None = None) -> str:
    """Render a timezone-aware datetime in the machine's local timezone.

    Args:
        value: The timestamp to render. Must be timezone-aware.
        reference: When given, and ``value`` falls on the same local
            calendar date as ``reference`` (both converted to local time
            first), only the time-of-day is rendered (``"14:32:10"``)
            instead of the full ``"2026-09-19 14:32:10 CEST"`` form. Lets
            a caller with one shared reference instant (for example a
            report's ``generated_at``) keep a per-source breakdown short
            without repeating today's date for every entry.

    Returns:
        The localized, human-readable rendering.
    """
    local_value = value.astimezone()
    if reference is not None:
        local_reference = reference.astimezone()
        if local_value.date() == local_reference.date():
            return local_value.strftime(_LOCAL_TIME_ONLY_FORMAT)
    return local_value.strftime(_LOCAL_DATETIME_FORMAT)


def local_tz_abbreviation(value: datetime) -> str:
    """Return the local timezone's abbreviation at a given instant.

    Args:
        value: The timestamp whose instant to evaluate the local zone
            at (only the instant matters, not its original offset --
            DST, for example, is resolved for this instant in the local
            zone, not in ``value``'s own zone).

    Returns:
        The local zone's abbreviation, for example ``"CEST"`` or ``"UTC"``.
    """
    return value.astimezone().strftime("%Z")
