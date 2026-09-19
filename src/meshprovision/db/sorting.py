"""Deterministic, human-friendly row ordering for the ODS database.

The ``Nodes``/``Keys`` sheets are always sorted -- on load, after every
in-memory mutation, and on write -- so the ``.ods`` file, ``mesh db list``,
and ``mesh status`` all agree on one order regardless of insertion history
or hand-editing. This retires the project's former "insertion order,
never re-sorted" invariant; see :mod:`meshprovision.db.ods` for where
:func:`sorted_rows` is applied.

Ordering is natural/human ("MT2" before "MT11", not the reverse), applied
via :func:`natural_key`, and case-insensitive throughout.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from typing import Final

from meshprovision.db import schema

__all__ = ["natural_key", "sorted_rows"]

_NUMBER_RUN: Final[re.Pattern[str]] = re.compile(r"(\d+)")

_NaturalKey = tuple[tuple[int, str, int], ...]


def natural_key(value: str) -> _NaturalKey:
    """Build a sort key that orders digit runs by numeric value.

    Splits ``value`` on runs of digits so ``"MT2"`` sorts before
    ``"MT11"`` (a plain string compare would put ``"MT11"`` first,
    since ``"1" < "2"``). Comparison is case-insensitive.

    Args:
        value: The string to build a sort key for.

    Returns:
        A tuple of ``(is_number, text_chunk, numeric_chunk)`` triples,
        one per alternating text/digit run of ``value.casefold()``, with
        every element the same shape so triples compare directly
        regardless of which chunks are numeric. A pure text chunk is
        ``(0, chunk, 0)``; a digit run is ``(1, "", int(chunk))``.
    """
    parts = _NUMBER_RUN.split(value.casefold())
    # re.split with one capture group returns text/digit/text/digit/...,
    # starting and ending with a (possibly empty) text chunk -- odd
    # indices are always the captured digit runs.
    return tuple(
        (1, "", int(part)) if index % 2 == 1 else (0, part, 0) for index, part in enumerate(parts)
    )


def _node_sort_key(row: Mapping[str, str]) -> tuple[_NaturalKey, str]:
    """Build the ``Nodes`` sheet's sort key for one row.

    Orders by ``long_name``, falling back to ``short_name`` when
    ``long_name`` is empty, then by ``node_id`` to make the order fully
    deterministic even between two rows with the same name. Archived
    nodes are not treated specially -- they sort inline by name, same as
    any active row, so the sheet stays one readable list.

    Args:
        row: The row's ``{column_name: text}`` values.

    Returns:
        A ``(natural_key(name), node_id)`` tuple.
    """
    name = row.get("long_name") or row.get("short_name") or ""
    return natural_key(name), row.get("node_id", "")


def _key_sort_key(row: Mapping[str, str]) -> tuple[_NaturalKey, str, str]:
    """Build the ``Keys`` sheet's sort key for one row.

    Orders by ``key_ref`` (the sheet's own primary key), then by
    ``owner_node_id``/``key_type`` to break ties for the degenerate case
    of a row with a blank ``key_ref``.

    Args:
        row: The row's ``{column_name: text}`` values.

    Returns:
        A ``(natural_key(key_ref), owner_node_id, key_type)`` tuple.
    """
    return (
        natural_key(row.get("key_ref", "")),
        row.get("owner_node_id", ""),
        row.get("key_type", ""),
    )


_SORT_KEYS: Final[Mapping[str, Callable[[Mapping[str, str]], tuple[object, ...]]]] = {
    schema.NODES_SHEET: _node_sort_key,
    schema.KEYS_SHEET: _key_sort_key,
}


def sorted_rows(sheet: str, rows: Sequence[Mapping[str, str]]) -> tuple[Mapping[str, str], ...]:
    """Sort one sheet's rows into their canonical display order.

    Pure and idempotent: calling it twice, or on an already-sorted
    sequence, changes nothing. Safe to call from every read/write path
    (:mod:`meshprovision.db.ods`'s ``load_database``, ``build_document``,
    and ``OdsDatabase.replace``) without worrying about compounding
    re-sorts.

    Args:
        sheet: The sheet name (``"Nodes"`` or ``"Keys"``).
        rows: The rows to sort.

    Returns:
        ``rows`` sorted by that sheet's canonical key, as a new tuple.
        An unrecognized ``sheet`` name is returned unchanged (as a
        tuple) rather than raising -- callers that must reject an
        unknown sheet (for example :meth:`~meshprovision.db.ods.
        OdsDatabase.replace`) already validate it themselves.
    """
    key_fn = _SORT_KEYS.get(sheet)
    if key_fn is None:
        return tuple(rows)
    return tuple(sorted(rows, key=key_fn))
