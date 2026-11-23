"""Passive drift: how a template-managed node's database row differs from what was heard.

It compares what the data sources and the node's own node info said about a node against
its database row, for the short and long names, the role and the hardware model. It asks
nothing of anyone: every input is data ``mesh health`` already collected.

An observation counts only when it is recent, newer than the row's last update, and when
both sides have a value to compare (an empty recorded cell is no claim, as in
:func:`~meshprovision.provisioning.repair.diff_record`). Names and role come only from a
decoded node info with its exact time; the hardware model comes from ``mesh status``'s
sources, because the node infos in the history carry none.

This module imports nothing that reads files or the network (no ``httpx``, ``pathlib``,
:mod:`meshprovision.cache` or :mod:`meshprovision.db`); ``tests/unit/test_import_contracts.py``
holds it to that.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from meshprovision.enums import hw_model_table
from meshprovision.health.history import NodeInfoSeen
from meshprovision.health.packets import FUTURE_SKEW_SECONDS

__all__ = [
    "DRIFT_MAX_AGE_SECONDS",
    "RECORD_GRACE_SECONDS",
    "DriftSource",
    "ObservedHardware",
    "PassiveDrift",
    "RecordedIdentity",
    "passive_drift",
]

DRIFT_MAX_AGE_SECONDS: Final[float] = 7 * 24 * 3600.0
"""An observation older than this is not judged: a node announces its node info every
3 hours by default, so a week without one means it is no longer heard."""

RECORD_GRACE_SECONDS: Final[float] = 300.0
"""An observation must be this much newer than the row's last update to count (clock skew
between lorastats and this host); an older one may predate the change the row records.
The node also announces a committed name change at once; that announcement lands before
the row is written and is skipped on purpose, so drift after a provision run shows from
the next periodic node info."""


class DriftSource(StrEnum):
    """Where an observed value came from.

    Attributes:
        NODE_INFO: The newest node-info packet in the node's health history.
        SOURCES: ``mesh status``'s sources (loranet, lorastats' node list).
    """

    NODE_INFO = "node_info"
    SOURCES = "sources"


@dataclass(frozen=True, slots=True)
class RecordedIdentity:
    """What the database row claims about a node.

    Attributes:
        short_name: The recorded short name ("" when unfilled).
        long_name: The recorded long name ("" when unfilled).
        role: The recorded canonical role name ("" when unfilled).
        hw_model: The recorded canonical hardware model name ("" when unfilled).
        updated_at: When the row was last updated, epoch seconds, or ``None``.
    """

    short_name: str
    long_name: str
    role: str
    hw_model: str
    updated_at: float | None


@dataclass(frozen=True, slots=True)
class ObservedHardware:
    """The hardware model the data sources report.

    Attributes:
        hw_model: The sources' hardware model (canonical name or raw string).
        seen_at: When the source that reported :attr:`hw_model` last saw the node, epoch
            seconds.
    """

    hw_model: str
    seen_at: float


@dataclass(frozen=True, slots=True)
class PassiveDrift:
    """One difference between the database row and what was heard.

    Attributes:
        field: ``"short_name"``, ``"long_name"``, ``"hw_model"`` or ``"role"``.
        recorded: The database's value.
        observed: The heard value.
        source: Where the heard value came from.
        seen_at: When it was heard, epoch seconds.
    """

    field: str
    recorded: str
    observed: str
    source: DriftSource
    seen_at: float


def _current(seen_at: float, recorded: RecordedIdentity, now: float) -> bool:
    """Whether an observation is recent, not from the future and newer than the row."""
    if seen_at < now - DRIFT_MAX_AGE_SECONDS or seen_at > now + FUTURE_SKEW_SECONDS:
        return False
    return recorded.updated_at is None or seen_at > recorded.updated_at + RECORD_GRACE_SECONDS


def _as_heard(name: str) -> str:
    """A recorded long name as a node-info payload gives it back.

    The payload joins the names with ``", "`` and the parser strips every
    part, so ``"Foo , Bar"`` comes back as ``"Foo, Bar"``.
    """
    return ", ".join(part.strip() for part in name.split(", "))


def _name_drift(recorded: RecordedIdentity, nodeinfo: NodeInfoSeen) -> tuple[PassiveDrift, ...]:
    """The names and role the node's newest node info disagrees with, in fixed order."""
    if ", " in recorded.short_name:
        # The payload cannot say where such a short name ends and the long
        # name starts, so neither name can be compared.
        return ()
    pairs = (
        (
            "short_name",
            recorded.short_name,
            recorded.short_name.strip(),
            nodeinfo.short_name.strip(),
        ),
        (
            "long_name",
            recorded.long_name,
            _as_heard(recorded.long_name),
            nodeinfo.long_name.strip(),
        ),
    )
    found = [
        PassiveDrift(name, was, heard, DriftSource.NODE_INFO, nodeinfo.time)
        for name, was, expected, heard in pairs
        if was and expected != heard
    ]
    return tuple(found)


def _hardware_drift(recorded: RecordedIdentity, hardware: ObservedHardware) -> PassiveDrift | None:
    """The hardware model difference, when the sources name a canonical model."""
    heard = hardware.hw_model
    if not recorded.hw_model or heard == "UNSET" or hw_model_table().try_name(heard) != heard:
        return None
    if recorded.hw_model == heard:
        return None
    return PassiveDrift("hw_model", recorded.hw_model, heard, DriftSource.SOURCES, hardware.seen_at)


def passive_drift(
    recorded: RecordedIdentity | None,
    nodeinfo: NodeInfoSeen | None,
    hardware: ObservedHardware | None,
    *,
    now: float,
) -> tuple[PassiveDrift, ...]:
    """Compare a template-managed node's database row with what was heard of it. Pure.

    Args:
        recorded: The row's claims, or ``None`` when the row is not to be judged.
        nodeinfo: The newest node info in the node's history.
        hardware: The hardware model the sources report.
        now: The current time, epoch seconds.

    Returns:
        The differences, in the order ``short_name``, ``long_name``, ``hw_model``,
        ``role``.
    """
    if recorded is None:
        return ()
    names: tuple[PassiveDrift, ...] = ()
    role: tuple[PassiveDrift, ...] = ()
    if nodeinfo is not None and _current(nodeinfo.time, recorded, now):
        names = _name_drift(recorded, nodeinfo)
        if nodeinfo.role is not None and recorded.role and recorded.role != nodeinfo.role:
            role = (
                PassiveDrift(
                    "role", recorded.role, nodeinfo.role, DriftSource.NODE_INFO, nodeinfo.time
                ),
            )
    model = None
    if hardware is not None and _current(hardware.seen_at, recorded, now):
        model = _hardware_drift(recorded, hardware)
    return (*names, *(() if model is None else (model,)), *role)
