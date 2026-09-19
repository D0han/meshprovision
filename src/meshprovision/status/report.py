"""Read-only status orchestration: load, query, merge, and report.

This module is the only place that assembles a full
:class:`StatusReport`, and it is **strictly read-only**. It loads node
ids and records from the ODS database (load only, never save or
replace), queries both data sources through the cache layer, tolerates a
failing source without aborting the whole report, and hands the result
to :mod:`meshprovision.status.render` for presentation.

**The read-only guarantee, stated for both a human reviewer and a unit
test.** Nothing in this module may reference
``OdsDatabase.save``, ``OdsDatabase.replace``, ``NodeRepository.upsert``,
``NodeRepository.delete``, ``KeyRepository.upsert``, ``db.atomic_writer``,
or anything in
``meshprovision.provisioning.apply`` or ``meshprovision.provisioning.
repair``. An e2e test asserts the **live** ODS file's mtime is unchanged
across a full ``mesh status`` run, and a unit test
(``tests/unit/test_readonly_status_boundary.py``) walks this module's AST
for those operations -- both are expected to keep passing as this module
changes.
:func:`load_records` additionally asserts, defensively, that merely
loading the database never marks the in-memory session dirty.

None of this is contradicted by :func:`~meshprovision.db.ods
.load_database` best-effort refreshing the known-good safety copy under
``data/backups/`` on every successful load, including this module's own
-- that is a side-channel copy elsewhere on disk, never a write to
``OdsDatabase``'s in-memory state or the live database file this
module's own guarantee is about.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Final

from meshprovision.cache.http import CachedHTTPClient
from meshprovision.config.settings import Settings
from meshprovision.datasources.base import SOURCE_LORANET, SOURCE_LORASTATS, DataSource
from meshprovision.datasources.loranet import LoranetSource
from meshprovision.datasources.lorastats import DEFAULT_REGIONS, LorastatsSource
from meshprovision.datasources.models import NodeObservation
from meshprovision.db.nodes import NodeRecord, NodeRepository
from meshprovision.db.ods import OdsDatabase
from meshprovision.errors import DataSourceError, DbIntegrityError, ExitCode
from meshprovision.nodeid import NodeId
from meshprovision.status.merge import (
    SOURCE_PRIORITY,
    Availability,
    MergedNode,
    Thresholds,
    merge_all,
)
from meshprovision.status.timefmt import format_local, local_tz_abbreviation

__all__ = [
    "CollectedObservations",
    "SourceFailure",
    "StatusOptions",
    "StatusReport",
    "build_report",
    "collect_observations",
    "load_node_ids",
    "load_records",
    "run_status",
]

_logger = logging.getLogger(__name__)

_ALL_AVAILABILITIES: Final[tuple[Availability, ...]] = tuple(Availability)


@dataclass(frozen=True, slots=True)
class SourceFailure:
    """One data source's failure while collecting observations for a report.

    Attributes:
        source: The failing source's short name (for example
            ``"loranet"``, ``"lorastats"``).
        message: The underlying error's human-readable message.
        hint: The underlying error's actionable hint, when it had one.
    """

    source: str
    message: str
    hint: str | None = None


@dataclass(frozen=True, slots=True)
class CollectedObservations:
    """The result of one :func:`collect_observations` call.

    Attributes:
        observations: Per-source observation maps, keyed by source name
            (a source that failed entirely is simply absent).
        failures: Every source that failed during collection, in the
            order they were queried.
        skipped_entries: Per-source count of entries a *successful*
            source fetched but could not parse, omitting any source with
            a count of zero.
        field_coercions: Per-source count of individual fields a
            *successful* source could not coerce, omitting any source
            with a count of zero.
        data_as_of: Per-source timestamp of when the data behind this
            run was actually fetched from the network -- for a cache
            hit, the *original* fetch time, not "now"; the oldest such
            timestamp when a source's fetch spanned more than one HTTP
            request. Omits a source that made no HTTP request at all
            (it failed before issuing one, or was not queried).
    """

    observations: dict[str, dict[NodeId, NodeObservation]]
    failures: tuple[SourceFailure, ...]
    skipped_entries: dict[str, int]
    field_coercions: dict[str, int]
    data_as_of: dict[str, datetime]


@dataclass(frozen=True, slots=True)
class StatusOptions:
    """Everything that shapes one ``mesh status`` run.

    Attributes:
        thresholds: Age boundaries used to classify node availability.
        force_refresh: Whether to bypass the HTTP cache read for this
            run (the fetched response is still written back to the
            cache either way).
        sources: Which data sources to query, by short name. Defaults to
            both, in :data:`~meshprovision.status.merge.SOURCE_PRIORITY`
            order.
        regions: The lorastats region list to query. Defaults to
            :data:`~meshprovision.datasources.lorastats.DEFAULT_REGIONS`.
        node_ids: Which nodes to report on. An empty tuple means every
            node in the database.
        fail_on_offline: Whether an offline node should make
            :meth:`StatusReport.exit_code` return a non-zero exit code.
    """

    thresholds: Thresholds = field(default_factory=Thresholds)
    force_refresh: bool = False
    sources: tuple[str, ...] = SOURCE_PRIORITY
    regions: tuple[str, ...] = DEFAULT_REGIONS
    node_ids: tuple[NodeId, ...] = ()
    fail_on_offline: bool = True


_DEFAULT_STATUS_OPTIONS: Final[StatusOptions] = StatusOptions()
"""Module-level singleton default for the ``options`` parameter below --
avoids constructing a fresh :class:`StatusOptions` on every call/def
evaluation (``StatusOptions`` is immutable, so sharing one instance is
always safe)."""


@dataclass(frozen=True, slots=True)
class StatusReport:
    """The full result of one ``mesh status`` run.

    Attributes:
        generated_at: When this report was assembled. Timezone-aware.
        nodes: Every reported node's merged view, in the database's
            canonical row order (sorted by ``long_name``, see
            :mod:`meshprovision.db.sorting`).
        thresholds: The age boundaries used to classify availability.
        failures: Data sources that failed during collection, if any.
        skipped_entries: Per-source count of entries a *successful*
            source fetched but could not parse, keyed by source name.
            Omits any source with a count of zero. Distinct from
            :attr:`failures`: the source ran and returned real data, it
            just silently dropped some of it -- without this, a mass
            parse-failure (an upstream schema change, for example) is
            indistinguishable from those nodes simply being offline.
        field_coercions: Per-source count of individual *fields* (within
            otherwise-successfully-parsed entries) whose raw value was
            present but a ``coerce_*`` helper could not confidently
            coerce it, keyed by source name. Omits any source with a
            count of zero. Distinct from :attr:`skipped_entries`: the
            entry itself parsed fine, just one field within it didn't --
            without this, a source silently zeroing out one field
            fleet-wide (an upstream schema rename, for example) is
            invisible.
        data_as_of: Per-source timestamp of when that source's data was
            actually fetched from the network -- for a cache hit, the
            *original* fetch time, not "now" -- keyed by source name.
            Omits a source that made no HTTP request (it failed before
            issuing one, or was not queried). Surfaced in
            :meth:`summary` so an operator can tell how stale the report
            is without cross-referencing the HTTP cache.
        cache_hits: Cache hits accumulated by the underlying HTTP client
            during this run.
        cache_misses: Cache misses accumulated by the underlying HTTP
            client during this run.
        network_requests: Actual network requests made by the underlying
            HTTP client during this run (including retries).
    """

    generated_at: datetime
    nodes: tuple[MergedNode, ...]
    thresholds: Thresholds
    failures: tuple[SourceFailure, ...] = ()
    skipped_entries: Mapping[str, int] = field(default_factory=dict)
    field_coercions: Mapping[str, int] = field(default_factory=dict)
    data_as_of: Mapping[str, datetime] = field(default_factory=dict)
    cache_hits: int = 0
    cache_misses: int = 0
    network_requests: int = 0

    @property
    def counts(self) -> Mapping[Availability, int]:
        """Node counts broken down by availability.

        Returns:
            A mapping with every :class:`~meshprovision.status.merge.
            Availability` member present (zero-filled when a category has
            no members), in :class:`Availability` declaration order.
        """
        counts: dict[Availability, int] = dict.fromkeys(_ALL_AVAILABILITIES, 0)
        for node in self.nodes:
            counts[node.availability] += 1
        return MappingProxyType(counts)

    @property
    def unobserved(self) -> tuple[MergedNode, ...]:
        """Nodes that are in the database but were found by no source.

        Returns:
            Every node with ``in_database`` true and ``observed`` false,
            in report order.
        """
        return tuple(node for node in self.nodes if node.in_database and not node.observed)

    @property
    def has_offline(self) -> bool:
        """Whether any reported node is classified offline.

        Returns:
            ``True`` if any node's availability is
            :attr:`~meshprovision.status.merge.Availability.OFFLINE`.
        """
        return any(node.availability is Availability.OFFLINE for node in self.nodes)

    @property
    def degraded(self) -> bool:
        """Whether this report represents a degraded run.

        No magnitude threshold on :attr:`skipped_entries`/
        :attr:`field_coercions`: even a single skipped entry or
        miscoerced field marks the run degraded, deliberately matching
        how :attr:`has_offline`/:attr:`failures` already work -- neither
        distinguishes "one offline node" from "the whole fleet is
        offline" either. This module's :func:`collect_observations` is
        always called with the operator's own (often small) fleet's ids,
        never a source's full upstream dump, so one skipped entry is
        already a meaningfully large fraction for a typical fleet size,
        not noise to be filtered. The exact counts remain visible in
        :attr:`skipped_entries`/:attr:`field_coercions` for a caller
        that wants to judge magnitude itself (a `--json` consumer, for
        example).

        Returns:
            ``True`` if :attr:`has_offline`, any source failed, any
            source skipped an entry it could not parse, or any source
            reported a field it could not coerce.
        """
        return (
            self.has_offline
            or bool(self.failures)
            or bool(self.skipped_entries)
            or bool(self.field_coercions)
        )

    def exit_code(self, *, fail_on_offline: bool = True) -> int:
        """Compute the process exit code the ``mesh status`` CLI should return.

        A source failure, a source silently skipping an entry it could
        not parse, or a source silently failing to coerce one field of
        an otherwise-parsed entry, always degrades the exit code, since
        a status report built from an incomplete or partially-dropped
        source is not fully trustworthy either way -- see
        :attr:`degraded` for why this has no magnitude threshold. An
        offline node only does so when ``fail_on_offline`` is true.

        Args:
            fail_on_offline: Whether an offline node should count as
                degraded for this call.

        Returns:
            :attr:`~meshprovision.errors.ExitCode.STATUS_DEGRADED` when
            degraded; :attr:`~meshprovision.errors.ExitCode.OK` otherwise.
        """
        is_degraded = (
            bool(self.failures)
            or bool(self.skipped_entries)
            or bool(self.field_coercions)
            or (fail_on_offline and self.has_offline)
        )
        return int(ExitCode.STATUS_DEGRADED) if is_degraded else int(ExitCode.OK)

    def summary(self) -> str:
        """Render a one-line human-readable summary of this report.

        Returns:
            For example ``"5 node(s): 3 online, 1 stale, 0 offline, 1
            unknown; data as of loranet 14:28:03, lorastats 14:32:10
            CEST; 1 source failure(s); 12 unparsable entrie(s) from
            loranet"``. The ``data as of`` clause is omitted entirely
            when :attr:`data_as_of` is empty (every source failed before
            issuing a request, or none were queried).
        """
        counts = self.counts
        breakdown = ", ".join(f"{counts[avail]} {avail.value}" for avail in _ALL_AVAILABILITIES)
        text = f"{len(self.nodes)} node(s): {breakdown}"
        if self.data_as_of:
            parts = ", ".join(
                f"{source} {format_local(timestamp, reference=self.generated_at)}"
                for source, timestamp in self.data_as_of.items()
            )
            text += f"; data as of {parts} {local_tz_abbreviation(self.generated_at)}"
        if self.failures:
            text += f"; {len(self.failures)} source failure(s)"
        if self.skipped_entries:
            parts = ", ".join(
                f"{count} from {source}" for source, count in self.skipped_entries.items()
            )
            total = sum(self.skipped_entries.values())
            text += f"; {total} unparsable entrie(s) ({parts})"
        if self.field_coercions:
            parts = ", ".join(
                f"{count} from {source}" for source, count in self.field_coercions.items()
            )
            total = sum(self.field_coercions.values())
            text += f"; {total} uncoercible field(s) ({parts})"
        return text


def load_records(db_path: Path) -> dict[NodeId, NodeRecord]:
    """Load every node record from the ODS database, strictly read-only.

    Deliberately does not take the cross-process write lock (see
    :mod:`meshprovision.db.locking`): every write replaces the database
    with a single ``os.replace``, so a reader here always sees a complete
    pre- or post-write file, and taking a lock would only make `mesh
    status` block behind a long-running `mesh provision`.

    Args:
        db_path: Path to the ``.ods`` database file.

    Returns:
        A mapping from each node's id to its record, in the database's
        canonical row order (a plain ``dict``'s insertion order,
        following :mod:`meshprovision.db.sorting`'s sort by
        ``long_name`` -- this function never re-sorts it itself).

    Raises:
        meshprovision.errors.SchemaError: If the file cannot be read or
            does not match the expected schema.
        meshprovision.errors.DbValidationError: If any cell fails
            validation.
        meshprovision.errors.DuplicateNodeError: If a ``node_id`` value
            repeats.
        DbIntegrityError: If a cached derived value disagrees with its
            recomputed value while loading, or -- defensively -- if
            merely loading the database somehow marked the in-memory
            session dirty.
    """
    db = OdsDatabase(db_path)
    db.load()
    repo = NodeRepository(db)
    records = {rec.node: rec for rec in repo.all()}
    if db.dirty():
        raise DbIntegrityError(
            "Loading the database marked it dirty; refusing to continue in read-only mode",
            sheet=None,
            cell=None,
        )
    return records


def load_node_ids(db_path: Path) -> tuple[NodeId, ...]:
    """Return every node id in the database, in its canonical row order.

    Args:
        db_path: Path to the ``.ods`` database file.

    Returns:
        Every node id currently in the ``Nodes`` sheet, sorted by
        ``long_name`` (see :mod:`meshprovision.db.sorting`).

    Raises:
        meshprovision.errors.SchemaError: If the file cannot be read or
            does not match the expected schema.
        meshprovision.errors.DbValidationError: If any cell fails
            validation.
        meshprovision.errors.DuplicateNodeError: If a ``node_id`` value
            repeats.
        DbIntegrityError: If a cached derived value disagrees with its
            recomputed value while loading, or if loading marked the
            session dirty.
    """
    return tuple(load_records(db_path).keys())


def collect_observations(
    sources: Sequence[DataSource], ids: Sequence[NodeId], *, force_refresh: bool = False
) -> CollectedObservations:
    """Query every source for the given node ids, tolerating a failing source.

    A source that raises :class:`~meshprovision.errors.DataSourceError`
    (covering ``HttpError``, ``RateLimitError``, ``InvalidResponseError``,
    ``CacheError``, ``NodeNotFoundError``) is recorded as a
    :class:`SourceFailure` and skipped; the remaining sources still run.
    One dead source degrades the report, it never aborts it.
    :class:`~meshprovision.errors.MissingContactError` (a
    :class:`~meshprovision.errors.ConfigError`, not a
    :class:`~meshprovision.errors.DataSourceError`) is deliberately not
    caught here: an unset ``MESHPROVISION_CONTACT`` is a configuration
    failure the operator must fix, so it propagates to the caller.

    A source that *succeeds* but cannot parse every entry it fetched
    (see :attr:`~meshprovision.datasources.base.DataSource.last_fetch_skipped`)
    is a different, quieter failure mode than a `SourceFailure` -- the
    source runs, returns real data, and just silently drops some of it.
    Without surfacing that count, a mass parse-failure (an upstream
    schema change, for example) looks identical to those nodes simply
    being offline.

    Also collects each successful source's
    :attr:`~meshprovision.datasources.base.DataSource.last_fetch_data_as_of`
    into :attr:`CollectedObservations.data_as_of` -- when the data behind
    that source's contribution was actually pulled off the network (the
    original fetch time on a cache hit, not "now"), so a report can state
    how stale its data really is instead of implying every run reflects
    the current instant.

    Args:
        sources: The data sources to query, in the order they were
            configured.
        ids: The node ids to fetch observations for.
        force_refresh: Forwarded to each source's ``fetch_nodes`` call.

    Returns:
        The collected observations, failures, and per-source diagnostic
        counts. See :class:`CollectedObservations`.
    """
    observations: dict[str, dict[NodeId, NodeObservation]] = {}
    failures: list[SourceFailure] = []
    skipped: dict[str, int] = {}
    field_coercions: dict[str, int] = {}
    data_as_of: dict[str, datetime] = {}
    for source in sources:
        try:
            fetched = source.fetch_nodes(ids, force_refresh=force_refresh)
        except DataSourceError as exc:
            failures.append(SourceFailure(source=source.name, message=exc.message, hint=exc.hint))
            _logger.warning("%s data source failed: %s", source.name, exc.message)
            continue
        observations[source.name] = fetched
        if source.last_fetch_skipped:
            skipped[source.name] = source.last_fetch_skipped
        if source.last_fetch_field_coercions:
            field_coercions[source.name] = source.last_fetch_field_coercions
        if source.last_fetch_data_as_of is not None:
            data_as_of[source.name] = source.last_fetch_data_as_of
    return CollectedObservations(
        observations=observations,
        failures=tuple(failures),
        skipped_entries=skipped,
        field_coercions=field_coercions,
        data_as_of=data_as_of,
    )


def build_report(
    *,
    records: Mapping[NodeId, NodeRecord],
    observations_by_source: Mapping[str, Mapping[NodeId, NodeObservation]],
    node_ids: Sequence[NodeId],
    failures: Sequence[SourceFailure] = (),
    now: datetime,
    options: StatusOptions = _DEFAULT_STATUS_OPTIONS,
) -> StatusReport:
    """Assemble a :class:`StatusReport` from already-collected data. Pure.

    Performs no I/O: every input is already in memory. Cache counters
    (``cache_hits``/``cache_misses``/``network_requests``) are left at
    their defaults here; :func:`run_status` copies them in from the
    :class:`~meshprovision.cache.http.CachedHTTPClient` it drove.

    Args:
        records: Every known node's database record, keyed by id.
        observations_by_source: Per-source observation maps, keyed by
            source name.
        node_ids: The node ids to include in the report, in the desired
            output order (:func:`load_node_ids` returns the database's
            canonical, ``long_name``-sorted row order; this function
            never re-sorts it).
        failures: Data sources that failed during collection.
        now: The current time. Must be timezone-aware.
        options: The thresholds to classify availability against
            (``options.thresholds``); other fields of ``options`` are not
            read here -- they shape what the caller already collected.

    Returns:
        The assembled, byte-identical-on-identical-input report.

    Raises:
        ValueError: If ``now`` is not timezone-aware.
    """
    merged = merge_all(
        observations_by_source,
        node_ids=node_ids,
        records=records,
        now=now,
        thresholds=options.thresholds,
    )
    return StatusReport(
        generated_at=now,
        nodes=merged,
        thresholds=options.thresholds,
        failures=tuple(failures),
    )


def run_status(
    settings: Settings,
    options: StatusOptions = _DEFAULT_STATUS_OPTIONS,
    *,
    client: CachedHTTPClient | None = None,
    now: datetime | None = None,
) -> StatusReport:
    """Run one full, read-only status collection and assembly.

    Loads the database (never writing to it), queries the configured
    data sources through a cache-backed HTTP client, and assembles the
    resulting :class:`StatusReport`. ``--watch`` is a CLI concern, not
    this module's: because every request flows through
    :class:`~meshprovision.cache.http.CachedHTTPClient`, calling this
    function again on an interval performs zero network calls as long as
    the calls land inside the cache TTL -- there is no watch loop here.

    Args:
        settings: Application settings (database path, cache directory,
            cache TTL, contact string).
        options: Options shaping this run.
        client: An existing HTTP client to reuse instead of constructing
            one. When given, this function does not own it and will not
            close it -- useful for tests and for a CLI ``--watch`` loop
            that wants to reuse one client (and its cache) across polls.
        now: The current time. Defaults to ``datetime.now(tz=UTC)``.

    Returns:
        The assembled status report.

    Raises:
        meshprovision.errors.MissingContactError: If
            ``MESHPROVISION_CONTACT`` is unset and lorastats is one of
            the configured sources.
        meshprovision.errors.SchemaError: If the database cannot be read
            or does not match the expected schema.
        meshprovision.errors.DbValidationError: If any database cell
            fails validation.
        meshprovision.errors.DuplicateNodeError: If a ``node_id`` value
            repeats in the database.
        DbIntegrityError: If loading the database marked the session
            dirty.
    """
    resolved_now = now if now is not None else datetime.now(tz=UTC)
    needs_lorastats = SOURCE_LORASTATS in options.sources
    lorastats_contact = settings.require_contact() if needs_lorastats else None
    owned_client = client is None
    active_client = client or CachedHTTPClient(
        cache_dir=settings.cache_dir,
        user_agent=settings.user_agent(require_contact=needs_lorastats),
        ttl=settings.cache_ttl,
        force_refresh=options.force_refresh,
    )
    try:
        records = load_records(settings.db_path)
        # An explicit --node request always wins, even for an archived node
        # (the operator asked for it by name); the default "show everything"
        # case excludes archived nodes -- they were deliberately
        # decommissioned via `mesh db forget` and querying/reporting on them
        # every run would just show a permanently "offline" ghost entry.
        ids = options.node_ids or tuple(
            node_id for node_id, record in records.items() if not record.is_archived
        )

        sources: list[DataSource] = []
        if SOURCE_LORANET in options.sources:
            sources.append(LoranetSource(active_client))
        if lorastats_contact is not None:
            sources.append(
                LorastatsSource(active_client, contact=lorastats_contact, regions=options.regions)
            )

        collected = collect_observations(sources, ids, force_refresh=options.force_refresh)
        stats = active_client.stats
        report = build_report(
            records=records,
            observations_by_source=collected.observations,
            node_ids=ids,
            failures=collected.failures,
            now=resolved_now,
            options=options,
        )
        return StatusReport(
            generated_at=report.generated_at,
            nodes=report.nodes,
            thresholds=report.thresholds,
            failures=report.failures,
            skipped_entries=collected.skipped_entries,
            field_coercions=collected.field_coercions,
            data_as_of=collected.data_as_of,
            cache_hits=stats.hits,
            cache_misses=stats.misses,
            network_requests=stats.network_requests,
        )
    finally:
        if owned_client:
            active_client.close()
