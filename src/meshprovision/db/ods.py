"""Validation, recomputation, and session layer for the ``Nodes``/``Keys`` ODS database.

Reading an ODS file's raw sheet contents is
:mod:`meshprovision.db.ods_read`'s job; building and writing one is
:mod:`meshprovision.db.ods_write`'s. This module sits between them: it
validates and coerces :mod:`~meshprovision.db.ods_read`'s raw
``DatabaseData`` into a :class:`LoadedDatabase`
(:func:`load_database`/:func:`parse_database`), and :class:`OdsDatabase`
ties a load/modify/save cycle together, calling into
:mod:`~meshprovision.db.ods_write` on :meth:`OdsDatabase.save`.

**Rows are always sorted**, via :func:`meshprovision.db.sorting.sorted_rows`
-- on load (:func:`load_database`), after every in-memory mutation
(:meth:`OdsDatabase.replace`), and on write
(:func:`meshprovision.db.ods_write.build_document`). This means row order
is no longer a hand-editable property of the file: a sheet's rows always
come back in the same canonical order regardless of insertion history or
how a human last arranged them.
"""

from __future__ import annotations

import contextlib
import logging
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final

from meshprovision.db import (
    cell_validation,
    header_diff,
    locking,
    ods_read,
    ods_write,
    schema,
    sorting,
)
from meshprovision.db.atomic_writer import DEFAULT_RETENTION
from meshprovision.db.known_good import refresh_known_good
from meshprovision.errors import DbIntegrityError, DuplicateNodeError, SchemaError

__all__ = [
    "IntegrityWarning",
    "IntegrityWarningKind",
    "LoadedDatabase",
    "OdsDatabase",
    "load_database",
    "parse_database",
    "verify",
]

_logger = logging.getLogger(__name__)

_TEXT_LIKE_KINDS: Final[frozenset[schema.ColumnKind]] = frozenset(
    {
        schema.ColumnKind.TEXT,
        schema.ColumnKind.NODE_ID,
        schema.ColumnKind.KEY_REF,
        schema.ColumnKind.KEY_REF_LIST,
        schema.ColumnKind.PIN,
        schema.ColumnKind.BASE64_KEY,
    }
)
_COERCED_VALUE_TYPES: Final[frozenset[str]] = frozenset(
    {"float", "percentage", "currency", "date", "time"}
)


class IntegrityWarningKind(StrEnum):
    """What kind of non-fatal integrity problem an :class:`IntegrityWarning` reports."""

    RECOMPUTE = "recompute"
    """A derived cell's cached value disagreed with its recomputed value."""

    COERCED_CELL = "coerced_cell"
    """A text-kind cell was not stored as text, so LibreOffice may have
    coerced its content."""


@dataclass(frozen=True, slots=True)
class IntegrityWarning:
    """One non-fatal integrity problem found while loading a database.

    Attributes:
        sheet: Name of the sheet containing the cell.
        cell: The cell reference, for example ``"Nodes.O3"``.
        column: Name of the affected column.
        cached: The value that was cached in the cell.
        recomputed: The value recomputed from the row's source columns
            (and the value actually used).
        kind: See :class:`IntegrityWarningKind`.
    """

    sheet: str
    cell: str
    column: str
    cached: str = ""
    recomputed: str = ""
    kind: IntegrityWarningKind = IntegrityWarningKind.RECOMPUTE

    def message(self) -> str:
        """Render a human-readable summary of this warning.

        Returns:
            For example ``"Nodes.O3: cached private_key_ref value ... disagrees ..."``.
        """
        if self.kind == IntegrityWarningKind.COERCED_CELL:
            return (
                f"{self.cell}: {self.column} is not formatted as text "
                f"(value type {self.cached!r}); LibreOffice may have coerced its content"
            )
        return (
            f"{self.cell}: cached {self.column} value {self.cached!r} disagrees with "
            f"recomputed value {self.recomputed!r}; using the recomputed value"
        )


@dataclass(frozen=True, slots=True)
class LoadedDatabase:
    """The fully validated, recomputed contents of one ODS database.

    Attributes:
        path: Path to the ODS file that was loaded.
        nodes: Every ``Nodes`` sheet row, validated and with derived
            columns already recomputed.
        keys: Every ``Keys`` sheet row, validated and with derived
            columns already recomputed.
        warnings: Every integrity problem found while loading, across
            both sheets.
    """

    path: Path
    nodes: tuple[Mapping[str, str], ...]
    keys: tuple[Mapping[str, str], ...]
    warnings: tuple[IntegrityWarning, ...]


def _tolerated_headers(sheet_spec: schema.SheetSpec) -> tuple[tuple[str, ...], ...]:
    """Build every header shape :func:`_check_header` accepts for one sheet.

    The first entry is the full, current column list. Each further entry
    drops one more trailing ``legacy_optional`` column, stopping at the
    first trailing column that is not ``legacy_optional`` -- so a
    database written before a ``legacy_optional`` column (for example
    ``Keys.origin``) existed still loads, while a genuinely mangled or
    reordered header still fails.

    Args:
        sheet_spec: The sheet to build tolerated header shapes for.

    Returns:
        At least one entry: ``sheet_spec.column_names()`` itself.
    """
    names = sheet_spec.column_names()
    variants = [names]
    while variants[-1] and sheet_spec.column(variants[-1][-1]).legacy_optional:
        variants.append(variants[-1][:-1])
    return tuple(variants)


def _check_header(sheet_data: ods_read.SheetData, sheet_spec: schema.SheetSpec) -> None:
    """Confirm a sheet's header row matches its expected column order.

    Each cell is stripped before comparing, so incidental leading/
    trailing whitespace (an easy hand-edit slip) is not itself a
    mismatch, and trailing extra blank columns are tolerated entirely --
    order is otherwise strict, since the ODF formulas reference fixed
    column letters. A header missing a trailing run of
    ``legacy_optional`` columns (see :func:`_tolerated_headers`) is
    tolerated too, so a database written before such a column existed
    still loads.

    Args:
        sheet_data: The sheet's raw data.
        sheet_spec: The expected column layout.

    Raises:
        SchemaError: If the header does not match, with a
            :func:`~meshprovision.db.header_diff.describe_header_mismatch`
            table as the message and a best-guess diagnosis as the hint.
    """
    expected_variants = _tolerated_headers(sheet_spec)
    found = tuple(cell.strip() for cell in sheet_data.header)
    while found and not found[-1]:
        found = found[:-1]
    if found in expected_variants:
        return
    message, hint = header_diff.describe_header_mismatch(
        sheet=sheet_spec.name, found=found, expected=expected_variants[0]
    )
    raise SchemaError(message, sheet=sheet_spec.name, hint=hint)


def _check_headers(raw: ods_read.DatabaseData) -> None:
    """Confirm every present sheet's header matches its schema, in one pass.

    Checking both sheets before loading either row means a database with
    two mangled headers (for example, every cell touched by the same
    LibreOffice save) reports both problems in a single ``mesh db
    verify`` run, rather than making the operator fix ``Nodes`` and
    re-run to discover ``Keys`` is broken too.

    Args:
        raw: The database's raw sheet contents.

    Raises:
        SchemaError: If any present sheet's header does not match its
            schema. Naming every offending sheet when more than one
            fails; :func:`_check_header`'s own error, unchanged, when
            exactly one does.
    """
    problems: list[SchemaError] = []
    for sheet_name, sheet_spec in schema.SHEET_SPECS.items():
        sheet_data = raw.sheets.get(sheet_name)
        if sheet_data is None:
            continue
        try:
            _check_header(sheet_data, sheet_spec)
        except SchemaError as exc:
            problems.append(exc)
    if not problems:
        return
    if len(problems) == 1:
        raise problems[0]
    raise SchemaError(
        "\n\n".join(exc.message for exc in problems),
        hint="\n\n".join(f"{exc.sheet}: {exc.hint}" for exc in problems if exc.hint),
    )


def _row_values(
    sheet_spec: schema.SheetSpec, cells: tuple[ods_read.CellValue, ...], ods_row: int
) -> tuple[dict[str, str], list[IntegrityWarning]]:
    """Build a ``{column_name: text}`` map for one row, flagging likely coercion.

    Args:
        sheet_spec: The sheet's column layout.
        cells: The row's raw cells, in column order.
        ods_row: The row's 1-based ODS row number, used only in the
            coercion warning's cell reference.

    Returns:
        A new ``dict`` of raw cell text, one entry per column in
        ``sheet_spec``, and the list of coercion warnings found in this
        row (not yet logged -- the caller decides whether the row is
        blank before doing that).
    """
    values: dict[str, str] = {}
    coercions: list[IntegrityWarning] = []
    for index, col in enumerate(sheet_spec.columns):
        cell = cells[index] if index < len(cells) else ods_read.CellValue(text="")
        if col.kind in _TEXT_LIKE_KINDS and cell.value_type in _COERCED_VALUE_TYPES:
            coercions.append(
                IntegrityWarning(
                    sheet=sheet_spec.name,
                    cell=f"{sheet_spec.name}.{sheet_spec.letter(col.name)}{ods_row}",
                    column=col.name,
                    cached=cell.value_type or "",
                    kind=IntegrityWarningKind.COERCED_CELL,
                )
            )
        if col.kind is schema.ColumnKind.TEXT:
            # office:string-value survives XML attribute-value
            # normalization for a newline (odfpy escapes it as a
            # character reference) but not a literal tab, which gets
            # silently collapsed to a space on the next parse -- the
            # cell's own <text:p> paragraph does not suffer this, and a
            # plain TEXT column never carries a formula, so there is no
            # cached-result-vs-stale-paragraph concern here the way
            # there is for a formula-bearing column like key_ref.
            values[col.name] = cell.paragraph_text
        else:
            values[col.name] = cell.text
    return values, coercions


def _apply_recompute(
    sheet_spec: schema.SheetSpec,
    validated: Mapping[str, str],
    ods_row: int,
    warnings: list[IntegrityWarning],
) -> dict[str, str]:
    """Recompute every derived column and reconcile it against its cached value.

    A cached value that is empty is silently replaced. A cached value
    that disagrees with the recomputed value produces an
    :class:`IntegrityWarning` (appended to ``warnings`` and logged) --
    either way, the recomputed value is what is used.

    Args:
        sheet_spec: The row's column layout.
        validated: The row's already-validated values.
        ods_row: The row's 1-based ODS row number, used in the warning's
            cell reference.
        warnings: Mutable list warnings are appended to.

    Returns:
        A new ``dict`` combining ``validated`` with every derived
        column's recomputed value.
    """
    merged = dict(validated)
    recomputed = schema.recompute_derived(sheet_spec, validated)
    for column, new_value in recomputed.items():
        cached = validated.get(column, "")
        if cached and cached != new_value:
            warning = IntegrityWarning(
                sheet=sheet_spec.name,
                cell=f"{sheet_spec.name}.{sheet_spec.letter(column)}{ods_row}",
                column=column,
                cached=cached,
                recomputed=new_value,
            )
            warnings.append(warning)
            _logger.warning("%s", warning.message())
        merged[column] = new_value
    return merged


def _load_sheet_rows(
    sheet_data: ods_read.SheetData,
    sheet_spec: schema.SheetSpec,
    warnings: list[IntegrityWarning],
) -> tuple[Mapping[str, str], ...]:
    """Validate and recompute every row of one sheet.

    Args:
        sheet_data: The sheet's raw data.
        sheet_spec: The sheet's expected column layout.
        warnings: Mutable list warnings are appended to.

    Returns:
        Every non-blank row, validated and with derived columns
        recomputed.

    Raises:
        SchemaError: If the sheet's header does not match its schema.
        DbValidationError: If any cell fails validation.
    """
    _check_header(sheet_data, sheet_spec)
    records: list[Mapping[str, str]] = []
    ods_row = sheet_data.first_data_row
    for cells in sheet_data.rows:
        raw_values, coercions = _row_values(sheet_spec, cells, ods_row)
        if all(not value.strip() for value in raw_values.values()):
            ods_row += 1
            continue
        for coercion in coercions:
            warnings.append(coercion)
            _logger.warning("%s", coercion.message())
        validated = cell_validation.validate_row(sheet_spec, ods_row, raw_values)
        records.append(_apply_recompute(sheet_spec, validated, ods_row, warnings))
        ods_row += 1
    return tuple(records)


def _check_unique_node_ids(nodes: Sequence[Mapping[str, str]]) -> None:
    """Confirm no ``node_id`` value repeats across the ``Nodes`` sheet.

    Args:
        nodes: The sheet's validated rows.

    Raises:
        DuplicateNodeError: If a ``node_id`` value appears more than once.
    """
    seen: set[str] = set()
    for row in nodes:
        node_id = row.get("node_id", "")
        if not node_id:
            continue
        if node_id in seen:
            raise DuplicateNodeError(
                f"Duplicate node_id in {schema.NODES_SHEET} sheet: {node_id!r}",
                node_id=node_id,
                sheet=schema.NODES_SHEET,
            )
        seen.add(node_id)


def _check_unique_key_refs(keys: Sequence[Mapping[str, str]]) -> None:
    """Confirm no ``key_ref`` value repeats across the ``Keys`` sheet.

    Args:
        keys: The sheet's validated rows.

    Raises:
        DbIntegrityError: If a ``key_ref`` value appears more than once.
    """
    seen: set[str] = set()
    for row in keys:
        key_ref = row.get("key_ref", "")
        if not key_ref:
            continue
        if key_ref in seen:
            raise DbIntegrityError(
                f"Duplicate key_ref in {schema.KEYS_SHEET} sheet: {key_ref!r}",
                sheet=schema.KEYS_SHEET,
                cell=key_ref,
            )
        seen.add(key_ref)


def parse_database(data: bytes, *, source: Path) -> LoadedDatabase:
    """Validate and recompute an ODS database's full contents, from bytes already in hand.

    The side-effect-free half of :func:`load_database`: no file I/O, and
    no known-good refresh. This is what lets a restore validate a backup
    file's bytes *before* they are written anywhere -- calling
    :func:`load_database` directly on a backup path would be wrong for
    that use, since it would refresh the known-good copy for the
    backup's own path rather than the live database's.

    Args:
        data: The full contents of an ``.ods`` file.
        source: Path to name in any error message. Not read -- ``data``
            is used as-is, regardless of what currently sits at this
            path, or whether anything does.

    Returns:
        The fully validated database, with both sheets' rows sorted into
        their canonical order (see :mod:`meshprovision.db.sorting`)
        regardless of the data's own row order. Its ``path`` is
        ``source``.

    Raises:
        SchemaError: If ``data`` is not valid ODF content, is missing
            the ``Nodes`` or ``Keys`` sheet, or either sheet's header
            does not match its schema.
        DbValidationError: If any cell fails validation.
        DuplicateNodeError: If ``Nodes.node_id`` has a duplicate.
        DbIntegrityError: If ``Keys.key_ref`` has a duplicate.
    """
    started = time.monotonic()
    raw = ods_read.read_raw(source, data=data)
    for sheet_name in schema.SHEET_NAMES:
        if sheet_name not in raw.sheets:
            raise SchemaError(
                f"{source} is missing the required {sheet_name!r} sheet", sheet=sheet_name
            )
    _check_headers(raw)

    warnings: list[IntegrityWarning] = []
    nodes = _load_sheet_rows(raw.sheets[schema.NODES_SHEET], schema.NODES_SHEET_SPEC, warnings)
    keys = _load_sheet_rows(raw.sheets[schema.KEYS_SHEET], schema.KEYS_SHEET_SPEC, warnings)

    # Sorted after warnings are collected (they cite the original ods_row
    # numbers) but before the uniqueness checks below, which don't care
    # about order -- see meshprovision.db.sorting.
    nodes = sorting.sorted_rows(schema.NODES_SHEET, nodes)
    keys = sorting.sorted_rows(schema.KEYS_SHEET, keys)

    _check_unique_node_ids(nodes)
    _check_unique_key_refs(keys)

    _logger.debug(
        "Parsed %s in %.2fs: %d node(s), %d key(s), %d warning(s).",
        source,
        time.monotonic() - started,
        len(nodes),
        len(keys),
        len(warnings),
    )
    return LoadedDatabase(path=source, nodes=nodes, keys=keys, warnings=tuple(warnings))


def load_database(path: Path) -> LoadedDatabase:
    """Read, validate, and recompute an ODS database's full contents.

    Args:
        path: Path to the ``.ods`` file.

    Returns:
        The fully validated database, with both sheets' rows sorted into
        their canonical order (see :mod:`meshprovision.db.sorting`)
        regardless of the file's own row order.

    Raises:
        DbReadError: If the file cannot be opened or read (permissions, I/O).
        SchemaError: If the file is not valid ODF content, is missing
            the ``Nodes`` or ``Keys`` sheet, or either sheet's header
            does not match its schema.
        DbValidationError: If any cell fails validation.
        DuplicateNodeError: If ``Nodes.node_id`` has a duplicate.
        DbIntegrityError: If ``Keys.key_ref`` has a duplicate.

    On success, also best-effort refreshes the file's known-good safety
    copy (see :func:`meshprovision.db.known_good.refresh_known_good`)
    -- every successful load, not just a write, since a load having
    reached this point is itself proof the file is currently valid. The
    copy is written from the exact bytes read and validated here, via
    :func:`meshprovision.db.ods_read._read_db_file`, never by re-opening
    ``path`` afterwards -- so a write landing between validation and the
    refresh can never publish unvalidated content as "known-good". Never
    fails the load: a refresh failure (full disk, read-only backup
    directory) is logged and swallowed, not raised.
    """
    data, stat_result = ods_read._read_db_file(path)
    loaded = parse_database(data, source=path)
    refresh_known_good(path, content=data, source_stat=stat_result)
    return loaded


def verify(path: Path) -> tuple[IntegrityWarning, ...]:
    """Load a database purely to collect its integrity warnings.

    Args:
        path: Path to the ``.ods`` file.

    Returns:
        Every cached-vs-recomputed disagreement found while loading.

    Raises:
        DbReadError: If the file cannot be opened or read (permissions, I/O).
        SchemaError: If the file is not valid ODF content or does not match its schema.
        DbValidationError: If any cell fails validation.
        DuplicateNodeError: If ``Nodes.node_id`` has a duplicate.
        DbIntegrityError: If ``Keys.key_ref`` has a duplicate.
    """
    return load_database(path).warnings


class OdsDatabase:
    """A read/modify/write session over one ODS file.

    Untyped at this layer: every row is a plain ``dict[str, str]`` keyed
    by column name. db-facade wraps this class with typed repositories.
    ``nodes.py`` and ``keys.py`` both wrap the *same* :class:`OdsDatabase`
    instance so that a single :meth:`save` call writes both sheets
    atomically, in one file, in one backup.

    Concurrency safety is opt-in via :meth:`lock`. A read-only session
    never needs it: every write replaces ``path`` with a single
    ``os.replace()`` (see :mod:`meshprovision.db.atomic_writer`), so a
    reader's :meth:`load` always sees a complete pre- or post-write file,
    never a torn one. A session that may run concurrently with another
    ``mesh`` process holding a write intent must call :meth:`lock`
    *before* :meth:`load` and hold it through :meth:`save` -- see
    :meth:`lock` and :meth:`save` for why the span matters.
    """

    def __init__(
        self, path: Path, *, backup_dir: Path | None = None, retention: int = DEFAULT_RETENTION
    ) -> None:
        """Initialize a session over ``path``, without reading it yet.

        Args:
            path: Path to the ``.ods`` file.
            backup_dir: Directory to store backups under on :meth:`save`.
            retention: Number of backups to retain on :meth:`save`.
        """
        self._path = path
        self._backup_dir = backup_dir
        self._retention = retention
        self._loaded = False
        self._is_dirty = False
        self._warnings: tuple[IntegrityWarning, ...] = ()
        self._rows: dict[str, tuple[Mapping[str, str], ...]] = {}
        self._lock_cm: contextlib.AbstractContextManager[None] | None = None

    @property
    def path(self) -> Path:
        """Path to the ``.ods`` file this session manages.

        Returns:
            The path passed to the constructor.
        """
        return self._path

    @property
    def loaded(self) -> bool:
        """Whether :meth:`load` has populated this session's rows.

        Returns:
            ``True`` once at least one successful load has completed.
        """
        return self._loaded

    @property
    def warnings(self) -> tuple[IntegrityWarning, ...]:
        """Integrity warnings collected by the most recent load.

        Returns:
            The warnings from the last :meth:`load` call.
        """
        return self._warnings

    def lock(self, *, timeout: float | None = None) -> None:
        """Acquire the cross-process write lock for this database.

        Must be called before :meth:`load` -- locking after the read
        would leave a window in which another process's write lands
        between the two, reintroducing the stale-snapshot race this
        exists to close. A no-op if already held by this session.

        Args:
            timeout: Seconds to poll before giving up. ``None`` (the
                default) defers to :func:`meshprovision.db.locking.
                exclusive_lock`'s own resolution (an explicit argument,
                then the ``MESHPROVISION_LOCK_TIMEOUT`` environment
                variable, then
                :data:`~meshprovision.db.locking.DEFAULT_LOCK_TIMEOUT`).

        Raises:
            DatabaseLockedError: If another process holds the lock and
                does not release it within the resolved timeout.
            AtomicWriteError: If the sidecar lock file itself cannot be
                created or acquired.
            SettingsError: If ``MESHPROVISION_LOCK_TIMEOUT`` is set to a
                malformed value.
        """
        if self._lock_cm is not None:
            return
        cm = locking.exclusive_lock(self._path, timeout=timeout)
        cm.__enter__()
        self._lock_cm = cm

    def unlock(self) -> None:
        """Release the cross-process write lock. Idempotent.

        A no-op when the lock is not currently held by this session.
        """
        if self._lock_cm is None:
            return
        cm = self._lock_cm
        self._lock_cm = None
        cm.__exit__(None, None, None)

    def __enter__(self) -> OdsDatabase:
        """Enter as a context manager, unlocking on exit.

        Returns:
            This instance.
        """
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Release the write lock, if held. Delegates to :meth:`unlock`.

        Args:
            *exc_info: The exception triple, unused -- the lock is
                released the same way whether the block raised or not.
        """
        self.unlock()

    def load(self, *, force: bool = False) -> None:
        """Load the database from disk, unless already loaded.

        Args:
            force: When true, reload even if already loaded, discarding
                any unsaved in-memory changes.

        Raises:
            DbReadError: If the file cannot be opened or read (permissions, I/O).
            SchemaError: If the file is not valid ODF content or does not match its schema.
            DbValidationError: If any cell fails validation.
            DuplicateNodeError: If ``Nodes.node_id`` has a duplicate.
            DbIntegrityError: If ``Keys.key_ref`` has a duplicate.
        """
        if self._loaded and not force:
            return
        loaded = load_database(self._path)
        self._rows = {schema.NODES_SHEET: loaded.nodes, schema.KEYS_SHEET: loaded.keys}
        self._warnings = loaded.warnings
        self._loaded = True
        self._is_dirty = False

    def rows(self, sheet: str) -> tuple[Mapping[str, str], ...]:
        """Return one sheet's current in-memory rows, loading first if needed.

        Args:
            sheet: The sheet name (``"Nodes"`` or ``"Keys"``).

        Returns:
            The sheet's rows.

        Raises:
            SchemaError: If ``sheet`` is not a known sheet name.
        """
        self.load()
        if sheet not in self._rows:
            raise SchemaError(f"Unknown sheet: {sheet!r}", sheet=sheet)
        return self._rows[sheet]

    def replace(self, sheet: str, rows: Sequence[Mapping[str, str]]) -> None:
        """Replace one sheet's in-memory rows. Does not touch disk.

        The stored rows are sorted into their canonical order (see
        :mod:`meshprovision.db.sorting`) regardless of the order passed
        in, so a subsequent :meth:`rows` call -- and thus ``mesh db
        list``/``mesh status`` -- reflects the new order immediately,
        within the same session, without waiting for a save/reload.

        Args:
            sheet: The sheet name (``"Nodes"`` or ``"Keys"``).
            rows: The new full set of rows for ``sheet``.

        Raises:
            SchemaError: If ``sheet`` is not a known sheet name.
        """
        self.load()
        if sheet not in schema.SHEET_SPECS:
            raise SchemaError(f"Unknown sheet: {sheet!r}", sheet=sheet)
        self._rows[sheet] = sorting.sorted_rows(sheet, tuple(dict(row) for row in rows))
        self._is_dirty = True

    def dirty(self) -> bool:
        """Whether there are in-memory changes not yet written to disk.

        Returns:
            ``True`` if :meth:`replace` has been called since the last
            load or save.
        """
        return self._is_dirty

    def save(self, *, backup: bool = True) -> None:
        """Write both sheets to disk atomically. A no-op when not dirty.

        Does **not** acquire the write lock itself -- a caller that may
        run concurrently with another ``mesh`` process must hold it
        across the whole load-modify-save cycle via :meth:`lock`, not
        just around this call: re-acquiring only here would leave this
        session's in-memory state stale relative to a write that landed
        after :meth:`load` but before :meth:`lock`, and locking again
        while already held would need re-entrancy bookkeeping this class
        does not have. :meth:`~meshprovision.cli.common.CliContext.
        open_database` does this for you.

        Args:
            backup: Whether to back up the current file before replacing
                it.

        Raises:
            AtomicWriteError: If the write or backup fails.
        """
        if not self._is_dirty:
            _logger.debug("save() called on a clean database; nothing to write.")
            return
        started = time.monotonic()
        ods_write.write_database(
            self._path,
            nodes=self._rows.get(schema.NODES_SHEET, ()),
            keys=self._rows.get(schema.KEYS_SHEET, ()),
            backup=backup,
            backup_dir=self._backup_dir,
            retention=self._retention,
        )
        self._is_dirty = False
        _logger.debug(
            "Saved %s in %.2fs (backup=%s): %d node(s), %d key(s).",
            self._path,
            time.monotonic() - started,
            backup,
            len(self._rows.get(schema.NODES_SHEET, ())),
            len(self._rows.get(schema.KEYS_SHEET, ())),
        )

    @classmethod
    def create(
        cls, path: Path, *, overwrite: bool = False, backup_dir: Path | None = None
    ) -> OdsDatabase:
        """Create a brand-new, empty ODS database and open a session over it.

        Args:
            path: Path to create the ``.ods`` file at.
            overwrite: Whether to replace an existing file at ``path``.
            backup_dir: Directory to store future backups under.

        Returns:
            A loaded :class:`OdsDatabase` session over the new, empty
            database.

        Raises:
            SchemaError: If ``path`` already exists and ``overwrite`` is
                false.
            AtomicWriteError: If the write fails.
        """
        if path.exists() and not overwrite:
            raise SchemaError(f"{path} already exists; pass overwrite=True to replace it")
        ods_write.create_empty(path, backup=False)
        instance = cls(path, backup_dir=backup_dir)
        instance.load(force=True)
        return instance
