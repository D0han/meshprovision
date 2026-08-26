"""Shared CLI plumbing for every ``mesh`` subcommand.

This module owns the single structlog configuration for the whole
process (:func:`configure_logging`), and installs
:func:`meshprovision.crypto.redact.redact_processor` as the **last**
processor before the renderer, exactly per that module's own contract --
every other processor (including one that might flatten a nested
structure into a string) runs before the redactor sees the event, so
nothing skips the scrub.

Every log line and every human-facing message this module prints goes to
**STDERR**. That keeps STDOUT free for machine-readable output --
``--json`` documents and the ``mesh status`` rich table -- so a
downstream ``jq`` pipeline never has to filter out a stray log line or
prompt. See :class:`CliContext` (``out``/``err`` consoles) and
:func:`echo_json` (always ``click.echo``, always STDOUT).

The error boundary, :func:`handle_cli_errors`, never prints a raw
Python traceback for a deliberate :class:`~meshprovision.errors.
MeshprovisionError` -- it prints ``exc.user_message`` and exits with the
error's mapped code. An exception that is *not* one of the four kinds
this boundary catches is, by the project's own exception discipline, a
bug: it is allowed to propagate as an ordinary traceback rather than
being masked, and that traceback is safe because every value this
project routes through :class:`~meshprovision.crypto.redact.SecretBytes`
already renders redacted regardless of context.

This module imports nothing from :mod:`meshprovision.cli.main` or any
command module -- only downward, from the earlier layers.
"""

from __future__ import annotations

import functools
import json
import logging
import sys
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Final, ParamSpec, TypeVar

import click
import structlog
from rich.console import Console

from meshprovision.config import template as template_module
from meshprovision.config.settings import Settings, load_settings
from meshprovision.crypto import redact
from meshprovision.errors import (
    AmbiguousDeviceError,
    ExitCode,
    MeshprovisionError,
    NonInteractiveError,
    SchemaError,
    exit_code_for,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path
    from typing import TextIO

    from meshprovision.cache.http import CachedHTTPClient
    from meshprovision.config.template import TemplateConfig
    from meshprovision.db.keys import KeyRepository
    from meshprovision.db.nodes import NodeRepository
    from meshprovision.db.ods import OdsDatabase

__all__ = [
    "CONTEXT_SETTINGS",
    "DEFAULT_JSON_INDENT",
    "LOG_LEVELS",
    "CliContext",
    "DbSession",
    "build_settings",
    "configure_logging",
    "echo_json",
    "handle_cli_errors",
    "pass_cli",
    "resolve_non_interactive",
]

_logger = logging.getLogger(__name__)

CONTEXT_SETTINGS: Final[dict[str, Any]] = {
    "help_option_names": ["-h", "--help"],
    "max_content_width": 100,
}
"""Shared click context settings for the ``mesh`` group and every subcommand."""

DEFAULT_JSON_INDENT: Final[int] = 2
"""Default indent width for :func:`echo_json`."""

LOG_LEVELS: Final[tuple[str, ...]] = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
"""The logging verbosities accepted by ``--log-level``."""

_NOISY_WARNING_ONLY: Final[tuple[str, ...]] = ("httpcore", "bleak", "urllib3")
"""Third-party loggers forced to WARNING regardless of the resolved level."""

_NOISY_AT_LEAST_WARNING: Final[tuple[str, ...]] = ("httpx", "meshtastic")
"""Third-party loggers floored at WARNING but allowed louder if requested."""

_ERR_CONSOLE: Final[Console] = Console(stderr=True)
"""Module-level stderr console used by :func:`_emit_error`."""


def _build_shared_processors() -> list[structlog.typing.Processor]:
    """Build the processor chain shared by structlog- and stdlib-originated events.

    Deliberately omits ``structlog.stdlib.add_logger_name``'s sibling
    ``structlog.processors.UnicodeDecoder`` -- decoding raw ``bytes``
    values into ``str`` before :func:`meshprovision.crypto.redact.
    redact_processor` runs would let key-shaped bytes slip past the
    byte-aware half of that scrubber.

    Returns:
        The processor list to use as both ``structlog.configure``'s
        ``processors`` prefix and ``ProcessorFormatter``'s
        ``foreign_pre_chain``.
    """
    return [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
    ]


def _resolve_colors(colors: bool | None) -> bool:
    """Resolve whether the console renderer should emit ANSI colors.

    Args:
        colors: An explicit override, or ``None`` to auto-detect from
            whether stderr is a TTY.

    Returns:
        ``colors`` unchanged when given; otherwise ``sys.stderr.isatty()``,
        defaulting to ``False`` if that check itself fails.
    """
    if colors is not None:
        return colors
    try:
        return sys.stderr.isatty()
    except (AttributeError, OSError, ValueError):
        return False


def _quiet_third_party_loggers(numeric_level: int) -> None:
    """Floor noisy third-party loggers at WARNING regardless of ``--log-level``.

    Args:
        numeric_level: The resolved numeric level for the root logger,
            used to keep ``httpx``/``meshtastic`` at least as verbose as
            WARNING without ever making them quieter than the operator
            asked for.
    """
    for name in _NOISY_WARNING_ONLY:
        logging.getLogger(name).setLevel(logging.WARNING)
    for name in _NOISY_AT_LEAST_WARNING:
        logging.getLogger(name).setLevel(max(numeric_level, logging.WARNING))


def configure_logging(
    level: str, *, stream: TextIO | None = None, colors: bool | None = None
) -> None:
    """Configure the process-wide structlog + stdlib logging pipeline.

    The single place structlog is configured. Every earlier-layer module
    logs through stdlib ``logging.getLogger(__name__)``, so stdlib
    records are routed through the same ``structlog.stdlib.
    ProcessorFormatter`` chain as structlog-native events -- including
    :func:`meshprovision.crypto.redact.redact_processor`, which runs
    first in the formatter's ``processors`` list so it is the last thing
    to touch the event dict before ``remove_processors_meta``/render.

    ``exception_formatter=structlog.dev.plain_traceback`` is passed to
    the renderer deliberately: ``ConsoleRenderer``'s own default is a
    ``RichTracebackFormatter(show_locals=True)``, which would print local
    variables -- i.e. potentially raw key material -- into the log on any
    traceback.

    Idempotent: calling this twice never duplicates handlers, since the
    root logger's existing handlers are removed first.

    Args:
        level: The logging verbosity. Must be one of :data:`LOG_LEVELS`.
        stream: The stream to attach the handler to. Defaults to
            ``sys.stderr``.
        colors: Whether to emit ANSI colors. ``None`` auto-detects from
            whether the target stream is a TTY.

    Raises:
        SchemaError: If ``level`` is not one of :data:`LOG_LEVELS`.
    """
    normalized = level.strip().upper()
    if normalized not in LOG_LEVELS:
        raise SchemaError(
            f"Unknown log level: {level!r}",
            hint=f"Choose one of: {', '.join(LOG_LEVELS)}.",
        )
    numeric_level = logging.getLevelNamesMapping()[normalized]

    shared = _build_shared_processors()
    renderer = structlog.dev.ConsoleRenderer(
        colors=_resolve_colors(colors),
        exception_formatter=structlog.dev.plain_traceback,
        sort_keys=True,
    )
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared,
        processors=[
            redact.redact_processor,
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(numeric_level)

    structlog.configure(
        processors=[*shared, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )

    _quiet_third_party_loggers(numeric_level)


def resolve_non_interactive(flag: bool | None) -> bool:
    """Resolve the effective ``--non-interactive`` setting.

    Args:
        flag: The value of the ``--non-interactive/--interactive`` click
            option, or ``None`` when the operator did not pass either.

    Returns:
        ``flag`` when it is not ``None``; otherwise ``True`` unless
        stdin is a TTY. A closed or detached stdin (raising
        ``AttributeError``, ``OSError``, or ``ValueError``) is treated as
        non-interactive.
    """
    if flag is not None:
        return flag
    try:
        return not sys.stdin.isatty()
    except (AttributeError, OSError, ValueError):
        return True


def build_settings(
    *,
    env_file: Path | None = None,
    db_path: Path | None = None,
    template_path: Path | None = None,
    cache_ttl: float | None = None,
    log_level: str | None = None,
) -> Settings:
    """Build a :class:`Settings` instance from ``.env``, the environment, and CLI overrides.

    Args:
        env_file: An explicit ``.env`` file to read, from ``--env-file``.
        db_path: Override for the ODS database path, from ``--db-path``.
        template_path: Override for the template path, from
            ``--template-path``.
        cache_ttl: Override for the HTTP cache TTL, from ``--cache-ttl``.
        log_level: Override for the log level, from ``--log-level``.
            Upper-cased before being passed through.

    Returns:
        The validated, layered :class:`Settings`.

    Raises:
        SettingsError: If the layered values fail validation.
    """
    overrides = {
        key: value
        for key, value in (
            ("db_path", db_path),
            ("template_path", template_path),
            ("cache_ttl", cache_ttl),
            ("log_level", log_level.upper() if log_level else None),
        )
        if value is not None
    }
    return load_settings(env_file=env_file, overrides=overrides)


def echo_json(payload: object, *, indent: int = DEFAULT_JSON_INDENT) -> None:
    """Print a JSON document to STDOUT.

    Always ``click.echo`` to STDOUT, never a rich ``Console`` -- so
    markup is never interpreted and lines are never wrapped, keeping the
    output machine-parseable.

    Args:
        payload: The value to serialize. Anything ``json.dumps`` cannot
            natively encode (a ``datetime``, a ``Path``, ...) is rendered
            via ``str()`` rather than raising.
        indent: The indentation width to pass to ``json.dumps``.
    """
    click.echo(json.dumps(payload, indent=indent, ensure_ascii=False, default=str))


def _emit_error(text: str) -> None:
    """Print one error line to stderr, redacted, unstyled by markup.

    Args:
        text: The error text to print. Passed through
            :func:`meshprovision.crypto.redact.scrub_text` as defence in
            depth before being printed.
    """
    _ERR_CONSOLE.print(redact.scrub_text(text), style="red", markup=False, highlight=False)


P = ParamSpec("P")
R = TypeVar("R")


def handle_cli_errors(func: Callable[P, R]) -> Callable[P, R | None]:
    """Wrap a click callback with the CLI's single error-to-exit-code boundary.

    Catches exactly four exception kinds, in this order, and nothing
    else -- an exception outside this list is a bug and is allowed to
    propagate as an ordinary traceback:

    - :class:`~meshprovision.errors.MeshprovisionError`: prints
      ``exc.user_message`` to stderr, logs the full traceback at DEBUG,
      and exits with the error's own mapped code.
    - ``click.Abort``: prints ``"Aborted."`` and exits
      :attr:`~meshprovision.errors.ExitCode.INTERRUPTED`.
    - ``KeyboardInterrupt``: exits
      :attr:`~meshprovision.errors.ExitCode.INTERRUPTED` silently.
    - ``OSError``: prints ``f"{type(exc).__name__}: {exc}"`` and exits
      :attr:`~meshprovision.errors.ExitCode.ERROR`.

    Deliberately does not catch ``SystemExit`` (or
    ``click.exceptions.Exit``): commands raise ``SystemExit(code)``
    themselves for a deliberate non-zero result, and
    ``click.testing.CliRunner`` records that code directly.

    Args:
        func: The click callback to wrap.

    Returns:
        A wrapped callback with the same signature, returning ``None``
        on every path that raises ``SystemExit`` instead of returning
        normally.
    """

    @functools.wraps(func)
    def _wrapper(*args: P.args, **kwargs: P.kwargs) -> R | None:
        try:
            return func(*args, **kwargs)
        except MeshprovisionError as exc:
            _emit_error(exc.user_message)
            _logger.debug("command failed", exc_info=True)
            raise SystemExit(exit_code_for(exc)) from None
        except click.Abort:
            _emit_error("Aborted.")
            raise SystemExit(int(ExitCode.INTERRUPTED)) from None
        except KeyboardInterrupt:
            raise SystemExit(int(ExitCode.INTERRUPTED)) from None
        except OSError as exc:
            _emit_error(f"{type(exc).__name__}: {exc}")
            raise SystemExit(int(ExitCode.ERROR)) from None

    return _wrapper


@dataclass(frozen=True, slots=True)
class DbSession:
    """A bundle of the open database plus its two typed repositories.

    Returned by :meth:`CliContext.open_database` so a command can reach
    the raw session (for ``db.save()``), the node repository, and the
    key repository without three separate lookups.

    A context manager: ``with ctx.open_database(for_write=True) as db:``
    releases the write lock (a no-op when ``for_write`` was false) on
    exit, including on an exception. Explicit release matters here, not
    just as hygiene -- ``tests/e2e/`` drives the CLI in-process via
    ``click.testing.CliRunner``, so relying on process-exit fd cleanup
    would leave the lock held across test cases and deadlock the next
    one that needs it.

    Attributes:
        db: The open, loaded :class:`~meshprovision.db.ods.OdsDatabase`
            session.
        nodes: A :class:`~meshprovision.db.nodes.NodeRepository` over
            ``db``.
        keys: A :class:`~meshprovision.db.keys.KeyRepository` over
            ``db``.
    """

    db: OdsDatabase
    nodes: NodeRepository
    keys: KeyRepository

    @property
    def path(self) -> Path:
        """Path to the underlying ``.ods`` file.

        Returns:
            ``self.db.path``.
        """
        return self.db.path

    def __enter__(self) -> DbSession:
        """Enter as a context manager.

        Returns:
            This instance.
        """
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Release the write lock, if held.

        Args:
            *exc_info: The exception triple, unused -- the lock is
                released the same way whether the block raised or not.
        """
        self.db.unlock()


@dataclass(frozen=True, slots=True)
class CliContext:
    """The object every ``mesh`` subcommand receives via :data:`pass_cli`.

    Immutable, per the project's convention: a command that needs a
    changed field (currently only ``assume_yes``, via the per-command
    ``--yes`` flag) calls :meth:`with_assume_yes` to get a new instance
    rather than mutating this one.

    Attributes:
        settings: The layered, validated application settings.
        non_interactive: Whether every prompt should raise
            :class:`~meshprovision.errors.NonInteractiveError` instead of
            prompting. Resolved once, globally, in ``cli.main.cli``.
        force_refresh: Whether the HTTP cache should bypass reads
            (``--no-cache``/``--force-refresh``). Reads are bypassed;
            writes still happen.
        assume_yes: Whether :meth:`confirm` should short-circuit to
            ``True`` without prompting. Per-command, via ``--yes``.
        out: A ``rich`` console bound to STDOUT -- machine-readable
            output only.
        err: A ``rich`` console bound to STDERR -- logging, prompts,
            warnings, and errors.
    """

    settings: Settings
    non_interactive: bool
    force_refresh: bool
    assume_yes: bool
    out: Console
    err: Console

    @classmethod
    def build(cls, *, settings: Settings, non_interactive: bool, force_refresh: bool) -> CliContext:
        """Construct a :class:`CliContext` with fresh consoles and ``assume_yes=False``.

        Args:
            settings: The layered, validated application settings.
            non_interactive: The resolved ``--non-interactive`` setting.
            force_refresh: The resolved cache-bypass setting.

        Returns:
            A new :class:`CliContext`.
        """
        return cls(
            settings=settings,
            non_interactive=non_interactive,
            force_refresh=force_refresh,
            assume_yes=False,
            out=Console(),
            err=Console(stderr=True),
        )

    def with_assume_yes(self, value: bool) -> CliContext:
        """Return a copy of this context with ``assume_yes`` replaced.

        Args:
            value: The new ``assume_yes`` value.

        Returns:
            A new :class:`CliContext`; ``self`` is never mutated.
        """
        return replace(self, assume_yes=value)

    def info(self, message: str) -> None:
        """Print an informational message to stderr, unstyled.

        Args:
            message: The message to print.
        """
        self.err.print(message, markup=False, highlight=False)

    def warn(self, message: str) -> None:
        """Print a warning message to stderr, prefixed and styled yellow.

        Args:
            message: The message to print.
        """
        self.err.print(f"warning: {message}", style="yellow", markup=False, highlight=False)

    def error(self, message: str) -> None:
        """Print an error message to stderr, prefixed and styled red.

        Args:
            message: The message to print.
        """
        self.err.print(f"error: {message}", style="red", markup=False, highlight=False)

    def success(self, message: str) -> None:
        """Print a success message to stderr, styled green.

        Args:
            message: The message to print.
        """
        self.err.print(message, style="green", markup=False, highlight=False)

    def print_out(self, text: str) -> None:
        """Print machine-relevant human text to STDOUT.

        Args:
            text: The text to print. Not JSON -- use :func:`echo_json`
                for that.
        """
        self.out.print(text, markup=False, highlight=False, soft_wrap=True)

    def confirm(self, question: str, *, default: bool = False) -> bool:
        """Ask a yes/no question, honouring ``assume_yes`` and ``non_interactive``.

        Args:
            question: The question to ask.
            default: The default answer if the operator just presses
                enter.

        Returns:
            ``True`` immediately if :attr:`assume_yes` is set (logged at
            DEBUG rather than prompted). Otherwise the operator's answer.
            A declined confirmation returns ``False`` -- the caller
            decides what to do next (typically raising ``click.Abort()``).

        Raises:
            NonInteractiveError: If :attr:`non_interactive` is set and
                :attr:`assume_yes` is not.
        """
        if self.assume_yes:
            _logger.debug("auto-confirming (assume_yes set): %s", question)
            return True
        if self.non_interactive:
            raise NonInteractiveError(
                f"Confirmation required but this run is non-interactive: {question}",
                prompt=question,
                hint="Pass --yes to confirm without prompting.",
            )
        return bool(click.confirm(question, default=default, err=True))

    def prompt(self, question: str, *, default: str | None = None) -> str:
        """Ask an open-ended question, honouring ``non_interactive``.

        Args:
            question: The question to ask.
            default: The default answer if the operator just presses
                enter.

        Returns:
            The operator's stripped answer.

        Raises:
            NonInteractiveError: If :attr:`non_interactive` is set.
        """
        if self.non_interactive:
            raise NonInteractiveError(
                f"Input required but this run is non-interactive: {question}",
                prompt=question,
                hint="Supply the value via a command-line option instead.",
            )
        answer = click.prompt(
            question, default=default, err=True, show_default=default is not None, type=str
        )
        return str(answer).strip()

    def choose(self, summaries: Sequence[str], prompt: str) -> int:
        """Ask the operator to pick one of several candidates.

        Args:
            summaries: One human-readable summary line per candidate,
                shown numbered starting at 1.
            prompt: The prompt shown after the numbered list.

        Returns:
            The zero-based index of the chosen candidate.

        Raises:
            NonInteractiveError: If :attr:`non_interactive` is set.
            AmbiguousDeviceError: If ``summaries`` is empty -- there is
                nothing to choose from, interactive or not.
        """
        if self.non_interactive:
            raise NonInteractiveError(
                f"Selection required but this run is non-interactive: {prompt}",
                prompt=prompt,
                hint="Narrow the selection with a more specific option instead.",
            )
        if not summaries:
            raise AmbiguousDeviceError("Nothing to choose from.", candidates=())
        for index, summary in enumerate(summaries, start=1):
            self.err.print(f"  [{index}] {summary}", markup=False, highlight=False)
        index = click.prompt(prompt, type=click.IntRange(1, len(summaries)), err=True)
        return int(index) - 1

    @property
    def chooser(self) -> Callable[[Sequence[str], str], int] | None:
        """This context's :meth:`choose` method, or ``None`` when non-interactive.

        Matches ``meshprovision.provisioning.connection.Chooser``, so it
        can be passed directly to ``connection.select_backend``.

        Returns:
            ``None`` when :attr:`non_interactive` is set (so transport
            ambiguity becomes a hard error rather than a prompt);
            otherwise :meth:`choose` bound to this instance.
        """
        if self.non_interactive:
            return None
        return self.choose

    def load_template(self) -> TemplateConfig:
        """Load and validate the configured provisioning template.

        Returns:
            The validated :class:`~meshprovision.config.template.
            TemplateConfig`.

        Raises:
            TemplateValidationError: If the template fails validation.
            NamePatternError: If a name pattern overflows its firmware
                byte limit.
            NameCapacityError: If a name pattern's namespace capacity is
                below the configured floor.
            AdminKeyCapacityError: If more than three admin nodes are
                configured.
        """
        return template_module.load_template(self.settings.template_path)

    def open_database(self, *, must_exist: bool = True, for_write: bool = False) -> DbSession:
        """Open (and load) the configured ODS database.

        Imports the ``db`` layer function-locally so that
        ``meshprovision.cli.common``'s own import graph does not
        eagerly pull in the whole database layer -- keeping ``mesh
        status``'s import surface honest.

        Read-only callers should leave ``for_write`` false: every write
        to the database is a single ``os.replace``, so a reader always
        sees a complete pre- or post-write file, and taking a lock would
        only make a read-only command block behind a long-running write.
        A caller that will modify the database and may run concurrently
        with another ``mesh`` process must pass ``for_write=True`` and
        use the returned :class:`DbSession` as a context manager so the
        lock is held across the whole load-modify-save cycle and
        released on every exit path.

        Args:
            must_exist: When ``True`` (the default), a missing database
                file is a hard error. When ``False``, a missing file is
                created as a brand-new, empty database instead.
            for_write: Whether this session intends to modify the
                database. When ``True``, acquires the cross-process
                write lock before the database is read at all, closing
                the load-then-overwrite race a lock taken only around
                ``save()`` would leave open.

        Returns:
            A :class:`DbSession` bundling the open database and its two
            typed repositories.

        Raises:
            SchemaError: If ``must_exist`` is true and the database file
                does not exist, or if the file fails to load.
            DbValidationError: If any cell fails validation on load.
            DuplicateNodeError: If ``Nodes.node_id`` has a duplicate.
            DbIntegrityError: If a derived value disagrees with its
                recomputed value on load.
            DatabaseLockedError: If ``for_write`` is true and another
                process holds the write lock past its timeout.
            AtomicWriteError: If ``for_write`` is true and the sidecar
                lock file cannot be created or acquired.
            SettingsError: If ``for_write`` is true and
                ``MESHPROVISION_LOCK_TIMEOUT`` is set to a malformed
                value.
        """
        from meshprovision.db import ods as ods_module
        from meshprovision.db.keys import KeyRepository
        from meshprovision.db.nodes import NodeRepository
        from meshprovision.db.ods import OdsDatabase

        path = self.settings.db_path
        db = OdsDatabase(path)
        if for_write:
            db.lock()
        try:
            if path.is_file():
                db.load()
            elif must_exist:
                raise SchemaError(
                    f"Node database not found: {path}",
                    hint=(
                        "Copy data/nodes_db.example.ods to data/nodes_db.ods, "
                        "or set MESHPROVISION_DB_PATH."
                    ),
                )
            else:
                ods_module.create_empty(path, backup=False)
                db.load(force=True)
        except BaseException:
            db.unlock()
            raise

        for warning in db.warnings:
            self.warn(warning.message())

        return DbSession(db=db, nodes=NodeRepository(db), keys=KeyRepository(db))

    def http_client(self, *, require_contact: bool = True) -> CachedHTTPClient:
        """Build a :class:`~meshprovision.cache.http.CachedHTTPClient` from settings.

        Args:
            require_contact: Whether a missing ``MESHPROVISION_CONTACT``
                should raise. Set to ``False`` on paths that never query
                lorastats.

        Returns:
            A new cache-backed HTTP client, configured from
            :attr:`settings` and :attr:`force_refresh`.

        Raises:
            MissingContactError: If ``MESHPROVISION_CONTACT`` is unset
                and ``require_contact`` is ``True`` -- lorastats.pl
                requires identifiable contact information in every
                request's ``User-Agent`` header.
        """
        from meshprovision.cache.http import CachedHTTPClient

        return CachedHTTPClient(
            cache_dir=self.settings.cache_dir,
            user_agent=self.settings.user_agent(require_contact=require_contact),
            ttl=self.settings.cache_ttl,
            force_refresh=self.force_refresh,
        )


pass_cli = click.make_pass_decorator(CliContext)
"""Click decorator injecting the shared :class:`CliContext` as a command's first argument."""
