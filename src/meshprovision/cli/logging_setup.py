"""The process-wide structlog + stdlib logging configuration.

:func:`configure_logging` is the single place structlog is configured for
the whole process. It installs :func:`meshprovision.crypto.redact.
redact_processor` as the **last** processor before the renderer, exactly
per that module's own contract -- every other processor (including one
that might flatten a nested structure into a string) runs before the
redactor sees the event, so nothing skips the scrub.

This module imports nothing from :mod:`meshprovision.cli.common`,
:mod:`meshprovision.cli.main`, or any command module -- only downward,
from the earlier layers.
"""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING, Final

import structlog

from meshprovision.crypto import redact
from meshprovision.errors import SchemaError

if TYPE_CHECKING:
    from typing import TextIO

__all__ = [
    "LOG_LEVELS",
    "configure_logging",
    "resolve_log_level",
]

LOG_LEVELS: Final[tuple[str, ...]] = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
"""The logging verbosities accepted by ``--log-level``."""

_LIBRARY_STAGES: Final[tuple[tuple[str, ...], ...]] = (
    ("meshtastic", "httpx"),
    ("bleak", "httpcore", "urllib3"),
)
"""Third-party loggers held back until ``-v`` reaches their stage.

Stage ``i`` (0-indexed) is released once ``--verbose``'s count is at least
``i + 2`` -- i.e. the *second* ``-v`` (``-vv``) releases stage 0
(``meshtastic``/``httpx``), and the *third* (``-vvv``) releases stage 1
(``bleak``/``httpcore``/``urllib3``). Before release, stage 0 tracks the
root level with a WARNING floor (``max(numeric_level, WARNING)`` -- the
same pre-``-v`` behavior this project has always had: an explicit
``--log-level error`` quiets these two further, but nothing quiets them
below WARNING); stage 1 is pinned to exactly WARNING regardless of the
root level, matching its pre-``-v`` behavior. Release itself is the new
capability this stage table exists for -- previously nothing could ever
make these *louder* than WARNING (the old ``max(numeric_level,
WARNING)`` floor could only ever raise the effective minimum, never
lower it), so ``--log-level debug`` alone could never surface library
detail no matter how loud requested; ``-vv``/``-vvv`` now can.
"""


class _LibrarySecretFilter(logging.Filter):
    """Withholds ``meshtastic`` library records that may carry secret material.

    Installed on the **handler** in :func:`configure_logging`, deliberately
    not on the ``meshtastic`` logger itself: a filter attached to a
    logger only runs for records emitted directly on that logger, never
    for records emitted on its children (``meshtastic.mesh_interface``,
    ``meshtastic.stream_interface``, ...) -- and those child loggers are
    exactly the ones the installed ``meshtastic`` library uses to print
    raw protobuf text (private keys rendered as octal escapes) and raw
    serialized frames (a Python ``bytes`` repr) at ``-vv``/``-vvv``. A
    handler-level filter sees every record the handler emits, regardless
    of which logger in the hierarchy produced it.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Rewrite a risky ``meshtastic`` record's message in place; never drop it.

        Args:
            record: The candidate log record.

        Returns:
            Always ``True``. The operator still sees that library
            traffic happened, at the withheld record's original level
            and logger name -- only the risky content is replaced.
        """
        if record.name == "meshtastic" or record.name.startswith("meshtastic."):
            message = record.getMessage()
            if redact.library_record_may_leak(message):
                record.msg = (
                    f"[{record.name}: {len(message)}-char record withheld; "
                    "may contain key material]"
                )
                record.args = ()
        return True


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


def _stage_third_party_loggers(numeric_level: int, verbosity: int) -> None:
    """Floor noisy third-party loggers at WARNING until ``-v`` releases them.

    Each :data:`_LIBRARY_STAGES` entry is held back until ``verbosity``
    reaches that stage's threshold, at which point it is set to
    ``NOTSET`` so it inherits the root logger's own level instead --
    ``--log-level warning -vvv`` therefore still means WARNING, while
    plain ``-vvv`` (root at DEBUG, via :func:`resolve_log_level`) lets it
    through at DEBUG. Before release, stage 0 (``meshtastic``/``httpx``)
    is floored at ``max(numeric_level, WARNING)`` -- quietable below
    WARNING by an explicit ``--log-level``, never raisable above it
    without ``-vv`` -- and stage 1 (``bleak``/``httpcore``/``urllib3``)
    is pinned to exactly WARNING.

    Args:
        numeric_level: The resolved numeric level for the root logger.
        verbosity: The ``-v``/``--verbose`` count.
    """
    for index, names in enumerate(_LIBRARY_STAGES):
        released = verbosity >= index + 2
        for name in names:
            if released:
                level = logging.NOTSET
            elif index == 0:
                level = max(numeric_level, logging.WARNING)
            else:
                level = logging.WARNING
            logging.getLogger(name).setLevel(level)


def resolve_log_level(log_level: str | None, verbose: int) -> str | None:
    """Resolve the effective ``--log-level`` value from the flag and ``-v`` count.

    An explicit ``--log-level`` always wins, preserving the existing
    flag > environment > ``.env`` precedence (:func:`~meshprovision.cli.
    common.build_settings` layers whatever this returns the same way it
    already layered ``log_level``). Otherwise, ``-v`` raises this
    project's own loggers to ``INFO`` and ``-vv``/``-vvv`` to ``DEBUG``
    (the extra count beyond 2 has no further effect here -- it instead
    releases third-party loggers, via :func:`_stage_third_party_loggers`);
    with no flag and no ``-v`` at all, ``None`` is returned so the
    environment/``.env``/default (``WARNING``) layers decide.

    Args:
        log_level: The raw ``--log-level`` value, or ``None``.
        verbose: The ``-v``/``--verbose`` count.

    Returns:
        ``log_level`` unchanged when given; otherwise ``"INFO"`` if
        ``verbose == 1``, ``"DEBUG"`` if ``verbose >= 2``; otherwise
        ``None``.
    """
    if log_level is not None:
        return log_level
    if verbose >= 2:
        return "DEBUG"
    if verbose == 1:
        return "INFO"
    return None


def configure_logging(
    level: str,
    *,
    stream: TextIO | None = None,
    colors: bool | None = None,
    verbosity: int = 0,
) -> None:
    """Configure the process-wide structlog + stdlib logging pipeline.

    The single place structlog is configured. Every earlier-layer module
    logs through stdlib ``logging.getLogger(__name__)``, so stdlib
    records are routed through the same ``structlog.stdlib.
    ProcessorFormatter`` chain as structlog-native events -- including
    :func:`meshprovision.crypto.redact.redact_processor`, which runs
    right after ``structlog.processors.format_exc_info`` in the
    formatter's ``processors`` list so it is the last thing to touch the
    event dict before ``remove_processors_meta``/render.
    ``format_exc_info`` turns an ``exc_info`` traceback into the event's
    ``"exception"`` string first, so the redactor scrubs and
    control-escapes the traceback text too (exception messages and
    chained causes can carry device- or file-sourced text); left as a
    tuple, the renderer would format it after the scrub, raw.

    ``format_exc_info`` uses the standard library's traceback formatting,
    which never prints locals, and
    ``exception_formatter=structlog.dev.plain_traceback`` is still passed
    to the renderer deliberately: ``ConsoleRenderer``'s own default is a
    ``RichTracebackFormatter(show_locals=True)``, which would print local
    variables -- i.e. potentially raw key material -- into the log on any
    traceback.

    :class:`_LibrarySecretFilter` is attached to the handler here too, so
    that at ``-vv``/``-vvv`` (see ``verbosity`` below) the released
    ``meshtastic`` library's own DEBUG logging -- which prints raw
    protobuf text and frame bytes, a shape ``redact_processor``'s
    base64/hex scrubbing does not catch -- never reaches the renderer
    unredacted.

    Idempotent: calling this twice never duplicates handlers, since the
    root logger's existing handlers are removed first.

    Args:
        level: The logging verbosity. Must be one of :data:`LOG_LEVELS`.
        stream: The stream to attach the handler to. Defaults to
            ``sys.stderr``.
        colors: Whether to emit ANSI colors. ``None`` auto-detects from
            whether the target stream is a TTY.
        verbosity: The ``-v``/``--verbose`` count, staged through
            :func:`_stage_third_party_loggers`: ``0``/``1`` leave every
            name in :data:`_LIBRARY_STAGES` at WARNING; ``2`` releases
            ``meshtastic``/``httpx``; ``3`` also releases
            ``bleak``/``httpcore``/``urllib3``. This only governs the
            third-party loggers -- ``level`` itself (typically resolved
            by :func:`resolve_log_level`, one rung ahead: ``-v`` ->
            INFO, ``-vv``/``-vvv`` -> DEBUG) is what raises this
            project's own loggers above the ``WARNING`` default.

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
            structlog.processors.format_exc_info,
            redact.redact_processor,
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(formatter)
    # On the handler, not the "meshtastic" logger: see _LibrarySecretFilter.
    handler.addFilter(_LibrarySecretFilter())

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

    _stage_third_party_loggers(numeric_level, verbosity)
