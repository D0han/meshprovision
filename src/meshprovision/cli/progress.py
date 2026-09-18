"""A periodic "still working" heartbeat for long, silent blocking calls.

Used to wrap blocking operations that have no progress callback of their
own -- most notably ``BLEInterface(...)`` (:func:`meshprovision.
provisioning.connection.BLEBackend.connect`), whose worst case runs to
several minutes with nothing to show for it. See
:func:`~meshprovision.cli.provision.connected_with_progress`.

Always on, not gated behind ``-v``: an operator watching a hung connect
needs to see it is still alive regardless of the chosen log level. The
verbosity flag (``-v``/``-vv``/``-vvv``, see
:mod:`meshprovision.cli.common`) controls *log detail*; this module
controls a separate, always-visible progress signal.
"""

from __future__ import annotations

import contextlib
import threading
import time
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Iterator

    from meshprovision.cli.common import CliContext

__all__ = ["DEFAULT_HEARTBEAT_INTERVAL", "heartbeat"]

DEFAULT_HEARTBEAT_INTERVAL: Final[float] = 10.0
"""Seconds between heartbeat ticks, absent an explicit ``interval``."""

_JOIN_TIMEOUT: Final[float] = 1.0
"""How long to wait for the ticker thread to notice ``done`` before moving
on. The thread is a daemon, so a slow join here never blocks process
exit -- this bound only keeps a slow join from being mistaken for a
hang in the caller's own timing."""


@contextlib.contextmanager
def heartbeat(
    ctx: CliContext,
    label: str,
    *,
    timeout: float,
    interval: float = DEFAULT_HEARTBEAT_INTERVAL,
) -> Iterator[None]:
    """Print a periodic "still <label>..." line while the wrapped block runs.

    Prints nothing if the block finishes before the first ``interval``
    elapses, so a fast serial/TCP connect looks exactly as it did before
    this existed. Ticks stop the instant the block exits (success,
    exception, or ``KeyboardInterrupt``) -- the background thread is a
    daemon woken by an :class:`threading.Event`, never a bare ``sleep``,
    so it notices immediately rather than on its next interval.

    Args:
        ctx: The CLI context to print through (``ctx.info``, stderr).
        label: What is being waited for, e.g. ``"connecting"``. Rendered
            as ``f"  still {label}... {elapsed:.0f}s / {timeout:.0f}s"``.
        timeout: The wrapped operation's own timeout, in seconds, shown
            alongside the elapsed time so the operator can see how close
            it is to giving up. Purely informational -- this function
            does not itself enforce any timeout.
        interval: Seconds between ticks.

    Yields:
        Nothing; used only for its ``with`` block.
    """
    done = threading.Event()
    started = time.monotonic()

    def _tick() -> None:
        while not done.wait(interval):
            elapsed = time.monotonic() - started
            ctx.info(f"  still {label}... {elapsed:.0f}s / {timeout:.0f}s")

    thread = threading.Thread(target=_tick, daemon=True, name="mesh-heartbeat")
    thread.start()
    try:
        yield
    finally:
        done.set()
        thread.join(timeout=_JOIN_TIMEOUT)
