"""Tests for meshprovision.cli.progress."""

from __future__ import annotations

import io
import threading
import time

import pytest
from rich.console import Console

from meshprovision.cli.common import CliContext
from meshprovision.cli.progress import heartbeat
from meshprovision.config.settings import Settings

pytestmark = pytest.mark.unit


def _context(buf: io.StringIO) -> CliContext:
    """Build a minimal context whose stderr console writes into ``buf``."""
    return CliContext(
        settings=Settings(),
        non_interactive=True,
        force_refresh=False,
        assume_yes=False,
        out=Console(file=io.StringIO()),
        err=Console(file=buf, no_color=True, width=200),
    )


def test_heartbeat_prints_nothing_when_the_block_is_faster_than_the_interval() -> None:
    """A fast block (the common case: serial/TCP connects) looks unchanged."""
    buf = io.StringIO()
    ctx = _context(buf)

    with heartbeat(ctx, "connecting", timeout=60, interval=10.0):
        pass

    assert buf.getvalue() == ""


def test_heartbeat_ticks_at_least_once_when_the_block_outlives_the_interval() -> None:
    """A block that outlives one interval sees at least one tick."""
    buf = io.StringIO()
    ctx = _context(buf)
    ticked = threading.Event()

    # A tiny interval, driven by the ticker thread itself rather than a
    # fixed sleep in the test -- avoids interval-based flakiness.
    with heartbeat(ctx, "connecting", timeout=60, interval=0.01):
        # Wait for the ticker's own Event.wait(0.01) to fire and print,
        # bounded so a stalled ticker fails the test instead of hanging it.
        deadline = time.monotonic() + 5.0
        while "still connecting" not in buf.getvalue() and time.monotonic() < deadline:
            time.sleep(0.005)
        ticked.set()

    assert ticked.is_set()
    output = buf.getvalue()
    assert "still connecting..." in output
    assert "/ 60s" in output


def test_heartbeat_stops_ticking_and_joins_its_thread_on_exit() -> None:
    """No ticker thread survives the ``with`` block, success or failure."""
    buf = io.StringIO()
    ctx = _context(buf)
    baseline = threading.active_count()

    with heartbeat(ctx, "connecting", timeout=60, interval=0.01):
        assert threading.active_count() == baseline + 1

    assert threading.active_count() == baseline


def test_heartbeat_joins_its_thread_even_when_the_block_raises() -> None:
    buf = io.StringIO()
    ctx = _context(buf)
    baseline = threading.active_count()

    with pytest.raises(RuntimeError), heartbeat(ctx, "connecting", timeout=60, interval=0.01):
        raise RuntimeError("boom")

    assert threading.active_count() == baseline
