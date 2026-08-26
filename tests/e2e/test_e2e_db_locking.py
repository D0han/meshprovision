"""E2e coverage for the sidecar write lock's operator-facing behavior.

Confirms the lock blocks only writers: a concurrent ``mesh admin import``
fails fast with exit code 4 while ``mesh db verify`` and ``mesh status``
succeed unaffected, with the lock held for the whole span -- the
assertion that pins design decision 3 (readers never block on the write
lock).
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.crypto.keys import generate_keypair
from meshprovision.db import locking
from meshprovision.errors import ExitCode
from tests.e2e.conftest import invoke

if TYPE_CHECKING:
    from collections.abc import Callable

    import respx
    from click.testing import CliRunner

pytestmark = pytest.mark.e2e


def test_a_held_write_lock_refuses_a_second_writer_but_not_readers(
    runner: CliRunner,
    env: dict[str, str],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    db_path = Path(env["MESHPROVISION_DB_PATH"])
    env["MESHPROVISION_LOCK_TIMEOUT"] = "0.2"
    b64 = base64.b64encode(generate_keypair().public).decode()

    with locking.exclusive_lock(db_path):
        result = invoke(runner, ["admin", "import", f"ADMIN1={b64}"], env)
        assert result.exit_code == int(ExitCode.DB)
        assert "Another mesh command" in result.stderr

        verify_result = invoke(runner, ["db", "verify"], env)
        assert verify_result.exit_code == 0

        with mock_sources():
            status_result = invoke(runner, ["status", "--json"], env)
        assert status_result.exit_code == 0

    # The lock is gone once released: the same writer now succeeds.
    result = invoke(runner, ["admin", "import", f"ADMIN1={b64}"], env)
    assert result.exit_code == 0
