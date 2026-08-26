"""Shared root conftest for both the unit and e2e test layers.

Two things happen here that MUST happen before anything else:

1. ``time.sleep`` is stubbed at IMPORT TIME, before any ``meshprovision``
   import. Three places in the source capture ``time.sleep`` as a
   *default argument value* at their own import time:
   ``apply.apply_plan(..., sleep=time.sleep)``,
   ``apply.ReconnectingSession.sleep`` (a slots-dataclass field default),
   and ``cache.http.CachedHTTPClient.__init__(..., sleep=time.sleep)``.
   A default argument is evaluated once, when the enclosing ``def``/
   dataclass runs -- so monkeypatching ``time.sleep`` from a fixture, at
   test time, is too late for those three call sites; a real
   ``apply_plan`` retry loop would then really sleep for several seconds
   per test. pytest imports ``tests/conftest.py`` before any test module
   or ``tests/*/conftest.py``, so stubbing here, before the first
   ``meshprovision`` import anywhere in the run, is what actually
   prevents that.
2. An autouse fixture also monkeypatches ``time.sleep`` for every test,
   covering the few call sites (``cli/status.py``'s ``--watch`` loop)
   that resolve ``time.sleep`` at *call* time rather than import time.

The autouse ``_isolated_cwd_and_env`` fixture additionally chdirs every
test into a fresh ``tmp_path`` and strips every ``MESHPROVISION_*``
environment variable, which is what keeps
``meshprovision.db.ods.OdsDatabase.save()``'s ``backup=True`` default
(which resolves ``data/backups/`` relative to the CWD) and
``meshprovision.config.settings.load_settings()``'s upward ``.env``
search from ever touching this repository's real files, and what keeps a
developer's shell environment from leaking into a test run.
"""

from __future__ import annotations

import time

REAL_SLEEP = time.sleep
time.sleep = lambda *_a, **_k: None

import os  # noqa: E402
from collections.abc import Callable  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any, Final  # noqa: E402

import pytest  # noqa: E402
import yaml  # noqa: E402

from meshprovision.crypto.keys import KeyPair, generate_keypair  # noqa: E402
from meshprovision.db import ods  # noqa: E402

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
"""Absolute path to the repository root (the parent of ``tests/``)."""

EXAMPLE_TEMPLATE: Final[Path] = REPO_ROOT / "config" / "template.example.yaml"
"""Path to the shipped, read-only example provisioning template."""

KNOWN_BAD_KEYS_FILE: Final[Path] = REPO_ROOT / "data" / "known_bad_keys.txt"
"""Path to the shipped, read-only committed weak-key blocklist."""

TEST_CONTACT: Final[str] = "meshprovision-tests@example.invalid"
"""A syntactically valid, obviously-fake ``MESHPROVISION_CONTACT`` value."""


@pytest.fixture(autouse=True)
def _isolated_cwd_and_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate every test's working directory, environment, and ``time.sleep``.

    Args:
        tmp_path: Pytest's per-test temporary directory.
        monkeypatch: Pytest's monkeypatch fixture.
    """
    monkeypatch.chdir(tmp_path)
    for name in list(os.environ):
        if name.startswith("MESHPROVISION_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(time, "sleep", lambda *_a, **_k: None)


@pytest.fixture
def repo_root() -> Path:
    """Return the repository root.

    Returns:
        :data:`REPO_ROOT`.
    """
    return REPO_ROOT


@pytest.fixture
def cli_env(tmp_path: Path) -> dict[str, str]:
    """Build a fresh CLI environment mapping for ``CliRunner.invoke(..., env=...)``.

    Args:
        tmp_path: Pytest's per-test temporary directory.

    Returns:
        A new, mutable ``dict`` a caller may freely add to.
    """
    return {
        "MESHPROVISION_CONTACT": TEST_CONTACT,
        "MESHPROVISION_CACHE_DIR": str(tmp_path / "cache"),
        "MESHPROVISION_LOG_LEVEL": "WARNING",
        "COLUMNS": "200",
        "NO_COLOR": "1",
    }


def _merge_one_level(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    """Merge ``overrides`` into ``base``, one level deep for nested dicts.

    Args:
        base: The base mapping (mutated and returned).
        overrides: Keys/values to apply on top of ``base``.

    Returns:
        ``base``, with ``overrides`` applied.
    """
    for key, value in overrides.items():
        existing = base.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            existing.update(value)
        else:
            base[key] = value
    return base


@pytest.fixture
def write_template(tmp_path: Path) -> Callable[..., Path]:
    """Return a factory that writes a customized copy of the example template.

    Args:
        tmp_path: Pytest's per-test temporary directory.

    Returns:
        A callable ``write_template(*, path=None, **overrides) -> Path``.
    """

    def _write(*, path: Path | None = None, **overrides: Any) -> Path:
        """Write a template YAML file, merged one level deep over the example.

        Args:
            path: Where to write the file. Defaults to
                ``tmp_path / "template.yaml"``.
            **overrides: Top-level fields to replace or merge.

        Returns:
            The path the template was written to.
        """
        data = yaml.safe_load(EXAMPLE_TEMPLATE.read_text(encoding="utf-8"))
        data = _merge_one_level(dict(data), overrides)
        target = path if path is not None else tmp_path / "template.yaml"
        target.write_text(yaml.safe_dump(data), encoding="utf-8")
        return target

    return _write


@pytest.fixture
def empty_ods(tmp_path: Path) -> Path:
    """Write a brand-new, empty ODS database and return its path.

    Args:
        tmp_path: Pytest's per-test temporary directory.

    Returns:
        Path to the created ``nodes_db.ods`` file.
    """
    path = tmp_path / "nodes_db.ods"
    ods.create_empty(path, backup=False)
    return path


@pytest.fixture
def keypair() -> KeyPair:
    """Generate one fresh X25519 keypair.

    Returns:
        A new :class:`~meshprovision.crypto.keys.KeyPair`.
    """
    return generate_keypair()


@pytest.fixture
def keypair_factory() -> Callable[[], KeyPair]:
    """Return a factory that generates a fresh X25519 keypair on each call.

    Returns:
        A callable taking no arguments and returning a new
        :class:`~meshprovision.crypto.keys.KeyPair` each time.
    """
    return generate_keypair
