"""Smoke test for ``scripts/generate_example_db.py``.

Neither CI nor the rest of the test suite exercises ``scripts/`` --
verified separately (see Round 37 batch #18's commit) via
``mypy --strict scripts/generate_example_db.py`` and a one-off manual
run. This is the one permanent regression test: the script builds its
own ``KeyRecord``/``NodeRecord`` rows directly (not through the CLI), so
a schema change like the ``Keys.origin`` column, or behavior wired
through it like ``is_host_generated_key``, could silently break the
script's output without any other test noticing.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from meshprovision.crypto.known_bad_keys import load_known_bad_keys
from meshprovision.db import ods
from meshprovision.db.keys import KeyRecord, KeyRepository
from meshprovision.db.nodes import NodeRepository
from meshprovision.db.verify import verify_database

if TYPE_CHECKING:
    from types import ModuleType

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT_PATH = _ROOT / "scripts" / "generate_example_db.py"


def _load_script() -> ModuleType:
    """Import ``scripts/generate_example_db.py`` by file path.

    ``scripts/`` is not a package on ``sys.path`` (deliberately -- it is
    not shipped), so the module is loaded directly from its file.

    Returns:
        The imported module.
    """
    spec = importlib.util.spec_from_file_location("generate_example_db", _SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_generate_example_db_output_loads_with_every_key_origin_recorded(
    tmp_path: Path,
) -> None:
    """The generated file must load cleanly, with a recorded origin on every key row.

    Loading exercises the full ``Keys.origin`` round trip
    (``to_row``/``from_row``, the header write, schema validation) for
    every row the script builds -- the same machinery a hand-edited or
    pre-upgrade database goes through, just driven by the script instead
    of the CLI.
    """
    module = _load_script()

    output = module.generate(tmp_path / "example.ods")
    loaded = ods.load_database(output)

    assert loaded.nodes
    assert loaded.keys
    for row in loaded.keys:
        assert KeyRecord.from_row(row).origin is not None


@pytest.mark.parametrize("shipped", [False, True], ids=["generated", "shipped"])
def test_the_example_database_passes_db_verify(tmp_path: Path, shipped: bool) -> None:
    """``mesh db verify`` on the example finds nothing worse than a warning."""
    module = _load_script()
    path = _ROOT / module.EXAMPLE_DB_PATH if shipped else module.generate(tmp_path / "ex.ods")
    db = ods.OdsDatabase(path)
    db.load(force=True)

    report = verify_database(
        path=path,
        warnings=db.warnings,
        nodes=NodeRepository(db),
        keys=KeyRepository(db),
        template=None,
        known_bad=load_known_bad_keys(),
    )

    assert report.exit_code(strict=False) == 0, report.problems
