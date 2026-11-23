"""The autouse fixture keeps every test away from the developer's own directories."""

from __future__ import annotations

from pathlib import Path

import platformdirs
import pytest

from meshprovision.config.settings import default_cache_dir

pytestmark = pytest.mark.unit


def test_home_and_the_default_cache_dir_are_inside_tmp_path(tmp_path: Path) -> None:
    assert Path.home().is_relative_to(tmp_path)
    assert Path(platformdirs.user_cache_dir()).is_relative_to(tmp_path)
    assert default_cache_dir().is_relative_to(tmp_path)
