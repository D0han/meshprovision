"""``mesh status`` asking lorastats.pl in the configured regions, against respx mocks."""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING

import pytest

from meshprovision.db.nodes import NodeRecord
from meshprovision.errors import ExitCode
from tests.e2e.conftest import invoke

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    import respx
    from click.testing import CliRunner

pytestmark = pytest.mark.e2e

_NODE = "deadbe01"


def _seed(seed_db: Callable[..., Path]) -> dict[str, dict[str, object]]:
    """Seed one node and return the source fixture that reports it as recently seen."""
    seed_db(nodes=[NodeRecord(node_id=_NODE, short_name="MTa1", region="EU_868")])
    return {_NODE: {"shortName": "MTa1", "seenBy": {"gw1": int(time.time()) - 60}}}


def _lorastats_route(router: respx.MockRouter) -> respx.Route:
    return next(r for r in router.routes if "lorastats.pl" in str(r.pattern))


def test_status_asks_the_region_the_setting_names(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    nodes = _seed(seed_db)
    env["MESHPROVISION_LORASTATS_REGIONS"] = "Wschód"

    with mock_sources(nodes=nodes, region="Wsch%C3%B3d") as router:
        result = invoke(runner, ["status", "--json", "--source", "lorastats"], env)
        assert _lorastats_route(router).call_count == 1

    (node,) = json.loads(result.stdout)["nodes"]
    assert node["sources"] == ["lorastats"]


def test_a_region_flag_overrides_the_setting(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    nodes = _seed(seed_db)
    env["MESHPROVISION_LORASTATS_REGIONS"] = "Wschód"

    with mock_sources(nodes=nodes, region="XX") as router:
        result = invoke(
            runner, ["status", "--json", "--source", "lorastats", "--region", "XX"], env
        )
        assert _lorastats_route(router).call_count == 1

    (node,) = json.loads(result.stdout)["nodes"]
    assert node["sources"] == ["lorastats"]


def test_a_malformed_region_setting_is_a_configuration_error(
    runner: CliRunner, env: dict[str, str], seed_db: Callable[..., Path]
) -> None:
    _seed(seed_db)
    env["MESHPROVISION_LORASTATS_REGIONS"] = "PL,a/b"

    result = invoke(runner, ["status", "--json"], env)

    assert result.exit_code == ExitCode.CONFIG
    assert "lorastats_regions" in result.stderr
