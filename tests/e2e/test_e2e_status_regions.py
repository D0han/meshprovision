"""``mesh status`` asking lorastats.pl in the configured regions, against respx mocks."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
import pytest

from meshprovision.datasources.lorastats import (
    LORASTATS_BASE_URL,
    LORASTATS_NODES_PATH,
    LORASTATS_STATUS_PATH,
)
from meshprovision.datasources.lorastats_regions import REGION_LIST_FILENAME
from meshprovision.datasources.region_memo import REGION_MEMO_FILENAME
from meshprovision.db.nodes import NodeRecord
from meshprovision.errors import ExitCode
from tests.conftest import LORASTATS_NODES_PAGE, LORASTATS_NODES_PAGE_REGIONS
from tests.e2e.conftest import invoke

if TYPE_CHECKING:
    from collections.abc import Callable

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


_PAGE_URL = "https://lorastats.pl/Nodes"


def _listed_router(
    mock_sources: Callable[..., respx.MockRouter],
    nodes: dict[str, dict[str, object]],
    *,
    page: httpx.Response | None = None,
    status: int = 200,
) -> tuple[respx.MockRouter, respx.Route, respx.Route]:
    """Serve the fixture navigation page, the nodes in Zachód, every other region empty.

    The status endpoint answers ``status`` for every node.

    Returns:
        The router, the page route and the Zachód route.
    """
    router = mock_sources(nodes=nodes, region="Zach%C3%B3d")
    zachod = _lorastats_route(router)
    router.get(url__regex=r"^https://lorastats\.pl/API/[^/]+/Nodes/JSON").mock(
        return_value=httpx.Response(200, json=[])
    )
    router.get(url__regex=r"^https://lorastats\.pl/Node/[0-9a-f]{8}/Status$").mock(
        return_value=httpx.Response(status, text="Wszystko OK.")
    )
    page_route = router.get(_PAGE_URL).mock(
        return_value=page or httpx.Response(200, html=LORASTATS_NODES_PAGE)
    )
    return router, page_route, zachod


def _region_list_file(env: dict[str, str]) -> Path:
    return Path(env["MESHPROVISION_CACHE_DIR"]) / REGION_LIST_FILENAME


def test_without_configured_regions_the_listed_regions_are_asked_in_order(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    nodes = _seed(seed_db)
    del env["MESHPROVISION_LORASTATS_REGIONS"]
    router, page, zachod = _listed_router(mock_sources, nodes)

    with router:
        result = invoke(runner, ["status", "--json", "--source", "lorastats"], env)
        assert (page.call_count, zachod.call_count) == (1, 1)

    document = json.loads(result.stdout)
    (node,) = document["nodes"]
    assert node["sources"] == ["lorastats"]
    # The page, the status probe, then Warszawa, ShortFast and Zachód, where the node is.
    assert document["cache"]["network_requests"] == 1 + 1 + 3
    cached = json.loads(_region_list_file(env).read_text(encoding="utf-8"))
    assert cached["regions"] == list(LORASTATS_NODES_PAGE_REGIONS)


def test_the_page_is_requested_again_only_with_refresh_regions(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    nodes = _seed(seed_db)
    del env["MESHPROVISION_LORASTATS_REGIONS"]
    router, page, _ = _listed_router(mock_sources, nodes)
    args = ["status", "--json", "--source", "lorastats"]

    with router:
        invoke(runner, args, env)
        invoke(runner, args, env)
        invoke(runner, ["--no-cache", *args], env)
        invoke(runner, ["--force-refresh", *args], env)
        assert page.call_count == 1
        result = invoke(runner, [*args, "--refresh-regions"], env)
        assert page.call_count == 2

    assert result.exit_code == 0


def test_a_watch_requests_the_page_once(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nodes = _seed(seed_db)
    del env["MESHPROVISION_LORASTATS_REGIONS"]
    polls = []

    def fake_sleep(_seconds: float) -> None:
        polls.append(1)
        if len(polls) >= 3:
            raise KeyboardInterrupt

    monkeypatch.setattr(time, "sleep", fake_sleep)
    router, page, _ = _listed_router(mock_sources, nodes)

    with router:
        invoke(
            runner,
            ["--no-cache", "status", "--json", "--watch", "--interval", "1", "--refresh-regions"],
            env,
        )
        assert page.call_count == 1


def test_configured_regions_never_request_the_page(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    nodes = _seed(seed_db)
    env["MESHPROVISION_LORASTATS_REGIONS"] = "Zachód"
    router, page, zachod = _listed_router(mock_sources, nodes)

    with router:
        invoke(runner, ["status", "--json"], env)
        invoke(runner, ["status", "--json", "--region", "Gdańsk"], env)
        assert (page.call_count, zachod.call_count) == (0, 1)

    assert not _region_list_file(env).exists()


def test_no_region_list_makes_lorastats_a_failed_source_naming_the_setting(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    nodes = _seed(seed_db)
    del env["MESHPROVISION_LORASTATS_REGIONS"]
    router, page, zachod = _listed_router(mock_sources, nodes, page=httpx.Response(404))

    with router:
        result = invoke(runner, ["status", "--json"], env)
        assert (page.call_count, zachod.call_count) == (1, 0)

    document = json.loads(result.stdout)
    (failure,) = document["failures"]
    assert failure["source"] == "lorastats"
    assert failure["message"].startswith("No lorastats region list")
    assert "MESHPROVISION_LORASTATS_REGIONS" in failure["hint"]
    (node,) = document["nodes"]
    assert node["sources"] == ["loranet"]
    assert result.exit_code == ExitCode.STATUS_DEGRADED


def test_a_failed_refresh_uses_the_stale_list_with_a_warning(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    nodes = _seed(seed_db)
    del env["MESHPROVISION_LORASTATS_REGIONS"]
    stale = {"version": 1, "regions": ["Zachód"], "fetched_at": time.time() - 30 * 86400}
    _region_list_file(env).parent.mkdir(parents=True, exist_ok=True)
    _region_list_file(env).write_text(json.dumps(stale), encoding="utf-8")
    router, page, zachod = _listed_router(mock_sources, nodes, page=httpx.Response(404))

    with router:
        result = invoke(runner, ["status", "--json", "--source", "lorastats"], env)
        assert (page.call_count, zachod.call_count) == (1, 1)

    assert "using the cached one" in result.stderr
    (node,) = json.loads(result.stdout)["nodes"]
    assert node["sources"] == ["lorastats"]
    assert result.exit_code == 0


def _two_regions_router(
    mock_sources: Callable[..., respx.MockRouter],
    nodes: dict[str, dict[str, object]],
    *,
    status: int = 200,
) -> tuple[respx.MockRouter, dict[str, respx.Route]]:
    """Serve the nodes in ``Gdańsk`` only, an empty ``Zachód`` and the status endpoint."""
    router = mock_sources(nodes=nodes, region="Gda%C5%84sk")
    routes = {
        "Gdańsk": _lorastats_route(router),
        "Zachód": router.get(
            url__startswith=LORASTATS_BASE_URL + LORASTATS_NODES_PATH.format(region="Zach%C3%B3d")
        ).mock(return_value=httpx.Response(200, json=[])),
        "status": router.get(LORASTATS_BASE_URL + LORASTATS_STATUS_PATH.format(node=_NODE)).mock(
            return_value=httpx.Response(status, text="Wszystko OK.")
        ),
    }
    return router, routes


def _calls(routes: dict[str, respx.Route]) -> dict[str, int]:
    return {name: route.call_count for name, route in routes.items()}


def _requests(result_stdout: str) -> int:
    count = json.loads(result_stdout)["cache"]["network_requests"]
    assert isinstance(count, int)
    return count


def test_a_node_in_the_second_configured_region_is_found_and_remembered(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    nodes = _seed(seed_db)
    env["MESHPROVISION_LORASTATS_REGIONS"] = "Zachód,Gdańsk"
    router, routes = _two_regions_router(mock_sources, nodes)

    with router:
        first = invoke(runner, ["status", "--json", "--source", "lorastats"], env)
        assert _calls(routes) == {"Gdańsk": 1, "Zachód": 1, "status": 1}
        second = invoke(runner, ["--no-cache", "status", "--json", "--source", "lorastats"], env)
        assert _calls(routes) == {"Gdańsk": 2, "Zachód": 1, "status": 1}

    assert (_requests(first.stdout), _requests(second.stdout)) == (3, 1)
    for result in (first, second):
        assert result.exit_code == 0
        (node,) = json.loads(result.stdout)["nodes"]
        assert node["sources"] == ["lorastats"]
    memo = json.loads((Path(env["MESHPROVISION_CACHE_DIR"]) / REGION_MEMO_FILENAME).read_text())
    assert memo["nodes"][_NODE]["region"] == "Gdańsk"


def test_a_node_unknown_to_lorastats_costs_exactly_one_request(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    nodes = _seed(seed_db)
    env["MESHPROVISION_LORASTATS_REGIONS"] = "Zachód,Gdańsk"
    router, routes = _two_regions_router(mock_sources, nodes, status=404)

    with router:
        first = invoke(runner, ["status", "--json", "--source", "lorastats"], env)
        second = invoke(runner, ["status", "--json", "--source", "lorastats"], env)
        assert _calls(routes) == {"Gdańsk": 0, "Zachód": 0, "status": 1}

    assert (_requests(first.stdout), _requests(second.stdout)) == (1, 0)
    (node,) = json.loads(first.stdout)["nodes"]
    assert node["sources"] == []
    assert json.loads(first.stdout)["failures"] == []


def test_a_single_region_flag_is_asked_directly_without_probe_or_memo(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    nodes = _seed(seed_db)
    env["MESHPROVISION_LORASTATS_REGIONS"] = "Zachód,Gdańsk"
    router, routes = _two_regions_router(mock_sources, nodes)

    with router:
        result = invoke(
            runner, ["status", "--json", "--source", "lorastats", "--region", "Gdańsk"], env
        )
        assert _calls(routes) == {"Gdańsk": 1, "Zachód": 0, "status": 0}

    assert _requests(result.stdout) == 1
    assert not (Path(env["MESHPROVISION_CACHE_DIR"]) / REGION_MEMO_FILENAME).exists()


def test_a_status_probe_failure_is_reported_as_a_lorastats_failure(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    nodes = _seed(seed_db)
    env["MESHPROVISION_LORASTATS_REGIONS"] = "Zachód,Gdańsk"
    router, routes = _two_regions_router(mock_sources, nodes, status=403)

    with router:
        result = invoke(runner, ["status", "--json"], env)
        assert _calls(routes) == {"Gdańsk": 0, "Zachód": 0, "status": 1}

    document = json.loads(result.stdout)
    (failure,) = document["failures"]
    assert failure["source"] == "lorastats"
    assert "HTTP 403" in failure["message"]
    (node,) = document["nodes"]
    assert node["sources"] == ["loranet"]
    assert result.exit_code == 7


def test_a_cold_start_on_lorastats_pls_list_costs_the_page_and_one_status_per_unknown_node(
    runner: CliRunner,
    env: dict[str, str],
    seed_db: Callable[..., Path],
    mock_sources: Callable[..., respx.MockRouter],
) -> None:
    nodes = _seed(seed_db)
    del env["MESHPROVISION_LORASTATS_REGIONS"]
    router, page, zachod = _listed_router(mock_sources, nodes, status=404)
    unknown = next(r for r in router.routes if "Status" in str(r.pattern))

    with router:
        first = invoke(runner, ["status", "--json", "--source", "lorastats"], env)
        second = invoke(runner, ["status", "--json", "--source", "lorastats"], env)
        assert (page.call_count, unknown.call_count, zachod.call_count) == (1, 1, 0)

    assert (_requests(first.stdout), _requests(second.stdout)) == (2, 0)
