"""A cache entry or known-good sidecar that decodes to an overflow or a recursion is a miss."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from meshprovision.cache.http import cache_key
from meshprovision.db import known_good
from tests.unit.test_cache_http import URL, _make_client

pytestmark = pytest.mark.unit

_DEEP: str = "[" * 200_000
"""Nests far deeper than the JSON decoder recurses: it raises ``RecursionError``."""


@pytest.mark.parametrize(
    ("field", "literal"),
    [
        pytest.param("status_code", "Infinity", id="infinite-status"),
        pytest.param("fetched_at", "1" + "0" * 400, id="fetched-at-too-large-for-a-float"),
        pytest.param(None, None, id="nested-too-deeply"),
    ],
)
@respx.mock
def test_an_entry_that_cannot_be_decoded_is_a_miss_and_unlinked(
    tmp_path: Path, field: str | None, literal: str | None
) -> None:
    route = respx.get(URL).mock(return_value=httpx.Response(200, json={"a": 1}))
    client = _make_client(tmp_path, now=[0.0])
    client.get(URL)
    key = cache_key("GET", URL)
    path = client.path_for_key(key)
    entry = json.loads(path.read_text())
    if field is None:
        path.write_text(_DEEP)
    else:
        path.write_text(json.dumps({**entry, field: "LITERAL"}).replace('"LITERAL"', literal))

    assert client._read_entry(path, cache_key_value=key) is None
    assert not path.exists()
    assert client.get(URL).from_cache is False
    assert route.call_count == 2


def test_a_sidecar_nested_too_deeply_is_no_provenance(tmp_path: Path) -> None:
    target = tmp_path / "nodes_db.ods"
    target.write_bytes(b"v1")
    backup_dir = tmp_path / "backups"
    known_good.refresh_known_good(
        target, content=target.read_bytes(), source_stat=target.stat(), backup_dir=backup_dir
    )
    (backup_dir / "nodes_db.known-good.json").write_text(_DEEP)

    status = known_good.known_good_status(target, backup_dir=backup_dir)

    assert status is not None
    assert status.provenance is known_good.KnownGoodProvenance.UNRECORDED
