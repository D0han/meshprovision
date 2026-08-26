"""Tests for meshprovision.cache.http."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import httpx
import pytest
import respx

from meshprovision.cache.http import (
    DEFAULT_MAX_RETRIES,
    CachedHTTPClient,
    cache_key,
    resolve_ttl,
)
from meshprovision.errors import (
    HttpError,
    InvalidResponseError,
    MissingContactError,
    RateLimitError,
    SettingsError,
)

pytestmark = pytest.mark.unit

URL = "https://example.invalid/data.json"


def _make_client(
    tmp_path: Path,
    *,
    now: list[float],
    ttl: float = 300.0,
    force_refresh: bool = False,
    max_retries: int = DEFAULT_MAX_RETRIES,
) -> CachedHTTPClient:
    return CachedHTTPClient(
        cache_dir=tmp_path / "cache",
        user_agent="meshprovision/test (+t@example.invalid)",
        ttl=ttl,
        clock=lambda: now[0],
        sleep=lambda _s: None,
        force_refresh=force_refresh,
        max_retries=max_retries,
    )


# ---------------------------------------------------------------------------
# TTL semantics.
# ---------------------------------------------------------------------------


@respx.mock
def test_zero_network_calls_inside_ttl(tmp_path: Path) -> None:
    route = respx.get(URL).mock(return_value=httpx.Response(200, json={"a": 1}))
    now = [1000.0]
    client = _make_client(tmp_path, now=now)

    first = client.get(URL)
    assert first.from_cache is False
    assert route.call_count == 1
    assert client.stats.network_requests == 1
    assert client.stats.misses == 1
    assert client.stats.writes == 1

    now[0] += 299
    second = client.get(URL)
    assert second.from_cache is True
    assert route.call_count == 1
    assert client.stats.network_requests == 1
    assert client.stats.hits == 1


@respx.mock
def test_ttl_expiry_triggers_exactly_one_refetch(tmp_path: Path) -> None:
    route = respx.get(URL).mock(return_value=httpx.Response(200, json={"a": 1}))
    now = [0.0]
    client = _make_client(tmp_path, now=now, ttl=300.0)

    client.get(URL)
    assert route.call_count == 1

    now[0] += 301
    client.get(URL)
    assert route.call_count == 2
    assert client.stats.network_requests == 2

    client.get(URL)
    assert route.call_count == 2


@respx.mock
def test_force_refresh_always_bypasses_read(tmp_path: Path) -> None:
    route = respx.get(URL).mock(return_value=httpx.Response(200, json={"a": 1}))
    now = [0.0]
    client = _make_client(tmp_path, now=now)

    client.get(URL)  # seed the cache
    assert client.stats.hits == 0

    for _ in range(3):
        client.get(URL, force_refresh=True)
    assert route.call_count == 4
    assert client.stats.hits == 0
    assert client.stats.writes == 4


@respx.mock
def test_client_force_refresh_flag_and_call_override(tmp_path: Path) -> None:
    route = respx.get(URL).mock(return_value=httpx.Response(200, json={"a": 1}))
    now = [0.0]
    client = _make_client(tmp_path, now=now, force_refresh=True)

    client.get(URL)
    client.get(URL)
    assert route.call_count == 2

    client.get(URL, force_refresh=False)
    assert route.call_count == 2
    assert client.stats.hits == 1


# ---------------------------------------------------------------------------
# cache_key.
# ---------------------------------------------------------------------------


def test_cache_key_never_collides_on_params() -> None:
    a = cache_key("GET", URL, {"node": "a"})
    b = cache_key("GET", URL, {"node": "b"})
    assert a != b


def test_cache_key_order_insensitive() -> None:
    a = cache_key("GET", URL, {"x": "1", "y": "2"})
    b = cache_key("GET", URL, {"y": "2", "x": "1"})
    assert a == b


def test_cache_key_list_values_expand() -> None:
    a = cache_key("GET", URL, {"x": ["1", "2"]})
    b = cache_key("GET", URL, [("x", "1"), ("x", "2")])
    assert a == b


def test_cache_key_none_and_bool_normalize() -> None:
    a = cache_key("GET", URL, {"x": None})
    b = cache_key("GET", URL, {"x": ""})
    assert a == b
    c = cache_key("GET", URL, {"x": True})
    d = cache_key("GET", URL, {"x": "true"})
    assert c == d


def test_cache_key_different_method_changes_key() -> None:
    assert cache_key("GET", URL) != cache_key("POST", URL)


def test_cache_key_is_64_lowercase_hex() -> None:
    key = cache_key("GET", URL)
    assert len(key) == 64
    assert key == key.lower()
    int(key, 16)


# ---------------------------------------------------------------------------
# Retry policy.
# ---------------------------------------------------------------------------


@respx.mock
def test_500_exhausts_retries_and_raises(tmp_path: Path) -> None:
    respx.get(URL).mock(return_value=httpx.Response(500))
    now = [0.0]
    client = _make_client(tmp_path, now=now)

    with pytest.raises(HttpError) as exc_info:
        client.get(URL)
    assert exc_info.value.status_code == 500
    assert client.stats.retries == DEFAULT_MAX_RETRIES
    assert client.stats.network_requests == DEFAULT_MAX_RETRIES + 1


@respx.mock
def test_500_then_200_succeeds_with_one_retry(tmp_path: Path) -> None:
    route = respx.get(URL)
    route.side_effect = [httpx.Response(500), httpx.Response(200, json={"ok": True})]
    now = [0.0]
    client = _make_client(tmp_path, now=now)

    response = client.get(URL)
    assert response.json() == {"ok": True}
    assert client.stats.retries == 1
    assert route.call_count == 2


@respx.mock
def test_404_no_retry(tmp_path: Path) -> None:
    route = respx.get(URL).mock(return_value=httpx.Response(404))
    now = [0.0]
    client = _make_client(tmp_path, now=now)

    with pytest.raises(HttpError) as exc_info:
        client.get(URL)
    assert exc_info.value.status_code == 404
    assert route.call_count == 1


@respx.mock
def test_429_rate_limited_with_retry_after(tmp_path: Path) -> None:
    respx.get(URL).mock(return_value=httpx.Response(429, headers={"Retry-After": "30"}))
    now = [0.0]
    client = _make_client(tmp_path, now=now)

    with pytest.raises(RateLimitError) as exc_info:
        client.get(URL)
    assert exc_info.value.retry_after == 30.0
    assert "lorastats" in (exc_info.value.hint or "").lower()


@respx.mock
def test_connect_error_raises_after_retries(tmp_path: Path) -> None:
    respx.get(URL).mock(side_effect=httpx.ConnectError("refused"))
    now = [0.0]
    client = _make_client(tmp_path, now=now)

    with pytest.raises(HttpError):
        client.get(URL)


@respx.mock
def test_unexpected_status_raises(tmp_path: Path) -> None:
    respx.get(URL).mock(return_value=httpx.Response(304))
    now = [0.0]
    client = _make_client(tmp_path, now=now)

    with pytest.raises(HttpError) as exc_info:
        client.get(URL)
    assert "unexpected" in str(exc_info.value)


# ---------------------------------------------------------------------------
# JSON guard.
# ---------------------------------------------------------------------------


@respx.mock
def test_html_body_raises_invalid_response_error(tmp_path: Path) -> None:
    respx.get(URL).mock(return_value=httpx.Response(200, html="<html>not json</html>"))
    now = [0.0]
    client = _make_client(tmp_path, now=now)

    response = client.get(URL)
    assert response.text() == "<html>not json</html>"
    assert response.content_type is not None
    with pytest.raises(InvalidResponseError) as exc_info:
        response.json()
    assert "text/html" in exc_info.value.message


# ---------------------------------------------------------------------------
# Disk format and robustness.
# ---------------------------------------------------------------------------


@respx.mock
def test_path_for_key_shards_on_first_two_hex_chars(tmp_path: Path) -> None:
    respx.get(URL).mock(return_value=httpx.Response(200, json={"a": 1}))
    now = [0.0]
    client = _make_client(tmp_path, now=now)
    client.get(URL)

    key = cache_key("GET", URL)
    path = client.path_for_key(key)
    assert path.parent.name == key[:2]
    assert path.exists()

    entry = json.loads(path.read_text())
    assert entry["version"] == 1
    assert entry["key"] == key
    base64.b64decode(entry["body"], validate=True)
    assert "fetched_at" in entry


@respx.mock
def test_corrupt_entry_is_a_miss_and_unlinked(tmp_path: Path) -> None:
    route = respx.get(URL).mock(return_value=httpx.Response(200, json={"a": 1}))
    now = [0.0]
    client = _make_client(tmp_path, now=now)
    client.get(URL)

    key = cache_key("GET", URL)
    path = client.path_for_key(key)
    path.write_bytes(b"not valid json{{{")

    response = client.get(URL)
    assert response.from_cache is False
    assert route.call_count == 2


@respx.mock
def test_version_bump_is_treated_as_miss(tmp_path: Path) -> None:
    route = respx.get(URL).mock(return_value=httpx.Response(200, json={"a": 1}))
    now = [0.0]
    client = _make_client(tmp_path, now=now)
    client.get(URL)

    key = cache_key("GET", URL)
    path = client.path_for_key(key)
    entry = json.loads(path.read_text())
    entry["version"] = 999
    path.write_text(json.dumps(entry))

    response = client.get(URL)
    assert response.from_cache is False
    assert route.call_count == 2


@respx.mock
def test_500_response_never_written_to_disk(tmp_path: Path) -> None:
    respx.get(URL).mock(return_value=httpx.Response(500))
    now = [0.0]
    client = _make_client(tmp_path, now=now, max_retries=0)

    with pytest.raises(HttpError):
        client.get(URL)

    key = cache_key("GET", URL)
    assert not client.path_for_key(key).exists()


@respx.mock
def test_purge_and_clear(tmp_path: Path) -> None:
    respx.get(URL).mock(return_value=httpx.Response(200, json={"a": 1}))
    respx.get("https://example.invalid/other.json").mock(return_value=httpx.Response(200, json={}))
    now = [0.0]
    client = _make_client(tmp_path, now=now)
    client.get(URL)
    client.get("https://example.invalid/other.json")

    now[0] += 10000
    purged = client.purge(older_than=0)
    assert purged == 2

    now[0] = 0.0
    client.get(URL)
    cleared = client.clear()
    assert cleared == 1


# ---------------------------------------------------------------------------
# User-Agent invariants.
# ---------------------------------------------------------------------------


def test_blank_user_agent_raises(tmp_path: Path) -> None:
    with pytest.raises(MissingContactError):
        CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="   ")


@respx.mock
def test_caller_user_agent_header_is_ignored(tmp_path: Path) -> None:
    route = respx.get(URL).mock(return_value=httpx.Response(200, json={"a": 1}))
    now = [0.0]
    client = _make_client(tmp_path, now=now)

    client.get(URL, headers={"User-Agent": "evil/1.0", "X-Custom": "yes"})
    request = route.calls[0].request
    assert request.headers["user-agent"] == "meshprovision/test (+t@example.invalid)"
    assert request.headers["x-custom"] == "yes"


# ---------------------------------------------------------------------------
# resolve_ttl precedence.
# ---------------------------------------------------------------------------


def test_resolve_ttl_precedence() -> None:
    assert resolve_ttl(explicit=10, environ={"MESHPROVISION_CACHE_TTL": "20"}, config_ttl=30) == 10
    assert resolve_ttl(environ={"MESHPROVISION_CACHE_TTL": "20"}, config_ttl=30) == 20
    assert resolve_ttl(environ={}, config_ttl=30) == 30
    assert resolve_ttl(environ={}) == 300.0


def test_resolve_ttl_non_numeric_env_raises() -> None:
    with pytest.raises(SettingsError):
        resolve_ttl(environ={"MESHPROVISION_CACHE_TTL": "not-a-number"})


def test_resolve_ttl_negative_raises() -> None:
    with pytest.raises(SettingsError):
        resolve_ttl(explicit=-1)


def test_resolve_ttl_zero_is_legal() -> None:
    assert resolve_ttl(explicit=0.0) == 0.0


@respx.mock
def test_request_negative_ttl_raises(tmp_path: Path) -> None:
    respx.get(URL).mock(return_value=httpx.Response(200, json={}))
    now = [0.0]
    client = _make_client(tmp_path, now=now)
    with pytest.raises(SettingsError):
        client.get(URL, ttl=-1)
