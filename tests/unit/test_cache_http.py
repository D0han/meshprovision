"""Tests for meshprovision.cache.http."""

from __future__ import annotations

import base64
import json
import os
import ssl
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
import respx

from meshprovision.cache import http as http_module
from meshprovision.cache.http import (
    DEFAULT_BACKOFF_BASE,
    DEFAULT_BACKOFF_MAX,
    DEFAULT_MAX_RETRIES,
    CachedHTTPClient,
    CachedResponse,
    cache_key,
    resolve_ttl,
)
from meshprovision.errors import (
    CacheError,
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
    sleep: Callable[[float], None] = lambda _s: None,
    backoff_base: float = DEFAULT_BACKOFF_BASE,
    backoff_max: float = DEFAULT_BACKOFF_MAX,
) -> CachedHTTPClient:
    return CachedHTTPClient(
        cache_dir=tmp_path / "cache",
        user_agent="meshprovision/test (+t@example.invalid)",
        ttl=ttl,
        clock=lambda: now[0],
        sleep=sleep,
        force_refresh=force_refresh,
        max_retries=max_retries,
        backoff_base=backoff_base,
        backoff_max=backoff_max,
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
# _display_url: the query string shown in the "fetching ..." log line.
# ---------------------------------------------------------------------------


def test_display_url_without_params_is_unchanged() -> None:
    from meshprovision.cache.http import _display_url

    assert _display_url(URL, None) == URL
    assert _display_url(URL, {}) == URL


def test_display_url_appends_params_in_input_order() -> None:
    from meshprovision.cache.http import _display_url

    assert _display_url(URL, {"node": "ab446357"}) == f"{URL}?node=ab446357"
    assert (
        _display_url(URL, [("b", "2"), ("a", "1")]) == f"{URL}?b=2&a=1"
    )  # order preserved, unlike cache_key's sort


@respx.mock
def test_fetch_log_line_includes_the_query_string(tmp_path: Path, caplog) -> None:
    """Distinct per-node requests (lorastats.pl's ``?node=<hex>``) must log distinctly.

    Regression test: the fetch log previously rendered only the bare
    URL, so four distinct ``?node=`` requests during ``mesh status``
    printed as four identical "fetching ..." lines.
    """
    respx.get(URL).mock(return_value=httpx.Response(200, json={"a": 1}))
    client = _make_client(tmp_path, now=[0.0])

    with caplog.at_level("INFO", logger="meshprovision.cache.http"):
        client.get(URL, params={"node": "ab446357"})

    messages = [r.getMessage() for r in caplog.records]
    assert any("node=ab446357" in message for message in messages)


@respx.mock
def test_fetch_log_line_has_no_trailing_question_mark_without_params(
    tmp_path: Path, caplog
) -> None:
    respx.get(URL).mock(return_value=httpx.Response(200, json={"a": 1}))
    client = _make_client(tmp_path, now=[0.0])

    with caplog.at_level("INFO", logger="meshprovision.cache.http"):
        client.get(URL)

    messages = [r.getMessage() for r in caplog.records if "fetching" in r.getMessage()]
    assert messages
    assert all("?" not in message for message in messages)


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


def test_parse_retry_after_header_absent_returns_none() -> None:
    from meshprovision.cache.http import _parse_retry_after

    assert _parse_retry_after(None, clock=lambda: 0.0) is None


@pytest.mark.parametrize("value", ["", "   "])
def test_parse_retry_after_empty_or_whitespace_returns_none(value: str) -> None:
    from meshprovision.cache.http import _parse_retry_after

    assert _parse_retry_after(value, clock=lambda: 0.0) is None


def test_parse_retry_after_http_date_computes_delay_from_clock() -> None:
    from meshprovision.cache.http import _parse_retry_after

    # Fri, 02 Jan 1970 00:00:30 GMT == epoch 30.0 (2 Jan minus 1 Jan = 86400s + 30s).
    header = "Fri, 02 Jan 1970 00:00:30 GMT"
    delay = _parse_retry_after(header, clock=lambda: 86400.0)
    assert delay == pytest.approx(30.0)


def test_parse_retry_after_http_date_in_past_clamps_to_zero() -> None:
    from meshprovision.cache.http import _parse_retry_after

    header = "Thu, 01 Jan 1970 00:00:00 GMT"
    delay = _parse_retry_after(header, clock=lambda: 1000.0)
    assert delay == 0.0


def test_parse_retry_after_date_without_timezone_returns_none() -> None:
    from meshprovision.cache.http import _parse_retry_after

    # A date string with no timezone/offset parses to a naive datetime,
    # which the tzinfo-None guard rejects rather than mis-computing a delay.
    assert _parse_retry_after("02 Jan 1970 00:00:30", clock=lambda: 0.0) is None


def test_parse_retry_after_malformed_date_returns_none() -> None:
    from meshprovision.cache.http import _parse_retry_after

    assert _parse_retry_after("not a date", clock=lambda: 0.0) is None


@respx.mock
def test_connect_error_raises_after_retries(tmp_path: Path) -> None:
    route = respx.get(URL).mock(side_effect=httpx.ConnectError("refused"))
    now = [0.0]
    client = _make_client(tmp_path, now=now)

    with pytest.raises(HttpError):
        client.get(URL)

    # The transport-error path must retry as many times as the 5xx path
    # does; asserting only that HttpError escapes would still pass if the
    # loop bailed out after a single attempt.
    assert route.call_count == DEFAULT_MAX_RETRIES + 1
    assert client.stats.retries == DEFAULT_MAX_RETRIES
    assert client.stats.network_requests == DEFAULT_MAX_RETRIES + 1


@respx.mock
def test_backoff_delays_grow_exponentially_from_the_base(tmp_path: Path) -> None:
    """Retry delays must be ``backoff_base * 2**attempt``, attempt zero-based."""
    respx.get(URL).mock(return_value=httpx.Response(500))
    delays: list[float] = []
    now = [0.0]
    client = _make_client(
        tmp_path, now=now, sleep=delays.append, backoff_base=0.25, backoff_max=1000.0
    )

    with pytest.raises(HttpError):
        client.get(URL)

    assert delays == [0.25, 0.5, 1.0]


@respx.mock
def test_backoff_delay_is_clamped_to_backoff_max(tmp_path: Path) -> None:
    respx.get(URL).mock(return_value=httpx.Response(500))
    delays: list[float] = []
    now = [0.0]
    client = _make_client(
        tmp_path, now=now, sleep=delays.append, backoff_base=10.0, backoff_max=15.0
    )

    with pytest.raises(HttpError):
        client.get(URL)

    assert delays == [10.0, 15.0, 15.0]


@respx.mock
def test_unexpected_status_raises(tmp_path: Path) -> None:
    respx.get(URL).mock(return_value=httpx.Response(304))
    now = [0.0]
    client = _make_client(tmp_path, now=now)

    with pytest.raises(HttpError) as exc_info:
        client.get(URL)
    assert "unexpected" in str(exc_info.value)


@respx.mock
def test_too_many_redirects_raises_http_error_without_retry(tmp_path: Path) -> None:
    """A redirect loop is a `RequestError`, not a `TransportError`: it must not be retried."""
    route = respx.get(URL).mock(return_value=httpx.Response(302, headers={"Location": URL}))
    now = [0.0]
    client = _make_client(tmp_path, now=now)

    with pytest.raises(HttpError) as exc_info:
        client.get(URL)
    assert isinstance(exc_info.value.__cause__, httpx.TooManyRedirects)
    assert client.stats.retries == 0
    assert client.stats.network_requests == 1
    assert route.call_count > 1  # httpx itself follows the loop before giving up.
    assert "redirecting in a loop" in (exc_info.value.hint or "")


_DOWNGRADE_LOCATION = "http://evil.invalid/data.json?token=secret"


@respx.mock
def test_https_to_http_redirect_is_refused_without_retry_or_cache(tmp_path: Path) -> None:
    """An https -> http redirect must never be sent, retried, or cached."""
    respx.get(URL).mock(return_value=httpx.Response(302, headers={"Location": _DOWNGRADE_LOCATION}))
    downgraded = respx.route(host="evil.invalid").mock(
        return_value=httpx.Response(200, json={"a": 1})
    )
    now = [0.0]
    client = _make_client(tmp_path, now=now)

    with pytest.raises(HttpError) as exc_info:
        client.get(URL)
    assert isinstance(exc_info.value.__cause__, http_module._InsecureRedirectError)
    assert downgraded.call_count == 0
    assert client.stats.retries == 0
    assert client.stats.network_requests == 1
    assert list((tmp_path / "cache").rglob("*.json")) == []


@respx.mock
def test_https_downgrade_hint_names_target_without_query(tmp_path: Path) -> None:
    respx.get(URL).mock(return_value=httpx.Response(301, headers={"Location": _DOWNGRADE_LOCATION}))
    now = [0.0]
    client = _make_client(tmp_path, now=now)

    with pytest.raises(HttpError) as exc_info:
        client.get(URL)
    hint = exc_info.value.hint or ""
    assert "redirected to http://evil.invalid/data.json, which would drop HTTPS" in hint
    assert "secret" not in hint
    assert "secret" not in str(exc_info.value)


@respx.mock
def test_relative_same_host_redirect_is_followed(tmp_path: Path) -> None:
    respx.get(URL).mock(return_value=httpx.Response(301, headers={"Location": "/moved.json"}))
    moved = respx.get("https://example.invalid/moved.json").mock(
        return_value=httpx.Response(200, json={"a": 1})
    )
    now = [0.0]
    client = _make_client(tmp_path, now=now)

    assert client.get(URL).json() == {"a": 1}
    assert moved.call_count == 1


@respx.mock
def test_cross_host_https_redirect_is_followed(tmp_path: Path) -> None:
    respx.get(URL).mock(
        return_value=httpx.Response(302, headers={"Location": "https://cdn.example.invalid/d.json"})
    )
    cdn = respx.get("https://cdn.example.invalid/d.json").mock(
        return_value=httpx.Response(200, json={"a": 1})
    )
    now = [0.0]
    client = _make_client(tmp_path, now=now)

    assert client.get(URL).json() == {"a": 1}
    assert cdn.call_count == 1


class _RawByteStream(httpx.SyncByteStream):
    """A byte stream whose content is not decoded until it is read.

    Passing bytes directly as `httpx.Response(content=...)` decodes them
    eagerly in `Response.__init__`, which would raise `DecodingError` at
    mock-setup time rather than when the client actually reads the
    response -- this stream defers that to match real network behavior.
    """

    def __init__(self, data: bytes) -> None:
        self._data = data

    def __iter__(self) -> object:
        yield self._data


@respx.mock
def test_undecodable_content_encoding_raises_http_error_without_retry(tmp_path: Path) -> None:
    """A body that fails to decode per its declared Content-Encoding must not be retried."""
    bad_response = httpx.Response(
        200,
        headers={"content-encoding": "gzip"},
        stream=_RawByteStream(b"not gzip data"),
    )
    route = respx.get(URL).mock(return_value=bad_response)
    now = [0.0]
    client = _make_client(tmp_path, now=now)

    with pytest.raises(HttpError) as exc_info:
        client.get(URL)
    assert isinstance(exc_info.value.__cause__, httpx.DecodingError)
    assert client.stats.retries == 0
    assert client.stats.network_requests == 1
    assert route.call_count == 1


@respx.mock
@pytest.mark.parametrize("exc_type", [httpx.RemoteProtocolError, httpx.ReadTimeout])
def test_transport_errors_mid_body_are_retried_then_wrapped(
    tmp_path: Path, exc_type: type[httpx.TransportError]
) -> None:
    """`TransportError` subclasses still retry: the new `RequestError` arm must not steal them.

    `RemoteProtocolError` and `ReadTimeout` are `TransportError` subclasses
    and were already retried before the `RequestError` arm was added; this
    pins that the broader arm -- which sits after `TransportError` in the
    except chain -- does not change their behavior.
    """
    route = respx.get(URL).mock(side_effect=exc_type("simulated"))
    now = [0.0]
    client = _make_client(tmp_path, now=now)

    with pytest.raises(HttpError) as exc_info:
        client.get(URL)
    assert isinstance(exc_info.value.__cause__, exc_type)
    assert client.stats.retries == DEFAULT_MAX_RETRIES
    assert route.call_count == DEFAULT_MAX_RETRIES + 1


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


_NOW = 1_700_000_000.0
_A_YEAR = 365 * 86400.0


def _set_fetched_at(client: CachedHTTPClient, value: float) -> Path:
    path = client.path_for_key(cache_key("GET", URL))
    entry = json.loads(path.read_text())
    entry["fetched_at"] = value
    path.write_text(json.dumps(entry))
    return path


@respx.mock
@pytest.mark.parametrize(
    "fetched_at",
    [float("inf"), float("nan"), 1e300, -1.0, _NOW + _A_YEAR],
    ids=["inf", "nan", "1e300", "before-the-epoch", "a-year-ahead"],
)
def test_out_of_range_fetched_at_is_never_fresh_and_is_refetched(
    tmp_path: Path, fetched_at: float
) -> None:
    """An unusable or future ``fetched_at`` must never keep an entry fresh, or crash a reader.

    A TTL of a century makes every finite one of these "fresh" by age alone.
    """
    route = respx.get(URL).mock(return_value=httpx.Response(200, json={"a": 1}))
    now = [_NOW]
    client = _make_client(tmp_path, now=now, ttl=100 * _A_YEAR)
    client.get(URL)
    path = _set_fetched_at(client, fetched_at)

    response = client.get(URL)

    assert response.from_cache is False
    assert response.fetched_at == _NOW
    assert route.call_count == 2
    assert json.loads(path.read_text())["fetched_at"] == _NOW


@respx.mock
@pytest.mark.parametrize("ahead", [60.0, 300.0], ids=["a-minute-ahead", "at-the-skew-limit"])
def test_fetched_at_slightly_ahead_of_the_clock_is_still_a_hit(
    tmp_path: Path, ahead: float
) -> None:
    """A small backwards clock correction (an NTP step) must not discard the cache."""
    route = respx.get(URL).mock(return_value=httpx.Response(200, json={"a": 1}))
    now = [_NOW]
    client = _make_client(tmp_path, now=now)
    client.get(URL)
    _set_fetched_at(client, _NOW + ahead)

    response = client.get(URL)

    assert response.from_cache is True
    assert response.fetched_at == _NOW + ahead
    assert route.call_count == 1


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
@pytest.mark.skipif(os.name != "posix", reason="permission bits are not meaningful on this OS")
def test_cache_root_is_owner_only_after_the_first_write(tmp_path: Path) -> None:
    respx.get(URL).mock(return_value=httpx.Response(200, json={"a": 1}))
    now = [0.0]
    client = _make_client(tmp_path, now=now)

    previous_umask = os.umask(0o000)
    try:
        client.get(URL)
    finally:
        os.umask(previous_umask)

    assert client.cache_dir.stat().st_mode & 0o777 == 0o700


@respx.mock
def test_write_failure_returns_the_response_uncached_and_logs_a_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    respx.get(URL).mock(return_value=httpx.Response(200, json={"a": 1}))
    now = [0.0]
    client = _make_client(tmp_path, now=now)

    def _fail_replace(self: Path, target: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Path, "replace", _fail_replace)

    with caplog.at_level("WARNING"):
        response = client.get(URL)

    assert response.status_code == 200
    assert response.from_cache is False
    assert "No space left on device" in caplog.text
    assert "MESHPROVISION_CACHE_DIR" in caplog.text

    path = client.path_for_key(cache_key("GET", URL))
    assert not path.exists()
    assert list(path.parent.glob(f"{path.name}.tmp-*")) == []
    assert client.stats.writes == 0

    # `_write_entry`'s own contract is unchanged: called directly, it still
    # raises `CacheError` with `__cause__` set to the underlying `OSError`.
    fetched = CachedResponse(
        status_code=200,
        headers={},
        content=b'{"a": 1}',
        url=URL,
        method="GET",
        fetched_at=now[0],
        cache_key=cache_key("GET", URL),
        from_cache=False,
    )
    with pytest.raises(CacheError) as excinfo:
        client._write_entry(path, fetched)
    assert excinfo.value.path == str(path)
    assert "No space left on device" in str(excinfo.value)
    assert excinfo.value.hint is not None
    assert "MESHPROVISION_CACHE_DIR" in excinfo.value.hint
    assert isinstance(excinfo.value.__cause__, OSError)


@respx.mock
def test_write_failure_before_the_temp_file_exists_still_returns_uncached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    respx.get(URL).mock(return_value=httpx.Response(200, json={"a": 1}))
    now = [0.0]
    client = _make_client(tmp_path, now=now)

    def _fail_write_bytes(self: Path, data: object) -> int:
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(Path, "write_bytes", _fail_write_bytes)

    with caplog.at_level("WARNING"):
        response = client.get(URL)

    assert response.status_code == 200
    assert response.from_cache is False
    assert "Permission denied" in caplog.text
    assert client.stats.writes == 0

    path = client.path_for_key(cache_key("GET", URL))
    assert not path.exists()
    assert list(path.parent.glob(f"{path.name}.tmp-*")) == []


@respx.mock
def test_write_failure_from_a_missing_shard_directory_still_returns_uncached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    respx.get(URL).mock(return_value=httpx.Response(200, json={"a": 1}))
    now = [0.0]
    client = _make_client(tmp_path, now=now)

    def _fail_mkdir(
        self: Path, mode: int = 0o777, parents: bool = False, exist_ok: bool = False
    ) -> None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "mkdir", _fail_mkdir)

    with caplog.at_level("WARNING"):
        response = client.get(URL)

    assert response.status_code == 200
    assert response.from_cache is False
    assert "Permission denied" in caplog.text
    assert client.stats.writes == 0


# ---------------------------------------------------------------------------
# User-Agent invariants.
# ---------------------------------------------------------------------------


def test_blank_user_agent_raises(tmp_path: Path) -> None:
    with pytest.raises(MissingContactError):
        CachedHTTPClient(cache_dir=tmp_path / "cache", user_agent="   ")


def test_internal_client_verifies_tls_certificates(tmp_path: Path) -> None:
    """The self-built ``httpx.Client`` must carry a verifying SSL context.

    Every other test either mocks at the ``respx`` transport layer or
    injects its own ``httpx.Client``, so nothing else exercises the
    ``verify=True`` argument. Assert on the resulting ``ssl.SSLContext``
    rather than on a stored flag, since httpx keeps no public record of
    what ``verify`` was passed.
    """
    with CachedHTTPClient(
        cache_dir=tmp_path / "cache", user_agent="meshprovision/test (+t@example.invalid)"
    ) as client:
        context = client._client._transport._pool._ssl_context

    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


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
def test_request_zero_ttl_is_accepted_and_always_refetches(tmp_path: Path) -> None:
    """``ttl=0`` is legal and means "always refetch, still write"."""
    route = respx.get(URL).mock(return_value=httpx.Response(200, json={"a": 1}))
    now = [0.0]
    client = _make_client(tmp_path, now=now)

    client.get(URL, ttl=0)
    assert route.call_count == 1

    now[0] += 1
    second = client.get(URL, ttl=0)
    assert second.from_cache is False
    assert route.call_count == 2
    assert client.stats.hits == 0
    assert client.stats.writes == 2


@respx.mock
def test_request_negative_ttl_raises(tmp_path: Path) -> None:
    respx.get(URL).mock(return_value=httpx.Response(200, json={}))
    now = [0.0]
    client = _make_client(tmp_path, now=now)
    with pytest.raises(SettingsError):
        client.get(URL, ttl=-1)
