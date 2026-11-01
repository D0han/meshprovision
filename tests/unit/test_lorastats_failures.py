"""``is_outage``: which failed lorastats requests stop a refresh."""

from __future__ import annotations

import httpx
import pytest

from meshprovision.datasources.lorastats_failures import is_outage
from meshprovision.errors import (
    DataSourceError,
    HttpError,
    InvalidResponseError,
    RateLimitCoolingDownError,
    RateLimitError,
)

pytestmark = pytest.mark.unit


def _caused_by(cause: Exception) -> HttpError:
    try:
        raise HttpError("failed", url="u") from cause
    except HttpError as exc:
        return exc


@pytest.mark.parametrize(
    ("error", "outage"),
    [
        pytest.param(RateLimitError("slow", url="u", status_code=429), True, id="429"),
        pytest.param(RateLimitCoolingDownError("cooling", url="u"), True, id="cooling-down"),
        pytest.param(HttpError("500", url="u", status_code=500), True, id="500"),
        pytest.param(HttpError("599", url="u", status_code=599), True, id="599"),
        pytest.param(HttpError("499", url="u", status_code=499), False, id="499"),
        pytest.param(HttpError("404", url="u", status_code=404), False, id="404"),
        pytest.param(_caused_by(httpx.ConnectError("refused")), True, id="transport"),
        pytest.param(_caused_by(ValueError("odd")), False, id="other-cause"),
        pytest.param(HttpError("too large", url="u"), False, id="no-status-no-cause"),
        pytest.param(
            InvalidResponseError("bad gateway page", url="u", status_code=502),
            False,
            id="unusable-5xx-body",
        ),
        pytest.param(DataSourceError("odd"), False, id="not-http"),
    ],
)
def test_only_a_429_a_5xx_or_no_answer_is_an_outage(error: DataSourceError, outage: bool) -> None:
    assert is_outage(error) is outage
