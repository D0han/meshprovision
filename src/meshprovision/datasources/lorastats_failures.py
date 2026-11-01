"""When a failed lorastats request means lorastats.pl should not be asked again in this run.

Shared by the refreshers of ``mesh health`` (per node) and ``mesh network``
(per region): once lorastats.pl is down or refusing, every further request
of the same refresh would only cost its retries and their back-off, so the
refresh stops asking. A failure of one answer (a 404, an unusable or
over-large body) says nothing about the others and does not stop it.
"""

from __future__ import annotations

from typing import Final

import httpx

from meshprovision.errors import DataSourceError, HttpError, InvalidResponseError, RateLimitError

__all__ = ["is_outage"]

_SERVER_ERROR_MIN: Final[int] = 500


def is_outage(exc: DataSourceError) -> bool:
    """Tell whether a failed request means lorastats.pl is down or refusing.

    Args:
        exc: The request's error.

    Returns:
        ``True`` for a 429 (or its cool-down), a 5xx answer, or a
        transport error (no answer at all); ``False`` for anything else,
        including an answer that could not be used.
    """
    if isinstance(exc, RateLimitError):
        return True
    if not isinstance(exc, HttpError) or isinstance(exc, InvalidResponseError):
        return False
    if exc.status_code is not None:
        return exc.status_code >= _SERVER_ERROR_MIN
    return isinstance(exc.__cause__, httpx.TransportError)
