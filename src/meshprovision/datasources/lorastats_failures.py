"""When a failed lorastats request means lorastats.pl should not be asked again in this run.

Shared by the refreshers of ``mesh health`` (per node) and ``mesh network``
(per region): once lorastats.pl is down or refusing, every further request
of the same refresh would only cost its retries and their back-off, so the
refresh stops asking. A failure of one answer (a 404, an unusable or
over-large body) says nothing about the others and does not stop it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import httpx

from meshprovision.errors import DataSourceError, HttpError, InvalidResponseError, RateLimitError

if TYPE_CHECKING:
    import logging

__all__ = ["is_outage", "outage_error"]

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


def outage_error(
    exc: DataSourceError, subject: str, *, asked: str, others: str, logger: logging.Logger
) -> DataSourceError | None:
    """Log a failed request; on an outage, return the error to report instead of every later one.

    Args:
        exc: The request's error.
        subject: What it was for (a node's hex id, a region).
        asked: What was asked, for the log (``"lorastats packets"``).
        others: What is no longer asked about, for the log (``"node"``).
        logger: The refresher's logger, which both warnings go to.

    Returns:
        A "not asked" error naming ``subject`` when ``exc`` is an outage
        (see :func:`is_outage`), else ``None``.
    """
    logger.warning("%s for %s failed: %s", asked, subject, exc.message)
    if not is_outage(exc):
        return None
    logger.warning("lorastats is failing; not asking it about any other %s in this refresh", others)
    return DataSourceError(f"not asked: lorastats failed for {subject} ({exc.message})")
