"""The ``mesh network``/``mesh health`` time renderers: an out-of-range epoch shows as unknown."""

from __future__ import annotations

import pytest

from meshprovision.health import render as health_render
from meshprovision.network.render_common import iso, time_text

pytestmark = pytest.mark.unit

_NOW = 1_792_526_400
_FAR = 1e12
"""Year 33658: past every datetime, as a corrupt cache value can be."""


def test_an_epoch_in_range_is_rendered() -> None:
    assert iso(_NOW) == "2026-10-20T20:00:00Z"
    assert time_text(_NOW) != "-"
    assert health_render._iso(_NOW) == "2026-10-20T20:00:00Z"


@pytest.mark.parametrize("epoch", [None, _FAR, float("inf")])
def test_an_unknown_or_out_of_range_epoch_renders_as_unknown(epoch: float | None) -> None:
    assert time_text(epoch) == "-"
    assert iso(epoch) is None
    assert health_render._time(epoch) is None
    assert health_render._iso(epoch) is None
