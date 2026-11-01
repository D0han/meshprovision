"""The relays view's device-health cell and loranet status line."""

from __future__ import annotations

import pytest

from meshprovision.network.relays import DeviceHealth
from meshprovision.network.render import device_text, loranet_line
from meshprovision.network.report import LoranetView
from tests.unit.network_fixtures import NOW

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("device", "text"),
    [
        pytest.param(None, "-", id="none"),
        pytest.param(DeviceHealth(metrics_at=NOW), "-", id="nothing-known"),
        pytest.param(
            DeviceHealth(
                external_power=True, voltage=12.8, uptime_seconds=2 * 86400, channel_utilization=7.9
            ),
            "ext 12.80V, up 2d, ChU 7.9%",
            id="external",
        ),
        pytest.param(
            DeviceHealth(
                battery_level=77, voltage=3.97, uptime_seconds=10 * 86400, channel_utilization=2.0
            ),
            "77% 3.97V, up 10d, ChU 2.0%",
            id="battery",
        ),
        pytest.param(DeviceHealth(voltage=4.1), "4.10V", id="voltage-only"),
        pytest.param(DeviceHealth(uptime_seconds=65), "up 1m", id="minutes"),
        pytest.param(DeviceHealth(uptime_seconds=59), "up 59s", id="seconds"),
        pytest.param(DeviceHealth(uptime_seconds=5 * 3600), "up 5h", id="hours"),
        pytest.param(
            DeviceHealth(channel_utilization=3.0, metrics_at=NOW - 3 * 86400),
            "ChU 3.0% (metrics 3d old)",
            id="stale-metrics",
        ),
        pytest.param(
            DeviceHealth(channel_utilization=3.0, metrics_at=NOW - 86400),
            "ChU 3.0%",
            id="a-day-old-is-fresh",
        ),
        pytest.param(DeviceHealth(air_util_tx=0.4), "-", id="air-util-only"),
    ],
)
def test_the_device_cell(device: DeviceHealth | None, text: str) -> None:
    assert device_text(device, now=NOW) == text


def test_loranet_lines() -> None:
    assert loranet_line(None) is None
    assert loranet_line(LoranetView(asked=True)) is None
    not_asked = loranet_line(LoranetView(asked=False))
    assert not_asked is not None
    assert not_asked.plain == "loranet not asked (--no-fetch): no device health."
    failed = loranet_line(LoranetView(asked=True, error="HTTP 500 [/]\x1b[31m"))
    assert failed is not None
    assert failed.plain == "loranet: HTTP 500 [/]\\x1b[31m"
