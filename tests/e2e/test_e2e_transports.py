"""All three transport selection paths through the real ``mesh provision`` CLI.

Exercises the multi-port interactive choice, the zero-port BLE and TCP
fallbacks, and the forced ``--interface`` hard-error case -- the real
``connection.select_backend`` logic runs unpatched; only ``connect()``
itself is faked (see ``bus`` in ``tests/e2e/conftest.py``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tests.e2e.conftest import FakeMeshInterface, invoke

if TYPE_CHECKING:
    from collections.abc import Callable

    from click.testing import CliRunner

    from tests.e2e.conftest import DeviceBus

pytestmark = pytest.mark.e2e


def test_explicit_serial_port(runner: CliRunner, env: dict[str, str], bus: DeviceBus) -> None:
    bus.use(FakeMeshInterface("deadbe01"))
    result = invoke(runner, ["provision", "--port", "/dev/ttyFAKE0", "--yes", "--dry-run"], env)
    assert result.exit_code == 0
    assert bus.connections == [("serial", "/dev/ttyFAKE0")]


def test_auto_serial_single_port(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    fake_serial_ports: Callable[..., None],
) -> None:
    fake_serial_ports("/dev/ttyFAKE0")
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["provision", "--yes", "--dry-run"], env)

    assert result.exit_code == 0
    assert bus.connections == [("serial", "/dev/ttyFAKE0")]
    assert "Using the only serial port found" in result.stderr


def test_multi_port_interactive_choice(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    fake_serial_ports: Callable[..., None],
) -> None:
    fake_serial_ports("/dev/ttyFAKE0", "/dev/ttyFAKE1")
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(
        runner,
        ["--interactive", "provision", "--yes", "--dry-run"],
        env,
        input="2\n",
    )

    assert result.exit_code == 0
    assert bus.targets == ("/dev/ttyFAKE1",)
    assert "/dev/ttyFAKE0" in result.stderr
    assert "/dev/ttyFAKE1" in result.stderr


def test_multi_port_non_interactive_is_a_hard_error(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    fake_serial_ports: Callable[..., None],
) -> None:
    fake_serial_ports("/dev/ttyFAKE0", "/dev/ttyFAKE1")
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["provision", "--yes", "--dry-run"], env)

    assert result.exit_code == 5
    assert "selection" in result.stderr.lower() or "required" in result.stderr.lower()


def test_forced_interface_serial_with_two_ports_is_a_hard_error_never_a_prompt(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    fake_serial_ports: Callable[..., None],
) -> None:
    fake_serial_ports("/dev/ttyFAKE0", "/dev/ttyFAKE1")
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(
        runner,
        ["--interactive", "provision", "--interface", "serial", "--yes", "--dry-run"],
        env,
    )

    assert result.exit_code == 5
    assert "Multiple serial ports found; pass --port to choose." in result.stderr


def test_ble_explicit_address(runner: CliRunner, env: dict[str, str], bus: DeviceBus) -> None:
    bus.use(FakeMeshInterface("deadbe01"))
    result = invoke(
        runner,
        ["provision", "--ble-address", "AA:BB:CC:DD:EE:FF", "--yes", "--dry-run"],
        env,
    )
    assert result.exit_code == 0
    assert bus.connections == [("ble", "AA:BB:CC:DD:EE:FF")]


def test_ble_via_scan(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    fake_ble_devices: Callable[..., None],
) -> None:
    fake_ble_devices("AA:BB:CC:DD:EE:FF")
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["provision", "--interface", "ble", "--yes", "--dry-run"], env)

    assert result.exit_code == 0
    assert bus.connections == [("ble", "AA:BB:CC:DD:EE:FF")]


def test_ble_scan_with_multiple_devices_prompts_the_chooser(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    fake_ble_devices: Callable[..., None],
) -> None:
    """``--ble-scan`` keeps ambiguity interactive, unlike ``--interface ble``.

    Exercises ``resolve_backend``'s ``chooser=ctx.chooser`` passthrough on
    the ``--ble-scan`` branch: dropping it would turn this prompt into a
    NonInteractiveError hard failure.
    """
    fake_ble_devices("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02")
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(
        runner,
        ["--interactive", "provision", "--ble-scan", "--yes", "--dry-run"],
        env,
        input="2\n",
    )

    assert result.exit_code == 0
    assert bus.connections == [("ble", "AA:BB:CC:DD:EE:02")]
    assert "AA:BB:CC:DD:EE:01" in result.stderr


def test_zero_port_fallback_ble_scan_with_multiple_devices_prompts_the_chooser(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    fake_serial_ports: Callable[..., None],
    fake_ble_devices: Callable[..., None],
) -> None:
    """The auto fallback's BLE scan is interactive too, not just its yes/no prompt.

    Covers ``resolve_backend``'s ``chooser=ctx.chooser`` passthrough on the
    ``scanned_ble`` branch: the first input accepts the scan, the second
    picks among the devices it found.
    """
    fake_ble_devices("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02")
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(
        runner,
        ["--interactive", "provision", "--yes", "--dry-run"],
        env,
        input="y\n2\n",
    )

    assert result.exit_code == 0
    assert bus.connections == [("ble", "AA:BB:CC:DD:EE:02")]


def test_ble_scan_finding_nothing_reports_no_ble_device_found(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    fake_ble_devices: Callable[..., None],
) -> None:
    """An empty ``--ble-scan`` must fail as a BLE miss, not fall through to auto.

    Pins the direction of ``resolve_backend``'s ``if not ble_devices:``
    guard: inverting it would let an empty scan reach the auto selector
    and report the generic "No serial or BLE device found." instead, with
    the wrong hints.
    """
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["provision", "--ble-scan", "--yes", "--dry-run"], env)

    assert result.exit_code == 5
    assert "No BLE device found." in result.stderr
    assert "--ble-address" in result.stderr
    assert bus.connections == []


def test_tcp_explicit_host(runner: CliRunner, env: dict[str, str], bus: DeviceBus) -> None:
    bus.use(FakeMeshInterface("deadbe01"))
    result = invoke(runner, ["provision", "--host", "10.0.0.5:4404", "--yes", "--dry-run"], env)
    assert result.exit_code == 0
    assert bus.connections == [("tcp", "10.0.0.5:4404")]


def test_tcp_forced_without_host_is_a_hard_error(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    bus.use(FakeMeshInterface("deadbe01"))
    result = invoke(runner, ["provision", "--interface", "tcp", "--yes", "--dry-run"], env)
    assert result.exit_code == 5
    assert "No TCP host specified." in result.stderr


def test_zero_port_fallback_non_interactive(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    fake_serial_ports: Callable[..., None],
    fake_ble_devices: Callable[..., None],
) -> None:
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(runner, ["provision", "--yes", "--dry-run"], env)

    assert result.exit_code == 5
    assert "No serial or BLE device found." in result.stderr
    for hint in ("--host", "--ble-scan", "--port"):
        assert hint in result.stderr


def test_zero_port_fallback_interactive_accepting_ble_scan(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    fake_serial_ports: Callable[..., None],
    fake_ble_devices: Callable[..., None],
) -> None:
    fake_ble_devices("AA:BB:CC:DD:EE:FF")
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(
        runner,
        ["--interactive", "provision", "--yes", "--dry-run"],
        env,
        input="y\n",
    )

    assert result.exit_code == 0
    assert bus.transports == ("ble",)


def test_zero_port_fallback_interactive_declining_ble_then_giving_tcp_host(
    runner: CliRunner,
    env: dict[str, str],
    bus: DeviceBus,
    fake_serial_ports: Callable[..., None],
    fake_ble_devices: Callable[..., None],
) -> None:
    bus.use(FakeMeshInterface("deadbe01"))

    result = invoke(
        runner,
        ["--interactive", "provision", "--dry-run"],
        env,
        input="n\n10.0.0.9\n",
    )

    assert result.exit_code == 0
    assert bus.connections == [("tcp", "10.0.0.9:4403")]


def test_two_explicit_targets_is_an_error(
    runner: CliRunner, env: dict[str, str], bus: DeviceBus
) -> None:
    bus.use(FakeMeshInterface("deadbe01"))
    result = invoke(
        runner,
        ["provision", "--port", "/dev/ttyFAKE0", "--host", "10.0.0.5", "--yes", "--dry-run"],
        env,
    )
    assert result.exit_code == 5
    assert "Pass only one of --port, --ble-address, --host." in result.stderr
