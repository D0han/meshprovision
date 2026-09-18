# Troubleshooting on Linux Mint

Part of the meshprovision docs — see the [README](../README.md).

## USB serial

- Check what you have: `ls -l /dev/ttyUSB* /dev/ttyACM*`, `lsusb`,
  `dmesg -w` while plugging the device in.
- The device node is group-owned by `dialout` (CH340/CP210x/FTDI adapters
  appear as `/dev/ttyUSB*`, native-USB boards such as nRF52/RP2040 as
  `/dev/ttyACM*`). Add yourself:

  ```bash
  sudo usermod -aG dialout,plugdev "$USER"
  ```

  Then **log out and back in** — group membership is only picked up on a
  new login session. `newgrp dialout` works for the current shell only.
  Verify with `id -nG`.
- **brltty steals CH340/CH341 adapters.** On Mint/Ubuntu/Debian the
  `brltty` braille-display daemon claims those USB IDs, so `/dev/ttyUSB0`
  appears and then vanishes a second later. Confirm in `dmesg` /
  `journalctl -u brltty`, then either `sudo apt remove brltty` or mask
  its udev rule (`/usr/lib/udev/rules.d/85-brltty.rules`).
- **ModemManager probes new serial ports** and can hold the port for the
  first several seconds after plug-in. If connects fail intermittently
  right after plugging in, `sudo systemctl stop ModemManager` (or add a
  udev rule with `ENV{ID_MM_DEVICE_IGNORE}="1"`) and retry.
- Inspect the device with udev:

  ```bash
  udevadm info --name=/dev/ttyUSB0 --attribute-walk | head -40
  udevadm info --query=property --name=/dev/ttyUSB0
  udevadm monitor --udev --subsystem-match=usb
  ```

  The `ID_VENDOR_ID` / `ID_MODEL_ID` properties are the VID/PID that
  meshprovision's serial discovery matches on.
- List ports the way the toolkit does: `python -m serial.tools.list_ports -v`.
- Skip discovery entirely when in doubt:
  `mesh provision --interface serial --port /dev/ttyUSB0`.

## BLE

- Requires BlueZ (Mint ships it) and a running D-Bus session. Check:
  `systemctl status bluetooth`, `bluetoothctl show`, `rfkill list
  bluetooth` (unblock with `rfkill unblock bluetooth`).
- Scan independently of meshprovision: `bluetoothctl` then `scan on`.
- `meshtastic >= 2.7.11` depends on `bleak` directly — no extra needed.
- Pairing uses the 6-digit fixed PIN stored in the `ble_pin` column of
  the `Nodes` sheet. To re-pair after a key change:
  `bluetoothctl remove <MAC>` then reconnect.
- Scans are slow on some adapters; raise `--ble-scan-timeout 15`.
- `mesh provision --interface ble --ble-address <MAC>` skips the scan.
- If scanning returns nothing as a normal user, confirm the `bluetooth`
  group / BlueZ policy allows it, and that no other tool (a phone app,
  another `bluetoothctl` session) currently holds the device — a
  Meshtastic node accepts only one BLE client at a time.

## TCP / network

- Meshtastic's TCP API listens on port 4403. Test reachability first:
  `nc -vz 192.168.1.50 4403` or `ping 192.168.1.50`.
- `--host` accepts `HOST` or `HOST:PORT`.
- Mint's firewall (`ufw`) is inactive by default. If you enabled it,
  allow outbound: `sudo ufw allow out 4403/tcp`. Check with
  `sudo ufw status verbose`.
- The node must have WiFi enabled and be on the same network/VLAN; client
  isolation on a guest SSID will silently block this.
- Separately, `mesh status` needs outbound HTTPS to loranet.pl and
  lorastats.pl, and will fail at startup with a clear message if
  `MESHPROVISION_CONTACT` is unset. Do not work around a lorastats block
  by retrying — that site bans IP addresses.

## General

- Add `-v` (before the subcommand) to see this tool's own HTTP fetch
  trace, or `--log-level debug` for a full trace of its own logic. Key
  material is redacted at every log level.
- A connect (BLE especially) hanging with no output? `mesh` always
  prints a `Connecting over ...` line and a `still connecting... Ns /
  Ms` heartbeat every 10s while it waits, so a stalled connect is
  visible without any flag. For the underlying library's own trace, add
  `-vv` (`meshtastic`/`httpx`) or `-vvv` (also `bleak`'s raw GATT
  chatter) before the subcommand, e.g. `mesh -vvv adopt --ble-scan`.
- `mesh db verify` after any hand-edit; `mesh --version` to confirm which
  build is on `PATH`; `which mesh` if you have more than one venv.
