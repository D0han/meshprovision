"""Offline groundwork for a possible read-only remote diff over the mesh.

It holds airtime and deadline arithmetic (:mod:`~meshprovision.remote.budget`), firmware
traits (:mod:`~meshprovision.remote.firmware`), the configuration remote work refuses
forever (:mod:`~meshprovision.remote.refused`) and a section diff that tells "not read"
from "matches" (:mod:`~meshprovision.remote.diff`). Nothing in this package sends a
packet, opens a device, reads a file or the clock, or writes anything, and no command
uses it yet; ``tests/unit/test_remote_write_free.py`` holds it to that.

Values marked *policy* are choices, not measurements; *measured* ones come from simulator
runs of real firmware (2.6.13, 2.7.26, 2.8.3), never from hardware; *source* ones were read
in the firmware.
"""
