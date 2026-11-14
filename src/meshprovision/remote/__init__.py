"""Offline groundwork for a possible read-only remote diff over the mesh.

It holds airtime and deadline arithmetic (:mod:`~meshprovision.remote.budget`), firmware
traits (:mod:`~meshprovision.remote.firmware`), the configuration remote work refuses
forever (:mod:`~meshprovision.remote.refused`), a section diff that tells "not read" from
"matches" (:mod:`~meshprovision.remote.diff`), the airtime ledger of a planned diff
(:mod:`~meshprovision.remote.ledger`), the offline plan of a read-only diff
(:mod:`~meshprovision.remote.plan`, with its types in
:mod:`~meshprovision.remote.plan_types`) and its text and JSON report
(:mod:`~meshprovision.remote.render`). Nothing in this package sends a packet, opens a device,
reads a file or the clock, or writes anything, and only ``mesh remote diff --dry-run``
(``cli/remote.py``) uses it, to print an offline estimate;
``tests/unit/test_remote_write_free.py`` holds it to that.

Values marked *policy* are choices, not measurements; *measured* ones come from simulator
runs of real firmware (2.6.13, 2.7.26, 2.8.3), never from hardware; *source* ones were read
in the firmware.
"""
