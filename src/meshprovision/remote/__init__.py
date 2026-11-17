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
in the firmware; *model* ones are the planning model's own figures, worked out from the
firmware but not read in one place of it.

The citations OPINION(-REMOTE-ADMIN), COMPARE, T1 to T7, PRESETS-PL(-RESULTS), SIM-REVIEW,
REFINED, PLAN-REVIEW-59 and simulator runs such as "A1 run s01_3" name the maintainer's
research documents on remote admin, which are not part of this repository. The firmware
``file:line`` citations (Meshtastic firmware 2.8.3 unless a version is named) are the ones a
reader can check.
"""
