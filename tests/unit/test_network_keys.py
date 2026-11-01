"""The key scan: sightings from advertised keys, and every finding rule."""

from __future__ import annotations

import hashlib
import zlib

import pytest

from meshprovision.crypto.known_bad_keys import SMALL_ORDER_POINTS
from meshprovision.crypto.redact import fingerprint
from meshprovision.health.history import HOUR_SECONDS, floor_hour
from meshprovision.network.keys import (
    FindingKind,
    FleetKey,
    KeyAudit,
    KeyFinding,
    KeySeen,
    Severity,
    fleet_key,
    merge_seen,
    observe,
    scan_keys,
    short_digest,
)
from meshprovision.network.rawpackets import AdvertisedKey
from meshprovision.nodeid import NodeId
from tests.unit.network_fixtures import NOW

pytestmark = pytest.mark.unit

_H = floor_hour(NOW)
_START = NOW - 30 * 24 * 3600
_KEY = hashlib.sha256(b"key").digest()
_DIGEST = fingerprint(_KEY, chars=16)


def _seen(node: str, digest: str = _DIGEST, *hours: int, derived: bool = False) -> KeySeen:
    spread = hours or (_H,)
    return KeySeen(
        node=node,
        digest=digest,
        first=min(spread) + 10,
        last=max(spread) + 20,
        hours=tuple(sorted(spread)),
        derived=derived,
    )


def _advert(node: int, key: bytes, time: float, short: str = "AB") -> AdvertisedKey:
    return AdvertisedKey(time, NodeId(node), key, short, "HELTEC_V3", "ROUTER")


def test_observe_groups_a_fetch_by_node_and_key_and_audits_each_key() -> None:
    weak = SMALL_ORDER_POINTS[1]
    adverts = [
        _advert(0xAB446357, _KEY, NOW - 7200, "old"),
        _advert(0xAB446357, _KEY, NOW - 60, "new"),
        _advert(0x11111111, weak, NOW - 60),
    ]

    seen = observe(adverts, known_bad=frozenset())

    assert seen[0] == KeySeen(
        node="11111111",
        digest=fingerprint(weak, chars=16),
        first=NOW - 60,
        last=NOW - 60,
        hours=(floor_hour(NOW - 60),),
        short_name="AB",
        hw_model="HELTEC_V3",
        role="ROUTER",
        derived=False,
        audit=KeyAudit(Severity.CRITICAL, ("low_entropy", "small_order")),
    )
    mine = seen[1]
    assert (mine.node, mine.first, mine.last, mine.short_name, mine.audit) == (
        "ab446357",
        NOW - 7200,
        NOW - 60,
        "new",
        None,
    )
    assert mine.hours == (floor_hour(NOW - 7200), floor_hour(NOW - 60))
    assert _KEY.hex() not in repr(seen)


def test_observe_passes_the_blocklist_to_the_audit() -> None:
    (seen,) = observe([_advert(0xAB446357, _KEY, NOW)], known_bad=frozenset({_KEY}))

    assert seen.audit == KeyAudit(Severity.CRITICAL, ("blocklist",))


def test_an_id_derived_from_its_key_is_recognised() -> None:
    derived = zlib.crc32(_KEY)

    seen = observe([_advert(derived, _KEY, NOW), _advert(1, _KEY, NOW)], known_bad=frozenset())

    assert [entry.derived for entry in seen] == [False, True]
    assert fleet_key(f"{derived:08x}", _KEY) == FleetKey(f"{derived:08x}", _DIGEST, True)
    assert fleet_key("00000001", None) == FleetKey("00000001")


def test_merge_keeps_the_span_every_hour_and_the_latest_names() -> None:
    old = KeySeen("ab446357", _DIGEST, 100.0, 3600.0, (0,), "Old", None, None, False, None)
    audit = KeyAudit(Severity.WARNING, ("monotonic",))
    new = KeySeen("ab446357", _DIGEST, 7300.0, 7400.0, (7200,), "New", "X", "ROUTER", False, audit)

    assert merge_seen(old, new) == KeySeen(
        "ab446357", _DIGEST, 100.0, 7400.0, (0, 7200), "New", "X", "ROUTER", False, audit
    )
    assert merge_seen(new, old) == merge_seen(old, new)


def test_merge_keeps_only_the_newest_168_hours() -> None:
    old = _seen("ab446357", _DIGEST, *(i * HOUR_SECONDS for i in range(100)))
    new = _seen("ab446357", _DIGEST, *(i * HOUR_SECONDS for i in range(100, 200)))

    assert merge_seen(old, new).hours == tuple(i * HOUR_SECONDS for i in range(32, 200))


def test_the_short_digest_is_the_usual_fingerprint() -> None:
    assert short_digest(_DIGEST) == fingerprint(_KEY)


def _kinds(
    *seen: KeySeen, fleet: tuple[FleetKey, ...] = ()
) -> list[tuple[str, str, tuple[str, ...], bool]]:
    scan = scan_keys(seen, fleet, start=_START)
    return [(f.kind.value, f.severity.value, f.nodes, f.fleet) for f in scan.findings]


def test_nothing_shared_nothing_found() -> None:
    assert _kinds(_seen("a"), _seen("b", "sha256:" + "1" * 16)) == []


def test_two_ids_in_the_same_hour_are_a_clone() -> None:
    assert _kinds(_seen("a", _DIGEST, _H), _seen("b", _DIGEST, _H, _H - HOUR_SECONDS)) == [
        ("clone", "critical", ("b", "a"), False)
    ]


def test_ids_that_alternate_are_a_clone() -> None:
    a = _seen("a", _DIGEST, _H - 3 * HOUR_SECONDS, _H - HOUR_SECONDS)
    b = _seen("b", _DIGEST, _H - 2 * HOUR_SECONDS)

    assert _kinds(a, b)[0][:2] == ("clone", "critical")


def test_ids_one_after_another_are_a_hand_over() -> None:
    a = _seen("a", _DIGEST, _H - 3 * HOUR_SECONDS, _H - 2 * HOUR_SECONDS)
    b = _seen("b", _DIGEST, _H - HOUR_SECONDS, _H)

    scan = scan_keys((a, b), (), start=_START)

    assert scan.findings == (
        KeyFinding(FindingKind.HANDOVER, Severity.WARNING, _DIGEST, ("a", "b"), False, (), a.last),
    )


def test_the_key_derived_id_after_the_old_one_is_a_migration() -> None:
    old = _seen("a", _DIGEST, _H - 3 * HOUR_SECONDS)
    new = _seen("b", _DIGEST, _H, derived=True)

    assert _kinds(old, new) == [("migration", "info", ("a", "b"), False)]


@pytest.mark.parametrize(
    "derived_first", [pytest.param(True, id="old-derived"), pytest.param(False, id="none-derived")]
)
def test_without_exactly_the_newest_derived_it_is_a_hand_over(derived_first: bool) -> None:
    old = _seen("a", _DIGEST, _H - 3 * HOUR_SECONDS, derived=derived_first)
    new = _seen("b", _DIGEST, _H)

    assert _kinds(old, new)[0][0] == "handover"


def test_a_derived_id_heard_before_the_old_one_stopped_is_no_migration() -> None:
    old = KeySeen("a", _DIGEST, _H - 7200.0, _H + 100.0, (_H - 7200,))
    new = KeySeen("b", _DIGEST, _H + 50.0, _H + 60.0, (_H + 3600,), derived=True)

    assert _kinds(old, new)[0][0] == "handover"


def test_a_clone_with_one_of_ours_involves_the_fleet() -> None:
    found = _kinds(_seen("a"), _seen("b"), fleet=(FleetKey("a"),))

    assert found == [("clone", "critical", ("a", "b"), True)]
    assert scan_keys((_seen("a"), _seen("b")), (FleetKey("a"),), start=_START).fleet_critical


def test_our_database_key_on_another_id_is_critical() -> None:
    found = _kinds(_seen("b"), fleet=(FleetKey("a", _DIGEST),))

    assert found == [("our-key-elsewhere", "critical", ("a", "b"), True)]


def test_our_key_on_its_derived_id_after_our_node_went_quiet_is_a_migration() -> None:
    old = _seen("a", _DIGEST, _H - 3 * HOUR_SECONDS)
    new = _seen("b", _DIGEST, _H, derived=True)

    assert _kinds(old, new, fleet=(FleetKey("a", _DIGEST),)) == [
        ("migration", "info", ("a", "b"), True)
    ]


def test_our_key_on_its_derived_id_while_our_node_is_still_heard_is_critical() -> None:
    old = _seen("a", _DIGEST, _H)
    new = _seen("b", _DIGEST, _H, derived=True)

    assert _kinds(old, new, fleet=(FleetKey("a", _DIGEST),)) == [
        ("our-key-elsewhere", "critical", ("a", "b"), True)
    ]


@pytest.mark.parametrize(("derived", "severity"), [(True, "critical"), (False, "warning")])
def test_our_id_with_another_key(derived: bool, severity: str) -> None:
    found = _kinds(_seen("a", "sha256:" + "2" * 16), fleet=(FleetKey("a", _DIGEST, derived),))

    assert found == [("our-id-other-key", severity, ("a",), True)]


def test_a_weak_key_has_the_audits_severity_and_checks() -> None:
    audit = KeyAudit(Severity.WARNING, ("monotonic",))
    entry = KeySeen("a", _DIGEST, NOW, NOW, (_H,), audit=audit)

    scan = scan_keys((entry,), (FleetKey("a"),), start=_START)

    assert scan.findings == (
        KeyFinding(FindingKind.WEAK_KEY, Severity.WARNING, _DIGEST, ("a",), True, ("monotonic",)),
    )
    assert not scan.fleet_critical


@pytest.mark.parametrize(
    ("old_derived", "new_derived", "severity"),
    [(False, False, "warning"), (True, False, "critical"), (True, True, "warning")],
)
def test_a_changed_key(old_derived: bool, new_derived: bool, severity: str) -> None:
    old = _seen("a", _DIGEST, _H - 3 * HOUR_SECONDS, derived=old_derived)
    new = _seen("a", "sha256:" + "3" * 16, _H, derived=new_derived)

    assert _kinds(old, new) == [("key-changed", severity, ("a",), False)]


def test_a_changed_key_of_ours_with_a_database_key_is_left_to_the_database_check() -> None:
    old = _seen("a", _DIGEST, _H - 3 * HOUR_SECONDS)
    new = _seen("a", "sha256:" + "3" * 16, _H)

    assert _kinds(old, new, fleet=(FleetKey("a", _DIGEST),)) == [
        ("our-id-other-key", "warning", ("a",), True)
    ]
    assert _kinds(old, new, fleet=(FleetKey("a"),)) == [("key-changed", "warning", ("a",), True)]


def test_sightings_and_hours_before_the_window_are_left_out() -> None:
    old = _seen("a", _DIGEST, _H - 40 * 24 * HOUR_SECONDS)
    straddling = _seen("b", _DIGEST, _H - 40 * 24 * HOUR_SECONDS, _H)
    alternating = _seen("c", _DIGEST, _H - 2 * HOUR_SECONDS)

    scan = scan_keys((old, straddling, alternating), (), start=NOW - 10 * 24 * 3600)

    assert [entry.node for entry in scan.seen] == ["b", "c"]
    assert scan.seen[0].hours == (_H,)
    assert scan.seen[0].first == NOW - 10 * 24 * 3600
    assert scan.findings[0].kind is FindingKind.HANDOVER


def test_findings_are_sorted_most_serious_first_and_counted() -> None:
    audit = KeyAudit(Severity.WARNING, ("monotonic",))
    seen = (
        _seen("a", _DIGEST, _H),
        _seen("b", _DIGEST, _H),
        KeySeen("c", "sha256:" + "4" * 16, NOW, NOW, (_H,), audit=audit),
        _seen("d", "sha256:" + "5" * 16, derived=True),
    )

    scan = scan_keys(seen, (FleetKey("a"),), start=_START)

    assert [f.kind for f in scan.findings] == [FindingKind.CLONE, FindingKind.WEAK_KEY]
    assert (scan.nodes, scan.fleet_seen, scan.derived) == (4, ("a",), ("d",))


def test_our_key_on_its_derived_id_heard_the_moment_ours_stopped_is_critical() -> None:
    old = KeySeen("a", _DIGEST, _H - 7200.0, _H + 50.0, (_H - 7200,))
    new = KeySeen("b", _DIGEST, _H + 50.0, _H + 60.0, (_H,), derived=True)

    assert _kinds(old, new, fleet=(FleetKey("a", _DIGEST),))[0][:2] == (
        "our-key-elsewhere",
        "critical",
    )


def test_a_critical_finding_about_outsiders_only_is_no_fleet_failure() -> None:
    scan = scan_keys((_seen("a"), _seen("b")), (FleetKey("c"),), start=_START)

    assert scan.findings[0].severity is Severity.CRITICAL
    assert not scan.fleet_critical


def test_severity_ranks_before_the_kind() -> None:
    audit = KeyAudit(Severity.CRITICAL, ("blocklist",))
    handover = (_seen("a", _DIGEST, _H - 3 * HOUR_SECONDS), _seen("b", _DIGEST, _H))
    weak = KeySeen("c", "sha256:" + "6" * 16, NOW, NOW, (_H,), audit=audit)

    scan = scan_keys((*handover, weak), (), start=_START)

    assert [f.kind for f in scan.findings] == [FindingKind.WEAK_KEY, FindingKind.HANDOVER]


def _at(node: str, first: float, last: float, *, derived: bool = False) -> KeySeen:
    hours = tuple(sorted({floor_hour(first), floor_hour(last)}))
    return KeySeen(node, _DIGEST, first, last, hours, derived=derived)


def test_a_hand_over_inside_one_hour_is_no_clone() -> None:
    old = _at("a", _H - 7200 + 60, _H + 5 * 60)
    new = _at("b", _H + 40 * 60, _H + 50 * 60, derived=True)

    scan = scan_keys((old, new), (FleetKey("a"),), start=_START)

    assert [(f.kind, f.severity) for f in scan.findings] == [(FindingKind.MIGRATION, Severity.INFO)]
    assert not scan.fleet_critical
    assert _kinds(old, _at("b", _H + 40 * 60, _H + 50 * 60))[0][0] == "handover"


def test_overlapping_sightings_in_a_common_hour_stay_a_clone() -> None:
    a = _at("a", _H + 60, _H + 50 * 60)
    b = _at("b", _H + 40 * 60, _H + 55 * 60, derived=True)

    assert _kinds(a, b)[0][:2] == ("clone", "critical")


def test_alternation_follows_the_first_sighting_order_within_an_hour() -> None:
    a = KeySeen("a", _DIGEST, _H + 60, _H + 120, (_H - HOUR_SECONDS, _H))
    b = KeySeen("b", _DIGEST, _H + 600, _H + 900, (_H, _H + HOUR_SECONDS))

    assert _kinds(a, b)[0][0] == "handover"


def test_an_old_key_heard_before_our_database_key_is_a_rekey_not_a_finding() -> None:
    old = _at("a", _H - 5 * HOUR_SECONDS, _H - 4 * HOUR_SECONDS)
    old = KeySeen("a", "sha256:" + "7" * 16, old.first, old.last, old.hours)
    current = _at("a", _H - 3 * HOUR_SECONDS, _H)
    late = KeySeen(
        "a",
        "sha256:" + "8" * 16,
        _H - 2 * HOUR_SECONDS,
        _H - 2 * HOUR_SECONDS + 60,
        (_H - 2 * HOUR_SECONDS,),
    )

    fleet = (FleetKey("a", _DIGEST),)

    assert _kinds(old, current, fleet=fleet) == []
    assert _kinds(old, current, late, fleet=fleet) == [
        ("our-id-other-key", "warning", ("a",), True)
    ]


def test_sightings_touching_at_one_instant_are_at_the_same_time() -> None:
    a = _at("a", _H + 60, _H + 600)
    b = _at("b", _H + 600, _H + 900)

    assert _kinds(a, b)[0][:2] == ("clone", "critical")
    assert _kinds(_at("a", _H + 600, _H + 900), _at("b", _H + 60, _H + 600))[0][0] == "clone"


def test_an_other_key_heard_until_the_database_key_appears_is_still_reported() -> None:
    current = _at("a", _H - 3 * HOUR_SECONDS, _H)
    other = KeySeen(
        "a", "sha256:" + "7" * 16, current.first - 600, current.first, current.hours[:1]
    )

    assert _kinds(other, current, fleet=(FleetKey("a", _DIGEST),)) == [
        ("our-id-other-key", "warning", ("a",), True)
    ]
