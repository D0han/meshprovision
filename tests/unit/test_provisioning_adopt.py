"""Tests for meshprovision.provisioning.adopt."""

from __future__ import annotations

import base64
import re
from datetime import UTC, datetime

import pytest

from meshprovision.config.template import load_template_text
from meshprovision.crypto.keys import encode_key
from meshprovision.db.nodes import NodeRecord
from meshprovision.db.schema import ManagementMode
from meshprovision.provisioning.adopt import (
    adopted_record,
    build_adoption_report,
    capture_ble_pin,
    check_name_pattern_fit,
    classify_live_admin_keys,
)
from tests.unit.conftest import make_security

pytestmark = pytest.mark.unit

_BASE64_KEY_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])")


@pytest.fixture
def template():
    return load_template_text("version: 1\n")


# ---------------------------------------------------------------------------
# classify_live_admin_keys
# ---------------------------------------------------------------------------


def test_classify_live_admin_keys_unregistered(make_live, template, keypair_factory) -> None:
    key = keypair_factory().public
    live = make_live(template, security=make_security(admin_keys=(key,)))

    result = classify_live_admin_keys(live, {})

    assert len(result) == 1
    assert result[0].material == key
    assert result[0].refs == ()
    assert result[0].preferred_ref is None


def test_classify_live_admin_keys_single_match(make_live, template, keypair_factory) -> None:
    key = keypair_factory().public
    live = make_live(template, security=make_security(admin_keys=(key,)))

    result = classify_live_admin_keys(live, {"ADMIN1_pub": key})

    assert result[0].refs == ("ADMIN1_pub",)
    assert result[0].preferred_ref == "ADMIN1_pub"


def test_classify_live_admin_keys_prefers_human_label_over_node_id_ref(
    make_live, template, keypair_factory
) -> None:
    key = keypair_factory().public
    public_keys = {"deadbe01_pub": key, "ADMIN1_pub": key}
    live = make_live(template, security=make_security(admin_keys=(key,)))

    first = classify_live_admin_keys(live, public_keys)
    second = classify_live_admin_keys(live, public_keys)

    assert first == second
    assert first[0].refs == ("ADMIN1_pub", "deadbe01_pub")
    assert first[0].preferred_ref == "ADMIN1_pub"


def test_live_admin_key_repr_never_exposes_material(make_live, template, keypair_factory) -> None:
    key = keypair_factory().public
    live = make_live(template, security=make_security(admin_keys=(key,)))

    result = classify_live_admin_keys(live, {})

    rendered = repr(result[0])
    assert result[0].fingerprint in rendered
    assert base64.b64encode(key).decode("ascii") not in rendered


def test_classify_live_admin_keys_preserves_device_order(
    make_live, template, keypair_factory
) -> None:
    key_a = keypair_factory().public
    key_b = keypair_factory().public
    public_keys = {"A_pub": key_a}
    live = make_live(template, security=make_security(admin_keys=(key_b, key_a)))

    result = classify_live_admin_keys(live, public_keys)

    assert result[0].material == key_b
    assert result[0].refs == ()
    assert result[1].material == key_a
    assert result[1].refs == ("A_pub",)


# ---------------------------------------------------------------------------
# check_name_pattern_fit
# ---------------------------------------------------------------------------


def test_check_name_pattern_fit_both_fit(template) -> None:
    findings = check_name_pattern_fit(template, short_name="MT00", long_name="Meshtastic MT00")

    assert findings == ()


def test_check_name_pattern_fit_neither_fits(template) -> None:
    findings = check_name_pattern_fit(template, short_name="ABCD", long_name="Custom Name")

    assert len(findings) == 2
    assert "short_name" in findings[0]
    assert "long_name" in findings[1]


def test_check_name_pattern_fit_mixed(template) -> None:
    findings = check_name_pattern_fit(template, short_name="MT00", long_name="Custom Name")

    assert len(findings) == 1
    assert "long_name" in findings[0]


# ---------------------------------------------------------------------------
# capture_ble_pin
# ---------------------------------------------------------------------------


def test_capture_ble_pin_fixed_pin_zero_pads(make_live, template) -> None:
    live = make_live(
        template, section_overrides={"bluetooth": {"mode": "FIXED_PIN", "fixed_pin": 42}}
    )

    assert capture_ble_pin(live) == "000042"


def test_capture_ble_pin_random_pin_not_captured(make_live, template) -> None:
    live = make_live(
        template, section_overrides={"bluetooth": {"mode": "RANDOM_PIN", "fixed_pin": 42}}
    )

    assert capture_ble_pin(live) is None


def test_capture_ble_pin_missing_mode_not_captured(make_live, template) -> None:
    live = make_live(template)

    assert capture_ble_pin(live) is None


def test_capture_ble_pin_malformed_value_does_not_raise(make_live, template) -> None:
    live = make_live(
        template,
        section_overrides={"bluetooth": {"mode": "FIXED_PIN", "fixed_pin": "not-a-number"}},
    )

    assert capture_ble_pin(live) is None


def test_capture_ble_pin_out_of_range_not_captured(make_live, template) -> None:
    live = make_live(
        template, section_overrides={"bluetooth": {"mode": "FIXED_PIN", "fixed_pin": 0}}
    )

    assert capture_ble_pin(live) is None


# ---------------------------------------------------------------------------
# build_adoption_report
# ---------------------------------------------------------------------------


def test_build_adoption_report_region_role_map_cleanly(make_live, template) -> None:
    live = make_live(template)

    report = build_adoption_report(
        live, existing=None, public_keys={}, template=template, known_bad=frozenset()
    )

    assert report.region == "EU_868"
    assert report.role == "CLIENT"
    assert report.warnings == ()


def test_build_adoption_report_region_role_unmappable_no_fallback(make_live, template) -> None:
    live = make_live(
        template,
        section_overrides={"lora": {"region": "MARS"}, "device": {"role": "SUPERVISOR"}},
    )

    report = build_adoption_report(
        live, existing=None, public_keys={}, template=template, known_bad=frozenset()
    )

    assert report.region == ""
    assert report.role == ""
    assert any("MARS" in w for w in report.warnings)
    assert any("SUPERVISOR" in w for w in report.warnings)


def test_build_adoption_report_region_role_absent(make_live, template) -> None:
    live = make_live(template, section_overrides={"lora": {"region": ""}, "device": {"role": ""}})

    report = build_adoption_report(
        live, existing=None, public_keys={}, template=template, known_bad=frozenset()
    )

    assert report.region == ""
    assert report.role == ""
    assert report.warnings == ()


def test_build_adoption_report_firmware_vulnerable(make_live, template) -> None:
    live = make_live(template, firmware_version="2.6.0")

    report = build_adoption_report(
        live, existing=None, public_keys={}, template=template, known_bad=frozenset()
    )

    assert report.firmware_vulnerable is True


def test_build_adoption_report_firmware_not_vulnerable(make_live, template) -> None:
    live = make_live(template, firmware_version="2.7.11")

    report = build_adoption_report(
        live, existing=None, public_keys={}, template=template, known_bad=frozenset()
    )

    assert report.firmware_vulnerable is False


def test_build_adoption_report_unparseable_firmware_warns_not_silently_safe(
    make_live, template
) -> None:
    live = make_live(template, firmware_version="not-a-version")

    report = build_adoption_report(
        live, existing=None, public_keys={}, template=template, known_bad=frozenset()
    )

    assert report.firmware_vulnerable is False
    assert any(
        "could not be parsed" in w and "CVE-2025-52464" in w and "unknown" in w
        for w in report.warnings
    )


def test_build_adoption_report_missing_firmware_warns_not_silently_safe(
    make_live, template
) -> None:
    live = make_live(template, firmware_version="")

    report = build_adoption_report(
        live, existing=None, public_keys={}, template=template, known_bad=frozenset()
    )

    assert report.firmware_vulnerable is False
    assert any(
        "no firmware version reported" in w and "CVE-2025-52464" in w and "unknown" in w
        for w in report.warnings
    )


def test_build_adoption_report_is_managed_reflected(make_live, template) -> None:
    live = make_live(template, security=make_security(is_managed=True))

    report = build_adoption_report(
        live, existing=None, public_keys={}, template=template, known_bad=frozenset()
    )

    assert report.is_managed is True


def test_build_adoption_report_warns_on_weak_live_admin_key(make_live, template) -> None:
    """Regression test: mesh adopt must actually audit live admin keys.

    known_bad was previously loaded by the caller and threaded all the
    way into build_adoption_report, then explicitly discarded
    (`del known_bad`) -- an inventory command that reports firmware
    vulnerability but says nothing about a structurally broken admin key
    is an incomplete "should I trust this device" picture.
    """
    live = make_live(template, security=make_security(admin_keys=(bytes(32),)))

    report = build_adoption_report(
        live, existing=None, public_keys={}, template=template, known_bad=frozenset()
    )

    assert any("admin key" in w and "weak-key audit" in w for w in report.warnings)


def test_build_adoption_report_healthy_live_admin_key_no_warning(
    make_live, template, keypair_factory
) -> None:
    key = keypair_factory().public
    live = make_live(template, security=make_security(admin_keys=(key,)))

    report = build_adoption_report(
        live, existing=None, public_keys={}, template=template, known_bad=frozenset()
    )

    assert not any("weak-key audit" in w for w in report.warnings)


def test_build_adoption_report_warns_on_blocklisted_live_admin_key(
    make_live, template, keypair_factory
) -> None:
    key = keypair_factory().public
    live = make_live(template, security=make_security(admin_keys=(key,)))

    report = build_adoption_report(
        live, existing=None, public_keys={}, template=template, known_bad=frozenset({key})
    )

    assert any("admin key" in w and "weak-key audit" in w for w in report.warnings)


# ---------------------------------------------------------------------------
# adopted_record
# ---------------------------------------------------------------------------


def test_adopted_record_fresh_adopt(make_live, template, keypair_factory) -> None:
    key = keypair_factory().public
    live = make_live(template, security=make_security(admin_keys=(key,)))
    report = build_adoption_report(
        live,
        existing=None,
        public_keys={"ADMIN1_pub": key},
        template=template,
        known_bad=frozenset(),
    )
    now = datetime(2026, 1, 1, tzinfo=UTC)

    record = adopted_record(report, now=now)

    assert record.management is ManagementMode.OBSERVED
    assert record.authorized_admin_keys == ("ADMIN1_pub",)
    assert record.first_added_ts == now
    assert record.last_updated_ts == now


def test_adopted_record_deduplicates_a_key_reported_twice_by_the_device(
    make_live, template, keypair_factory
) -> None:
    """Regression test: a duplicate live report must not persist a duplicate ref.

    classify_live_admin_keys() deliberately never dedupes (a device
    reporting the same key twice yields two LiveAdminKey entries), but
    the persisted authorized_admin_keys cell must not assert the same
    ref twice.
    """
    key = keypair_factory().public
    live = make_live(template, security=make_security(admin_keys=(key, key)))
    report = build_adoption_report(
        live,
        existing=None,
        public_keys={"ADMIN1_pub": key},
        template=template,
        known_bad=frozenset(),
    )
    assert len(report.admin_keys) == 2

    record = adopted_record(report, now=datetime(2026, 1, 1, tzinfo=UTC))

    assert record.authorized_admin_keys == ("ADMIN1_pub",)


def test_adopted_record_persists_unregistered_admin_keys_only(
    make_live, template, keypair_factory
) -> None:
    """A registered key never contributes to unregistered_admin_keys."""
    registered_key = keypair_factory().public
    unregistered_key = keypair_factory().public
    live = make_live(
        template, security=make_security(admin_keys=(registered_key, unregistered_key))
    )
    report = build_adoption_report(
        live,
        existing=None,
        public_keys={"ADMIN1_pub": registered_key},
        template=template,
        known_bad=frozenset(),
    )

    record = adopted_record(report, now=datetime(2026, 1, 1, tzinfo=UTC))

    assert record.authorized_admin_keys == ("ADMIN1_pub",)
    assert record.unregistered_admin_key_materials() == (unregistered_key,)


def test_adopted_record_deduplicates_unregistered_key_reported_twice(
    make_live, template, keypair_factory
) -> None:
    key = keypair_factory().public
    live = make_live(template, security=make_security(admin_keys=(key, key)))
    report = build_adoption_report(
        live, existing=None, public_keys={}, template=template, known_bad=frozenset()
    )
    assert len(report.admin_keys) == 2

    record = adopted_record(report, now=datetime(2026, 1, 1, tzinfo=UTC))

    assert record.unregistered_admin_key_materials() == (key,)


def test_adopted_record_skips_a_malformed_length_unregistered_key(
    make_live, template, keypair_factory
) -> None:
    """A malformed-length admin key degrades (is skipped), never crashes persistence.

    detect.py applies no length check on security.admin_key, so a
    non-32-byte value is reachable in practice; the report's own
    warnings already flag it separately (build_adoption_report's
    weak-key-audit loop).
    """
    good_key = keypair_factory().public
    live = make_live(template, security=make_security(admin_keys=(good_key, b"\x01\x02\x03")))
    report = build_adoption_report(
        live, existing=None, public_keys={}, template=template, known_bad=frozenset()
    )
    assert len(report.admin_keys) == 2

    record = adopted_record(report, now=datetime(2026, 1, 1, tzinfo=UTC))

    assert record.unregistered_admin_key_materials() == (good_key,)


def test_adopted_record_keeps_a_well_formed_key_reported_after_a_malformed_one(
    make_live, template, keypair_factory
) -> None:
    """The malformed-key skip must continue the loop, never abandon it.

    With the malformed key reported FIRST, a `break` regression in
    adopted_record's unregistered-key loop would silently drop every
    well-formed key the device reports after it. The warning assertion
    pins the coupling that makes the silent skip acceptable at all:
    build_adoption_report audits (and warns about) the very same key
    adopted_record then drops, so the operator is never left with a key
    that vanished without a word.
    """
    good_key = keypair_factory().public
    live = make_live(template, security=make_security(admin_keys=(b"\x01\x02\x03", good_key)))
    report = build_adoption_report(
        live, existing=None, public_keys={}, template=template, known_bad=frozenset()
    )
    assert len(report.admin_keys) == 2

    record = adopted_record(report, now=datetime(2026, 1, 1, tzinfo=UTC))

    assert record.unregistered_admin_key_materials() == (good_key,)
    assert any("malformed key material" in w for w in report.warnings)


def test_adopted_record_reuse_replaces_stale_unregistered_keys(
    make_live, template, keypair_factory
) -> None:
    """Full-replace, matching authorized_admin_keys: drops a key no longer live."""
    live_key = keypair_factory().public
    stale_key = keypair_factory().public
    live = make_live(template, security=make_security(admin_keys=(live_key,)))
    existing = NodeRecord(node_id="deadbe01", unregistered_admin_keys=(encode_key(stale_key),))
    report = build_adoption_report(
        live, existing=existing, public_keys={}, template=template, known_bad=frozenset()
    )

    record = adopted_record(report, now=datetime(2026, 1, 1, tzinfo=UTC))

    assert record.unregistered_admin_key_materials() == (live_key,)
    assert stale_key not in record.unregistered_admin_key_materials()


def test_adopted_record_reuse_drops_stale_ref_and_preserves_history(
    make_live, template, keypair_factory
) -> None:
    live_key = keypair_factory().public
    live = make_live(template, security=make_security(admin_keys=(live_key,)))
    existing = NodeRecord(
        node_id="deadbe01",
        authorized_admin_keys=("ADMIN1_pub", "STALE_pub"),
        notes="do not lose me",
        first_added_ts=datetime(2020, 1, 1, tzinfo=UTC),
    )
    report = build_adoption_report(
        live,
        existing=existing,
        public_keys={"ADMIN1_pub": live_key},
        template=template,
        known_bad=frozenset(),
    )
    now = datetime(2026, 1, 1, tzinfo=UTC)

    record = adopted_record(report, now=now)

    assert record.authorized_admin_keys == ("ADMIN1_pub",)
    assert "STALE_pub" not in record.authorized_admin_keys
    assert record.notes == "do not lose me"
    assert record.first_added_ts == datetime(2020, 1, 1, tzinfo=UTC)
    assert record.last_updated_ts == now


def test_adopted_record_leaves_role_region_untouched_when_unmapped(
    make_live, template, keypair_factory
) -> None:
    live = make_live(
        template, section_overrides={"lora": {"region": "MARS"}, "device": {"role": "SUPERVISOR"}}
    )
    existing = NodeRecord(node_id="deadbe01", role="ROUTER", region="US")
    report = build_adoption_report(
        live, existing=existing, public_keys={}, template=template, known_bad=frozenset()
    )

    record = adopted_record(report, now=datetime(2026, 1, 1, tzinfo=UTC))

    assert record.role == "ROUTER"
    assert record.region == "US"


def test_adopted_record_first_time_adopt_with_unmapped_role_region_stays_blank(
    make_live, template
) -> None:
    """Regression test: a first-time adopt must not fabricate CLIENT/EU_868.

    With no existing row, adopted_record() starts from a fresh
    NodeRecord(), whose class defaults are role="CLIENT"/region="EU_868".
    When the live role/region is unrecognized (report.role/region == ""),
    those defaults must not be left in place as if they were observed --
    the record must end up genuinely blank, matching AdoptionReport's own
    "never guess" contract.
    """
    live = make_live(
        template, section_overrides={"lora": {"region": "MARS"}, "device": {"role": "SUPERVISOR"}}
    )
    report = build_adoption_report(
        live, existing=None, public_keys={}, template=template, known_bad=frozenset()
    )
    assert report.role == ""
    assert report.region == ""

    record = adopted_record(report, now=datetime(2026, 1, 1, tzinfo=UTC))

    assert record.role == ""
    assert record.region == ""


def test_adopted_record_captures_ble_pin(make_live, template) -> None:
    live = make_live(
        template, section_overrides={"bluetooth": {"mode": "FIXED_PIN", "fixed_pin": 42}}
    )
    report = build_adoption_report(
        live, existing=None, public_keys={}, template=template, known_bad=frozenset()
    )

    record = adopted_record(report, now=datetime(2026, 1, 1, tzinfo=UTC))

    assert record.ble_pin is not None
    assert record.ble_pin.get_secret_value() == "000042"


# ---------------------------------------------------------------------------
# AdoptionReport.to_json_dict / describe -- secret hygiene
# ---------------------------------------------------------------------------


def test_to_json_dict_default_never_contains_material(make_live, template, keypair_factory) -> None:
    key = keypair_factory().public
    live = make_live(template, security=make_security(admin_keys=(key,)))
    report = build_adoption_report(
        live, existing=None, public_keys={}, template=template, known_bad=frozenset()
    )

    payload = report.to_json_dict()

    assert all("material" not in entry for entry in payload["admin_keys"])


def test_to_json_dict_show_key_material_only_for_unregistered(
    make_live, template, keypair_factory
) -> None:
    registered = keypair_factory().public
    unregistered = keypair_factory().public
    live = make_live(template, security=make_security(admin_keys=(registered, unregistered)))
    report = build_adoption_report(
        live,
        existing=None,
        public_keys={"ADMIN1_pub": registered},
        template=template,
        known_bad=frozenset(),
    )

    payload = report.to_json_dict(show_key_material=True)

    entries = {tuple(entry["refs"]): entry for entry in payload["admin_keys"]}
    assert "material" not in entries[("ADMIN1_pub",)]
    assert "material" in entries[()]
    decoded = base64.b64decode(entries[()]["material"])
    assert decoded == unregistered


def test_to_json_dict_malformed_admin_key_reports_material_error_not_crash(
    make_live, template
) -> None:
    """Regression test: a malformed-length admin key must degrade, never crash.

    detect.py applies no length check when reading security.admin_key
    off the device, so a malformed key is reachable in practice.
    encode_key() validates length and raises on mismatch --
    to_json_dict(show_key_material=True) must catch that per key rather
    than propagating and aborting the whole report, and must never
    silently emit a wrong/truncated encoding either.
    """
    live = make_live(template, security=make_security(admin_keys=(b"\x01\x02\x03",)))
    report = build_adoption_report(
        live, existing=None, public_keys={}, template=template, known_bad=frozenset()
    )

    payload = report.to_json_dict(show_key_material=True)

    entry = payload["admin_keys"][0]
    assert "material" not in entry
    assert entry["material_error"] == "malformed key material"


def test_ble_pin_never_appears_in_json_or_describe(make_live, template) -> None:
    live = make_live(
        template, section_overrides={"bluetooth": {"mode": "FIXED_PIN", "fixed_pin": 123456}}
    )
    report = build_adoption_report(
        live, existing=None, public_keys={}, template=template, known_bad=frozenset()
    )
    assert report.ble_pin == "123456"

    payload = report.to_json_dict()
    assert payload["ble_pin_captured"] is True
    assert isinstance(payload["ble_pin_captured"], bool)
    assert "123456" not in str(payload)

    payload_with_material = report.to_json_dict(show_key_material=True)
    assert "123456" not in str(payload_with_material)

    lines = report.describe()
    assert "123456" not in "\n".join(lines)


def test_describe_never_contains_base64_key_material(make_live, template, keypair_factory) -> None:
    key = keypair_factory().public
    live = make_live(template, security=make_security(admin_keys=(key,)))
    report = build_adoption_report(
        live, existing=None, public_keys={}, template=template, known_bad=frozenset()
    )

    text = "\n".join(report.describe())

    assert not _BASE64_KEY_RE.search(text)


def test_describe_covers_existing_registered_vulnerable_and_managed(
    make_live, template, keypair_factory
) -> None:
    key = keypair_factory().public
    live = make_live(
        template,
        firmware_version="2.6.0",
        security=make_security(admin_keys=(key,), is_managed=True),
    )
    existing = NodeRecord(node_id="deadbe01")

    report = build_adoption_report(
        live,
        existing=existing,
        public_keys={"ADMIN1_pub": key},
        template=template,
        known_bad=frozenset(),
    )

    lines = report.describe()
    text = "\n".join(lines)

    assert any("already in database" in line for line in lines)
    assert any("registered as ADMIN1_pub" in line for line in lines)
    assert any("CVE-2025-52464" in line for line in lines)
    assert any("admin key" in line and "authorized" in line for line in lines)
    assert not _BASE64_KEY_RE.search(text)
