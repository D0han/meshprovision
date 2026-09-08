"""Tests for meshprovision.provisioning.plan_render.

Exercises describe_plan/plan_to_json_dict directly, independent of the
CLI -- mirroring tests/unit/test_admin_custody.py's pattern for the
sibling extraction out of cli/admin.py.
"""

from __future__ import annotations

import pytest

from meshprovision.config.template import load_template_text
from meshprovision.db.nodes import NodeRecord
from meshprovision.provisioning import detect
from meshprovision.provisioning.plan import ChangePlan, PlanInputs, build_plan
from meshprovision.provisioning.plan_render import (
    PlanLineKind,
    describe_plan,
    plan_to_json_dict,
)
from meshprovision.provisioning.repair import Drift, DriftKind
from tests.unit.conftest import make_security

pytestmark = pytest.mark.unit


@pytest.fixture
def template():
    return load_template_text("version: 1\n")


def _empty_plan(make_live, template, keypair) -> ChangePlan:
    live = make_live(template, security=make_security(keypair=keypair))
    record = NodeRecord(node_id="deadbe01", short_name=live.short_name, long_name=live.long_name)
    inputs = PlanInputs(
        live=live,
        template=template,
        db_entry=record,
        state=detect.NodeState.PROVISIONED,
        admin_keys=(),
        db_public_key=None,
    )
    return build_plan(inputs)


def test_describe_plan_no_changes_reports_no_changes_needed(make_live, template, keypair) -> None:
    plan = _empty_plan(make_live, template, keypair)
    assert plan.is_empty

    lines = describe_plan(plan)

    assert any(line.text == "No changes needed." for line in lines)
    assert all(line.kind is not PlanLineKind.CHANGE for line in lines)


def test_describe_plan_with_changes_uses_change_kind_for_change_lines(make_live, template) -> None:
    template2 = template.model_copy(
        update={"device": template.device.model_copy(update={"role": "ROUTER"})}
    )
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live, template=template2, db_entry=None, state=detect.NodeState.FACTORY
    )
    plan = build_plan(inputs)
    assert not plan.is_empty

    lines = describe_plan(plan)

    change_lines = [line for line in lines if line.kind is PlanLineKind.CHANGE]
    assert change_lines
    assert set(change_lines) <= {line for line in lines if line.text in plan.describe()}


def test_describe_plan_drifts_render_as_info_lines_before_the_plan(
    make_live, template, keypair
) -> None:
    plan = _empty_plan(make_live, template, keypair)
    drift = Drift(kind=DriftKind.NAME, field="short_name", recorded="MT00", observed="MT01")

    lines = describe_plan(plan, drifts=(drift,))

    assert lines[0].kind is PlanLineKind.INFO
    assert lines[0].text == "Drift detected:"
    assert any(drift.describe() in line.text for line in lines)


def test_describe_plan_reboot_warning_uses_warning_kind(make_live, template) -> None:
    template2 = template.model_copy(
        update={"lora": template.lora.model_copy(update={"region": "US"})}
    )
    live = make_live(template, security=make_security(empty=True))
    inputs = PlanInputs(
        live=live, template=template2, db_entry=None, state=detect.NodeState.FACTORY
    )
    plan = build_plan(inputs)
    assert plan.reboots_device

    lines = describe_plan(plan)

    reboot_lines = [
        line
        for line in lines
        if line.kind is PlanLineKind.WARNING
        and line.text == "Applying this plan reboots the device."
    ]
    assert len(reboot_lines) == 1


def test_plan_to_json_dict_includes_detection_drifts_and_plan(make_live, template, keypair) -> None:
    plan = _empty_plan(make_live, template, keypair)
    drift = Drift(kind=DriftKind.NAME, field="short_name", recorded="MT00", observed="MT01")

    document = plan_to_json_dict(plan, drifts=(drift,))

    assert document["detection"] == {
        "node_id": plan.node_id.hex,
        "state": plan.state.value,
        "is_new": plan.is_new,
    }
    assert document["drifts"] == [
        {"kind": "name", "field": "short_name", "recorded": "MT00", "observed": "MT01"}
    ]
    assert document["plan"] == plan.to_json_dict()
