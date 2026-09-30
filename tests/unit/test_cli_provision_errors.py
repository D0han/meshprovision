"""Unit tests for meshprovision.cli.provision's admin-key-rotation error finalizer."""

from __future__ import annotations

import pytest

from meshprovision.cli.provision import _finalize_admin_key_rotation_error
from meshprovision.config.template import load_template_text
from meshprovision.errors import AdminKeyRotationRefusedError
from tests.unit.conftest import live_config_from_template, make_security

pytestmark = pytest.mark.unit


def test_finalize_capture_reason_hint_names_cve_and_ref_flag(keypair) -> None:
    """A ``"capture"`` refusal's hint points at ``--ref`` and the CVE.

    Not the old ``"adopt"`` wording, which is false when nothing was ever
    recorded.
    """
    template = load_template_text("version: 1\n")
    live = live_config_from_template(template, security=make_security(keypair=keypair))
    exc = AdminKeyRotationRefusedError(
        "deadbe01 has no recorded key, and the key it reports is already registered as: "
        "ADMIN1_pub.",
        reason="capture",
        admin_refs=("ADMIN1_pub",),
    )

    finalized = _finalize_admin_key_rotation_error(exc, live)

    assert finalized.hint is not None
    assert "sha256:" in finalized.hint
    assert "--ref" in finalized.hint
    assert "CVE-2025-52464" in finalized.hint
    assert "than the one recorded" not in finalized.hint
    assert finalized.reported_fingerprint is not None
    assert "sha256:" in finalized.reported_fingerprint
