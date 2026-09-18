"""Tests for meshprovision.crypto.redact."""

from __future__ import annotations

import io
import logging
import re

import pytest
import structlog

from meshprovision.cli.common import configure_logging
from meshprovision.crypto.redact import (
    REDACTED,
    SAFE_KEY_NAMES,
    SENSITIVE_KEY_NAMES,
    SENSITIVE_KEY_SUFFIXES,
    SecretBytes,
    fingerprint,
    redact,
    redact_processor,
    scrub_text,
)
from meshprovision.nodeid import NodeId

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _restore_logging() -> None:
    """Ensure ``configure_logging`` calls in this module never leak into other tests."""
    yield
    configure_logging("WARNING", stream=io.StringIO())


class TestSecretBytes:
    def test_repr_str_format_never_leak(self) -> None:
        secret = SecretBytes(b"\x01" * 32)
        assert "01" * 32 not in repr(secret)
        assert "01" * 32 not in str(secret)
        assert repr(secret).startswith("<redacted:sha256:")
        assert str(secret) == repr(secret)

    def test_format_spec_leak_closed(self) -> None:
        secret = SecretBytes(b"\x02" * 32)
        formatted = f"{secret:>60}"
        assert formatted == repr(secret)
        assert "02" * 32 not in formatted

    def test_len(self) -> None:
        assert len(SecretBytes(b"x" * 32)) == 32

    def test_equality_constant_time_and_not_implemented(self) -> None:
        a = SecretBytes(b"a" * 32)
        b = SecretBytes(b"a" * 32)
        c = SecretBytes(b"b" * 32)
        assert a == b
        assert a != c
        assert a.__eq__(object()) is NotImplemented

    def test_hash_usable_in_set(self) -> None:
        a = SecretBytes(b"a" * 32)
        b = SecretBytes(b"a" * 32)
        assert len({a, b}) == 1

    def test_reveal_returns_exact_bytes(self) -> None:
        raw = b"\x00\x01\x02" * 10 + b"\x03\x04"
        secret = SecretBytes(raw)
        assert secret.reveal() == raw

    def test_constructor_copies_bytearray(self) -> None:
        mutable = bytearray(b"\x00" * 32)
        secret = SecretBytes(mutable)
        mutable[0] = 0xFF
        assert secret.reveal() == b"\x00" * 32

    def test_constructor_type_error_on_str(self) -> None:
        with pytest.raises(TypeError):
            SecretBytes("not bytes")  # type: ignore[arg-type]


class TestFingerprintRedact:
    def test_fingerprint_stable(self) -> None:
        assert fingerprint(b"x" * 32) == fingerprint(b"x" * 32)

    def test_fingerprint_chars_clamped(self) -> None:
        fp = fingerprint(b"x" * 32, chars=0)
        assert len(fp.split(":")[1]) == 1
        fp2 = fingerprint(b"x" * 32, chars=1000)
        assert len(fp2.split(":")[1]) == 64

    def test_fingerprint_accepts_all_types(self) -> None:
        raw = b"y" * 32
        assert fingerprint(raw) == fingerprint(bytearray(raw))
        assert fingerprint(raw) == fingerprint(SecretBytes(raw))
        assert fingerprint("some string") == fingerprint(b"some string")
        assert fingerprint("kanał-ä") == fingerprint("kanał-ä".encode())

    def test_fingerprint_type_error_otherwise(self) -> None:
        with pytest.raises(TypeError):
            fingerprint(12345)  # type: ignore[arg-type]

    def test_own_fingerprint_survives_scrub_text(self) -> None:
        fp = fingerprint(b"z" * 32)
        assert scrub_text(fp) == fp


class TestScrubText:
    def test_base64_key_redacted(self) -> None:
        import base64

        token = base64.b64encode(b"k" * 32).decode("ascii")
        text = f"leaked key: {token} end"
        assert token not in scrub_text(text)
        assert REDACTED in scrub_text(text)

    def test_hex_key_redacted(self) -> None:
        token = "ab" * 32
        text = f"leaked: {token} end"
        assert token not in scrub_text(text)
        assert REDACTED in scrub_text(text)

    def test_lookalikes_not_touched(self) -> None:
        import base64

        token43 = base64.b64encode(b"k" * 31).decode("ascii").rstrip("=")
        text43 = f"value {token43} here"
        assert scrub_text(text43) == text43

        token45 = base64.b64encode(b"k" * 32).decode("ascii") + "x"
        text45 = f"value {token45} here"
        assert scrub_text(text45) == text45

        hex63 = "a" * 63
        text_hex63 = f"value {hex63} here"
        assert scrub_text(text_hex63) == text_hex63


class TestRedactProcessor:
    def test_returns_new_mapping_never_mutates_input(self) -> None:
        event = {"private_key": "secretvalue", "msg": "hello"}
        original = dict(event)
        result = redact_processor(None, "info", event)
        assert event == original
        assert result is not event

    def test_sensitive_key_names_redacted(self) -> None:
        """The replacement must be the *fingerprinted* form, not a bare literal.

        Asserting only ``"<redacted" in ...`` would also pass for a
        degraded ``REDACTED`` constant, losing the ability to correlate
        which secret a given log line touched.
        """
        for name in SENSITIVE_KEY_NAMES:
            event = {name: "value123"}
            result = redact_processor(None, "info", event)
            assert result[name] == redact("value123")
            assert result[name] != REDACTED

    def test_sensitive_key_suffixes_redacted(self) -> None:
        for suffix in SENSITIVE_KEY_SUFFIXES:
            key = f"custom{suffix}"
            event = {key: "value123"}
            result = redact_processor(None, "info", event)
            assert re.fullmatch(r"<redacted:sha256:[0-9a-f]+>", str(result[key]))

    def test_safe_key_names_pass_through(self) -> None:
        for name in SAFE_KEY_NAMES:
            event = {name: "a_pub"}
            result = redact_processor(None, "info", event)
            assert result[name] == "a_pub"

    def test_secret_bytes_under_non_sensitive_key_still_redacted(self) -> None:
        event = {"totally_normal_field": SecretBytes(b"x" * 32)}
        result = redact_processor(None, "info", event)
        assert "<redacted" in str(result["totally_normal_field"])

    def test_non_str_bytes_value_under_sensitive_key_becomes_literal_redacted(self) -> None:
        event = {"private_key": 12345}
        result = redact_processor(None, "info", event)
        assert result["private_key"] == REDACTED

    def test_non_str_value_under_non_sensitive_key_passes_through_unchanged(self) -> None:
        """Structured, non-secret log data must survive the processor intact.

        A regression in the final ``else`` branch would silently null or
        drop arbitrary structured values rather than merely over-redact
        them, quietly gutting every log event this project emits.
        """
        nested = {"inner": ["a", 1]}
        event = {
            "count": 42,
            "enabled": True,
            "ratio": 1.5,
            "meta": nested,
            "absent": None,
            "node_id": NodeId.parse("deadbe01"),
        }
        result = redact_processor(None, "info", event)

        assert result["count"] == 42
        assert result["enabled"] is True
        assert result["ratio"] == 1.5
        assert result["meta"] is nested
        assert result["absent"] is None
        assert result["node_id"] == NodeId.parse("deadbe01")

    def test_plain_string_values_pass_through_scrub_text(self) -> None:
        import base64

        token = base64.b64encode(b"k" * 32).decode("ascii")
        event = {"message": f"leaked {token}"}
        result = redact_processor(None, "info", event)
        assert token not in result["message"]


def test_end_to_end_log_output_never_leaks_key_material(
    keypair_factory,
) -> None:
    """End-to-end: the real configure_logging pipeline scrubs everything."""
    kp = keypair_factory()
    buf = io.StringIO()
    configure_logging("DEBUG", stream=buf, colors=False)

    logging.getLogger("t").warning("leak %s", kp.public_b64)
    logging.getLogger("t").warning("key=%s", SecretBytes(kp.private.reveal()))
    structlog.get_logger("t").warning(
        "provisioned", private_key=kp.private, admin_key=kp.public, key_ref="a_pub"
    )

    output = buf.getvalue()
    assert kp.public_b64 not in output
    assert kp.private_b64() not in output
    assert kp.public.hex() not in output
    assert "<redacted" in output
    assert "a_pub" in output


def test_unmuted_third_party_logger_at_max_verbosity_still_scrubs(
    keypair_factory,
) -> None:
    """A third-party logger released by ``-vvv`` still runs through the redactor.

    ``meshtastic``/``bleak`` are only unmuted at high ``-v`` counts
    (:func:`meshprovision.cli.common._stage_third_party_loggers`) so that
    library GATT/protobuf traces become visible -- but
    :func:`meshprovision.crypto.redact.redact_processor` must still be
    the last thing to touch those records before they render, exactly as
    it is for this project's own loggers.
    """
    kp = keypair_factory()
    buf = io.StringIO()
    configure_logging("DEBUG", stream=buf, colors=False, verbosity=3)

    logging.getLogger("bleak").debug("leaked %s", kp.public_b64)
    logging.getLogger("meshtastic").debug("key=%s", SecretBytes(kp.private.reveal()))

    output = buf.getvalue()
    assert kp.public_b64 not in output
    assert kp.private_b64() not in output
    assert "<redacted" in output
