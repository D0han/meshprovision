"""Tests for meshprovision.crypto.redact."""

from __future__ import annotations

import io
import logging
import re

import pytest
import structlog

import meshprovision.crypto.redact as redact_module
from meshprovision.cli.logging_setup import configure_logging
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

    def test_uppercase_hex_key_redacted(self) -> None:
        token = ("ab" * 32).upper()
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


class TestLibraryRecordMayLeak:
    """Each predicate of ``library_record_may_leak`` holds on its own.

    Every message trips exactly one predicate, so deleting any one of
    them (or one field-name spelling) fails exactly its own id.
    """

    @pytest.mark.parametrize(
        "message",
        [
            "sending header:b'\\x94\\xc3'",
            'long_name: "\\001abc"',
            "payload: 0a0b",
            "privateKey: AAAA",
            "adminKey: AAAA",
            "fixedPin: 123456",
            "sessionPasskey: 1",
        ],
        ids=[
            "bytes-literal",
            "escaped-quote",
            "payload",
            "privateKey",
            "adminKey",
            "fixedPin",
            "sessionPasskey",
        ],
    )
    def test_a_single_risky_shape_is_withheld(self, message: str) -> None:
        assert redact_module.library_record_may_leak(message)

    def test_ordinary_library_chatter_is_not_withheld(self) -> None:
        assert not redact_module.library_record_may_leak("Connecting to 192.168.1.5")


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
        which secret a given log line touched. Uses ``bytes`` here: a
        ``str`` value under a sensitive key name (a PIN, a password) no
        longer gets a fingerprint at all -- see
        ``test_string_values_under_sensitive_keys_become_plain_redacted``.
        """
        for name in SENSITIVE_KEY_NAMES:
            event = {name: b"value123"}
            result = redact_processor(None, "info", event)
            assert result[name] == redact(b"value123")
            assert result[name] != REDACTED

    def test_sensitive_key_suffixes_redacted(self) -> None:
        for suffix in SENSITIVE_KEY_SUFFIXES:
            key = f"custom{suffix}"
            event = {key: b"value123"}
            result = redact_processor(None, "info", event)
            assert re.fullmatch(r"<redacted:sha256:[0-9a-f]+>", str(result[key]))

    def test_string_values_under_sensitive_keys_become_plain_redacted(self) -> None:
        """A str value under a sensitive key gets a plain literal, not a fingerprint.

        A short string (a BLE PIN, a password) has too little entropy for
        a truncated hash to hide it, so it gets the plain ``REDACTED``
        literal instead of a fingerprint -- unlike ``bytes``/``SecretBytes``
        key material, which keeps the fingerprinted form (see
        ``test_sensitive_key_names_redacted``).
        """
        event = {"ble_pin": "482913"}
        result = redact_processor(None, "info", event)
        assert result["ble_pin"] == REDACTED
        assert "sha256" not in str(result["ble_pin"])

    def test_safe_key_names_pass_through(self) -> None:
        for name in SAFE_KEY_NAMES:
            event = {name: "a_pub"}
            result = redact_processor(None, "info", event)
            assert result[name] == "a_pub"

    @pytest.mark.parametrize(
        "key",
        ["PrivateKey", "PSK", " admin_key ", "Wifi_PSK"],
    )
    def test_sensitive_key_classification_is_case_and_whitespace_insensitive(
        self, key: str
    ) -> None:
        event = {key: "value123"}
        result = redact_processor(None, "info", event)
        assert result[key] != "value123"
        assert result[key] == REDACTED

    def test_safe_key_name_overrides_sensitive_match(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SAFE_KEY_NAMES must win even when it artificially collides with SENSITIVE_KEY_NAMES.

        None of the current SAFE names collide with a sensitive name/suffix
        today, so the override check is otherwise a no-op that could be
        deleted without any existing test noticing. Forcing a collision
        here proves the override actually takes precedence, not just that
        it's never exercised.
        """
        monkeypatch.setattr(
            redact_module,
            "SENSITIVE_KEY_NAMES",
            redact_module.SENSITIVE_KEY_NAMES | {"key_ref", "fingerprint"},
        )
        event = {
            "key_ref": "a_pub",
            "KEY_REF": "a_pub",
            "private_key": b"value123",
        }
        result = redact_processor(None, "info", event)
        assert result["key_ref"] == "a_pub"
        assert result["KEY_REF"] == "a_pub"
        assert result["private_key"] == redact(b"value123")

    def test_secret_bytes_under_non_sensitive_key_still_redacted(self) -> None:
        """Replaced by the redacted string, not left as a ``SecretBytes`` for a renderer to read."""
        secret = SecretBytes(b"x" * 32)
        event = {"totally_normal_field": secret}
        result = redact_processor(None, "info", event)
        assert result["totally_normal_field"] == redact(secret)

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

    def test_plain_string_values_have_terminal_escapes_escaped(self) -> None:
        event = {"event": "name A\x1b[2KB"}
        result = redact_processor(None, "info", event)
        assert "\x1b" not in result["event"]
        assert "\\x1b" in result["event"]


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
    assert kp.private.reveal_b64() not in output
    assert kp.public.hex() not in output
    assert "<redacted" in output
    assert "a_pub" in output


def test_debug_traceback_text_is_scrubbed_and_control_escaped(keypair_factory) -> None:
    """A logged traceback goes through the same scrub as the event's message.

    Exception messages (and their chained causes) can quote device- or
    file-sourced text; rendered after the scrub, an ESC sequence or a
    key-shaped string in one reached the stream raw under ``-vv``.
    """
    kp = keypair_factory()
    buf = io.StringIO()
    configure_logging("DEBUG", stream=buf, colors=False)

    try:
        try:
            raise OSError(f"cause \x1b]52;c;SGVsbG8=\x07 {kp.public_b64}")
        except OSError as exc:
            raise ValueError(f"evil \x1b[2J {kp.public_b64}") from exc
    except ValueError:
        logging.getLogger("t").debug("command failed", exc_info=True)

    output = buf.getvalue()
    assert "Traceback (most recent call last)" in output
    assert "The above exception was the direct cause" in output
    assert "\x1b" not in output
    key_leaked = kp.public_b64 in output  # boolean, so a failure never prints the key
    assert not key_leaked
    assert f"OSError: cause \\x1b]52;c;SGVsbG8=\\x07 {REDACTED}\n" in output
    assert f"ValueError: evil \\x1b[2J {REDACTED}\n" in output
