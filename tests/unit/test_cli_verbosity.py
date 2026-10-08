"""Tests for the ``-v``/``--verbose`` flag: level resolution and library staging."""

from __future__ import annotations

import base64
import io
import logging
import re
from typing import Final

import pytest
from click.testing import CliRunner
from google.protobuf.text_format import text_encoding
from meshtastic.protobuf import admin_pb2, localonly_pb2, mesh_pb2

from meshprovision.cli.logging_setup import configure_logging, resolve_log_level
from meshprovision.cli.main import cli
from meshprovision.config.settings import Settings
from meshprovision.crypto.keys import KeyPair, generate_keypair
from tests.conftest import WIDE_TERMINAL_COLUMNS

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("restore_logging")]

_PRIVATE_KEY_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r'private_key: "(?:[^"\\]|\\.)*"')
"""Matches the whole rendered ``private_key: "..."`` field, escapes and all."""


def _windows(token: str, size: int = 12) -> list[str]:
    """Every contiguous ``size``-char substring of ``token``.

    Used to catch a partial leak through line wrapping or truncation,
    not just a leak of the whole token.
    """
    return [token[i : i + size] for i in range(max(1, len(token) - size + 1))]


def _protobuf_corpus() -> list[tuple[str, bytes, bytes]]:
    """34 (label, private_key_bytes, public_key_bytes) cases for the redaction matrix.

    32 real, seeded X25519 keys, plus two adversarial byte patterns that
    a purely escape-detecting predicate would miss: one made entirely of
    printable ASCII (protobuf text format renders it with *no* octal
    escape at all), and one containing the quote/backslash bytes that
    protobuf text format itself uses to escape -- exercising
    escape-within-escape.
    """
    cases: list[tuple[str, bytes, bytes]] = []
    for index in range(32):
        kp: KeyPair = generate_keypair()
        cases.append((f"seeded-{index}", kp.private.reveal(), kp.public))
    printable = bytes(range(0x41, 0x61))
    cases.append(("printable-ascii", printable, bytes(reversed(printable))))
    quote_and_backslash = bytes([0x22, 0x5C, *range(30)])
    cases.append(("quote-and-backslash", quote_and_backslash, bytes(reversed(quote_and_backslash))))
    return cases


def _build_local_config(private_key: bytes, public_key: bytes) -> localonly_pb2.LocalConfig:
    """A ``LocalConfig`` carrying a private key, public key, admin key, and BLE PIN."""
    config = localonly_pb2.LocalConfig()
    config.security.private_key = private_key
    config.security.public_key = public_key
    config.security.admin_key.append(public_key)
    config.bluetooth.fixed_pin = 483920
    return config


def _build_admin_message(private_key: bytes, public_key: bytes) -> admin_pb2.AdminMessage:
    """An ``AdminMessage`` pushing the same key material via ``set_config``."""
    admin = admin_pb2.AdminMessage()
    admin.set_config.security.private_key = private_key
    admin.set_config.security.public_key = public_key
    admin.set_config.security.admin_key.append(public_key)
    return admin


class TestResolveLogLevel:
    def test_explicit_log_level_always_wins(self) -> None:
        """An explicit --log-level beats any -v count, in either direction."""
        assert resolve_log_level("warning", 0) == "warning"
        assert resolve_log_level("warning", 3) == "warning"
        assert resolve_log_level("error", 1) == "error"

    def test_no_log_level_and_no_verbose_returns_none(self) -> None:
        """Neither given: caller's env/.env/default layers must still decide."""
        assert resolve_log_level(None, 0) is None

    def test_single_v_implies_info_absent_explicit_level(self) -> None:
        assert resolve_log_level(None, 1) == "INFO"

    @pytest.mark.parametrize("verbose", [2, 3])
    def test_double_or_triple_v_implies_debug_absent_explicit_level(self, verbose: int) -> None:
        assert resolve_log_level(None, verbose) == "DEBUG"


def test_log_level_choices_are_the_settings_levels_in_severity_order() -> None:
    """``--log-level`` offers exactly the levels ``MESHPROVISION_LOG_LEVEL`` accepts, in order."""
    result = CliRunner().invoke(cli, ["--help"], env={"COLUMNS": WIDE_TERMINAL_COLUMNS})

    assert "--log-level [debug|info|warning|error|critical]" in result.output
    for level in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
        assert Settings(log_level=level).log_level == level


class TestStageThirdPartyLoggers:
    """Regression coverage for the ``max(numeric_level, WARNING)`` bug.

    The old code could only ever make ``meshtastic``/``httpx`` *quieter*
    than WARNING (a quieter explicit ``--log-level``), never louder --
    so ``--log-level debug`` alone could never surface their own
    progress logging. ``-vv``/``-vvv`` must be able to do what
    ``--log-level`` alone never could.
    """

    def test_default_verbosity_matches_pre_verbose_behavior(self) -> None:
        """verbosity=0 must reproduce the exact levels the old code set."""
        configure_logging("DEBUG", stream=io.StringIO(), colors=False)

        assert logging.getLogger("httpcore").level == logging.WARNING
        assert logging.getLogger("bleak").level == logging.WARNING
        assert logging.getLogger("urllib3").level == logging.WARNING
        assert logging.getLogger("httpx").level == logging.WARNING
        assert logging.getLogger("meshtastic").level == logging.WARNING
        assert logging.getLogger().level == logging.DEBUG

    def test_default_verbosity_still_tracks_a_quieter_explicit_level(self) -> None:
        """A quieter --log-level still quiets meshtastic/httpx further, as before."""
        configure_logging("ERROR", stream=io.StringIO(), colors=False)

        assert logging.getLogger("httpx").level == logging.ERROR
        assert logging.getLogger("meshtastic").level == logging.ERROR
        assert logging.getLogger("httpcore").level == logging.WARNING

    def test_single_v_does_not_unmute_any_library(self) -> None:
        """-v alone (verbosity=1) only raises this project's own loggers."""
        configure_logging("DEBUG", stream=io.StringIO(), colors=False, verbosity=1)

        assert logging.getLogger("meshtastic").level == logging.WARNING
        assert logging.getLogger("bleak").level == logging.WARNING

    def test_double_v_unmutes_meshtastic_and_httpx_only(self) -> None:
        """-vv releases stage 0 to inherit the root (DEBUG) level."""
        configure_logging("DEBUG", stream=io.StringIO(), colors=False, verbosity=2)

        assert logging.getLogger("meshtastic").getEffectiveLevel() == logging.DEBUG
        assert logging.getLogger("httpx").getEffectiveLevel() == logging.DEBUG
        assert logging.getLogger("bleak").level == logging.WARNING
        assert logging.getLogger("httpcore").level == logging.WARNING
        assert logging.getLogger("urllib3").level == logging.WARNING

    def test_triple_v_unmutes_every_staged_library(self) -> None:
        """-vvv releases both stages."""
        configure_logging("DEBUG", stream=io.StringIO(), colors=False, verbosity=3)

        for name in ("meshtastic", "httpx", "bleak", "httpcore", "urllib3"):
            assert logging.getLogger(name).getEffectiveLevel() == logging.DEBUG

    def test_explicit_log_level_still_caps_released_loggers(self) -> None:
        """--log-level warning -vvv still means WARNING, not DEBUG."""
        configure_logging("WARNING", stream=io.StringIO(), colors=False, verbosity=3)

        assert logging.getLogger("bleak").getEffectiveLevel() == logging.WARNING
        assert logging.getLogger("meshtastic").getEffectiveLevel() == logging.WARNING


class TestLibrarySecretFilter:
    """The handler-level filter that withholds risky ``meshtastic`` DEBUG records.

    ``-vv``/``-vvv`` deliberately release the ``meshtastic`` logger to
    DEBUG (see ``TestStageThirdPartyLoggers`` above) so transport issues
    can be diagnosed -- but the installed ``meshtastic`` library then
    logs raw protobuf text (private keys rendered as octal escapes) and
    raw frame bytes on its *child* loggers (``meshtastic.mesh_interface``,
    ``meshtastic.stream_interface``). ``redact_processor``'s base64/hex
    scrubbing does not catch that shape. These tests exercise the real
    ``configure_logging`` pipeline end to end, the way an operator running
    ``mesh -vv provision`` would actually trigger it.
    """

    def test_fromradio_style_private_key_and_pin_are_withheld(self, keypair_factory) -> None:
        """Headline: the exact leak the reviewer found is gone. Fails on revert."""
        kp = keypair_factory()
        buf = io.StringIO()
        configure_logging("DEBUG", stream=buf, colors=False, verbosity=2)

        config = _build_local_config(kp.private.reveal(), kp.public)
        rendered = str(config)
        match = _PRIVATE_KEY_TOKEN_RE.search(rendered)
        assert match is not None
        token = match.group(0)

        logging.getLogger("meshtastic.mesh_interface").debug(f"Received from radio: {config}")

        output = buf.getvalue()
        assert token not in output
        assert "483920" not in output
        assert base64.b64encode(kp.private.reveal()).decode("ascii") not in output
        assert "withheld" in output

    def test_raw_serialized_frame_bytes_repr_is_withheld(self, keypair_factory) -> None:
        """``stream_interface``'s ``sending header:...b:{serialized!r}`` line."""
        kp = keypair_factory()
        buf = io.StringIO()
        configure_logging("DEBUG", stream=buf, colors=False, verbosity=2)

        admin = _build_admin_message(kp.private.reveal(), kp.public)
        to_radio = mesh_pb2.ToRadio()
        to_radio.packet.decoded.payload = admin.SerializeToString()
        serialized = to_radio.SerializeToString()
        header = b"\x94\xc3" + len(serialized).to_bytes(2, "big")

        logging.getLogger("meshtastic.stream_interface").debug(
            f"sending header:{header!r} b:{serialized!r}"
        )

        output = buf.getvalue()
        assert repr(serialized) not in output
        assert kp.private.reveal().hex() not in output
        assert "withheld" in output

    def test_sending_packet_payload_carrying_an_admin_message_is_withheld(
        self, keypair_factory
    ) -> None:
        """The private key is nested inside ``decoded.payload``, not a top-level field."""
        kp = keypair_factory()
        buf = io.StringIO()
        configure_logging("DEBUG", stream=buf, colors=False, verbosity=2)

        admin = _build_admin_message(kp.private.reveal(), kp.public)
        packet = mesh_pb2.MeshPacket()
        packet.decoded.portnum = 6
        packet.decoded.payload = admin.SerializeToString()

        logging.getLogger("meshtastic.mesh_interface").debug(f"Sending packet: {packet}")

        output = buf.getvalue()
        assert kp.private.reveal().hex() not in output
        assert repr(admin.SerializeToString()) not in output
        assert "withheld" in output

    def test_benign_meshtastic_record_passes_through_unchanged(self) -> None:
        """Guards against over-filtering: ordinary connection chatter is untouched."""
        buf = io.StringIO()
        configure_logging("DEBUG", stream=buf, colors=False, verbosity=2)

        logging.getLogger("meshtastic.tcp_interface").debug("Connecting to 192.168.1.5")

        output = buf.getvalue()
        assert "Connecting to 192.168.1.5" in output
        assert "withheld" not in output

    def test_non_meshtastic_logger_is_not_covered_by_the_library_filter(self) -> None:
        """Scope guard: the filter is scoped to ``meshtastic`` and its children only.

        ``scrub_text`` still runs (it is the backstop for every logger),
        but it does not catch this shape -- this test pins that S3's
        protection is scoped to ``meshtastic``, so nobody later assumes
        project loggers are covered for protobuf text too.
        """
        buf = io.StringIO()
        configure_logging("DEBUG", stream=buf, colors=False, verbosity=3)

        logging.getLogger("t").debug("frame bytes: %r", b"\x01\x02\x03")

        output = buf.getvalue()
        assert "withheld" not in output


class TestMeshtasticProtobufTextRedactionMatrix:
    """T7: the redaction guarantee holds across a real, varied key corpus.

    The predecessor tests fed key material through the pipeline as
    base64/``SecretBytes`` strings -- a shape the installed ``meshtastic``
    library's own logging never produces, so they passed even while the
    real leak (protobuf text format) was live. These log real protobuf
    messages through the real ``meshtastic`` child loggers instead.
    """

    @pytest.mark.parametrize("verbosity", [2, 3])
    def test_meshtastic_protobuf_text_never_leaks_key_material(self, verbosity: int) -> None:
        buf = io.StringIO()
        configure_logging("DEBUG", stream=buf, colors=False, verbosity=verbosity)

        loggers = ("meshtastic.mesh_interface", "meshtastic.stream_interface", "meshtastic.node")
        forbidden: list[str] = []
        for index, (label, private_key, public_key) in enumerate(_protobuf_corpus()):
            config = _build_local_config(private_key, public_key)
            admin = _build_admin_message(private_key, public_key)

            rendered = str(config)
            match = _PRIVATE_KEY_TOKEN_RE.search(rendered)
            assert match is not None, f"{label}: no private_key token rendered"
            token = match.group(0)
            assert token in rendered, f"{label}: positive control is vacuous"

            forbidden.append(token)
            forbidden.append(text_encoding.CEscape(private_key, as_utf8=False))
            forbidden.append(base64.b64encode(private_key).decode("ascii"))
            forbidden.append(private_key.hex())
            forbidden.extend(_windows(token))

            logger = logging.getLogger(loggers[index % len(loggers)])
            logger.debug(f"Sending: {config}")
            logger.debug(f"Received from radio: {admin}")
            logger.debug(str(config).replace("\n", " "))

        output = buf.getvalue()
        assert "483920" not in output
        assert "withheld" in output
        for needle in forbidden:
            assert needle not in output, f"leaked: {needle!r}"

    def test_scope_guard_non_meshtastic_logger_not_withheld(self) -> None:
        """The same protobuf text on a non-meshtastic logger is not withheld.

        Documents that S3's protection is scoped to ``meshtastic``, not a
        general project-wide protobuf-text redactor.
        """
        buf = io.StringIO()
        configure_logging("DEBUG", stream=buf, colors=False, verbosity=3)

        kp = generate_keypair()
        config = _build_local_config(kp.private.reveal(), kp.public)

        logging.getLogger("t").debug(f"Received from radio: {config}")

        output = buf.getvalue()
        assert "withheld" not in output
