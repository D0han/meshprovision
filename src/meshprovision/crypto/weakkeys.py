"""The layered CVE-2025-52464 ("Repeated Public/Private Keypairs") audit.

No public blocklist of CVE-2025-52464 keys exists -- the advisory itself
publishes none, and current Meshtastic firmware detects duplicates only
on-mesh, via an advertisement check. Detection here is therefore built
from checks that can actually be run against a key or a fleet, layered
from cheapest/most-structural to most-contextual:

1. **Blocklist** (:func:`audit_public_key`, :func:`audit_private_key`) --
   membership in :func:`load_known_bad_keys`, which always includes
   :data:`SMALL_ORDER_POINTS` (libsodium's 7 canonical X25519 small-order
   points) plus anything in the operator-extensible
   ``data/known_bad_keys.txt``.
2. **Structural** -- all-zero, a single repeated byte, a monotonic byte
   run, or abnormally low Hamming weight / byte diversity. These are the
   unseeded-RNG failure signature described in the advisory.
3. **Consistency** (:func:`audit_keypair`) -- the public key derived from
   the private key must match the one reported by the device; a mismatch
   means corruption or a partial restore (firmware issue #7449).
4. **Firmware window** (:func:`audit_node`) -- firmware in
   ``[FIRMWARE_VULNERABLE_MIN, FIRMWARE_FIXED_MIN)`` is treated as
   presumptively compromised regardless of the key's own contents.
5. **Cross-fleet duplicate** (:func:`audit_node`,
   :func:`find_duplicate_public_keys`) -- two of *our own* nodes sharing
   a public key is exactly the vendor key-cloning failure mode the CVE
   describes.

**Invariant:** every element of :data:`SMALL_ORDER_POINTS` is exactly 32
bytes, and (per a unit test in the test layer, not this module)
``set(SMALL_ORDER_POINTS)`` is always a subset of
``load_known_bad_keys()`` -- whether or not
``data/known_bad_keys.txt`` is present on disk.

**On key clamping:** OpenSSL-family backends can store an X25519 private
scalar unclamped and clamp only at use time, so an unclamped private key
is *not*, by itself, evidence of anything wrong. ``check_clamping``
therefore defaults to ``False`` on every entry point in this module, and
when explicitly enabled, an unclamped scalar is reported at severity
``"warning"`` -- never ``"critical"``. See
``meshprovision.crypto.keys.is_clamped`` for the exact bit pattern
checked.
"""

from __future__ import annotations

import hmac
import logging
import os
import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final

from meshprovision.crypto import keys
from meshprovision.crypto.redact import SecretBytes, fingerprint, reveal
from meshprovision.errors import KeyMaterialError, SettingsError, WeakKeyError, WeakKeySeverity

__all__ = [
    "FIRMWARE_FIXED_MIN",
    "FIRMWARE_VULNERABLE_MIN",
    "KNOWN_BAD_KEYS_ENV",
    "LOW_HAMMING_MAX",
    "LOW_HAMMING_MIN",
    "MIN_DISTINCT_BYTES",
    "SMALL_ORDER_POINTS",
    "AuditResult",
    "WeakKeyCheck",
    "WeakKeyFinding",
    "audit_keypair",
    "audit_node",
    "audit_private_key",
    "audit_public_key",
    "default_known_bad_keys_path",
    "find_duplicate_public_keys",
    "hamming_weight",
    "is_all_zero",
    "is_low_entropy",
    "is_monotonic_run",
    "is_repeated_byte",
    "is_small_order",
    "is_vulnerable_firmware",
    "load_known_bad_keys",
    "parse_firmware_version",
    "parse_known_bad_keys",
]

_logger = logging.getLogger(__name__)

FIRMWARE_VULNERABLE_MIN: Final[tuple[int, int, int]] = (2, 5, 0)
"""First firmware version inside the CVE-2025-52464 window (inclusive)."""

FIRMWARE_FIXED_MIN: Final[tuple[int, int, int]] = (2, 6, 11)
"""First firmware version outside the CVE-2025-52464 window (exclusive bound)."""

KNOWN_BAD_KEYS_ENV: Final[str] = "MESHPROVISION_KNOWN_BAD_KEYS"
"""Environment variable overriding the blocklist file path."""

LOW_HAMMING_MIN: Final[int] = 32
"""Below this Hamming weight, a 32-byte value is critically suspect.

Random 32 bytes have a Hamming weight of ~128 +/- 8 (binomial, n=256,
p=0.5); 32 is more than 12 standard deviations below the mean.
"""

LOW_HAMMING_MAX: Final[int] = 224
"""Above this Hamming weight, a 32-byte value is suspiciously high (symmetric bound)."""

MIN_DISTINCT_BYTES: Final[int] = 5
"""Below this many distinct byte values, a 32-byte value is suspect.

Random 32 bytes have ~30 distinct values out of 256 possible.
"""

# The 7 canonical X25519 small-order / degenerate public keys from
# libsodium's has_small_order() blocklist
# (crypto_scalarmult/curve25519/ref10/x25519_ref10.c), decoded from the
# same base64 encodings committed verbatim to data/known_bad_keys.txt so
# the two files can never silently drift apart. p = 2**255 - 19; all
# encodings are little-endian 32-byte.
_SMALL_ORDER_ALL_ZERO = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000000"
)
"""The all-zero point (order 4). Also the firmware's own weak-key check."""

_SMALL_ORDER_POINT_ONE = bytes.fromhex(
    "0100000000000000000000000000000000000000000000000000000000000000"
)
"""The point 1 (order 1): 0x01 followed by 31 zero bytes."""

_SMALL_ORDER_8_A = bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")
"""Order-8 point #1 (libsodium blacklist entry 3)."""

_SMALL_ORDER_8_B = bytes.fromhex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157")
"""Order-8 point #2 (libsodium blacklist entry 4)."""

_SMALL_ORDER_P_MINUS_1 = bytes.fromhex(
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
)
"""p - 1 (order 2)."""

_SMALL_ORDER_P = bytes.fromhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
"""p (order 4) -- the field modulus itself, a non-canonical encoding of 0."""

_SMALL_ORDER_P_PLUS_1 = bytes.fromhex(
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
)
"""p + 1 (order 1) -- a non-canonical encoding of 1."""

SMALL_ORDER_POINTS: Final[tuple[bytes, ...]] = (
    _SMALL_ORDER_ALL_ZERO,
    _SMALL_ORDER_POINT_ONE,
    _SMALL_ORDER_8_A,
    _SMALL_ORDER_8_B,
    _SMALL_ORDER_P_MINUS_1,
    _SMALL_ORDER_P,
    _SMALL_ORDER_P_PLUS_1,
)
"""The 7 canonical libsodium X25519 small-order / degenerate public keys.

Every entry is exactly 32 bytes (verified below, at import time). Any
node advertising one of these has a broken or malicious key, and every
shared secret derived from one is degenerate.
"""

if any(len(point) != keys.X25519_KEY_SIZE for point in SMALL_ORDER_POINTS):
    raise KeyMaterialError(
        "SMALL_ORDER_POINTS contains an entry that is not "
        f"{keys.X25519_KEY_SIZE} bytes; this is a packaging bug",
        reason="invalid small-order point table",
    )

_FIRMWARE_VERSION_RE: Final[re.Pattern[str]] = re.compile(r"^\s*v?(\d+)\.(\d+)\.(\d+)")

_SEVERITY_RANK: Final[dict[WeakKeySeverity, int]] = {
    WeakKeySeverity.CRITICAL: 0,
    WeakKeySeverity.WARNING: 1,
}

_blocklist_cache: dict[tuple[Path, int, int], frozenset[bytes]] = {}
"""Module-private cache of parsed blocklist files, keyed by (path, mtime_ns, size).

Deliberately mutable, unlike the rest of this project's data structures:
this is infrastructure caching, not domain state. Keying on the file's
mtime and size (rather than just its path) means a rewritten blocklist
file is picked up on the next call without ever re-reading an unchanged
one.
"""


class WeakKeyCheck(StrEnum):
    """Which weak-key check produced a :class:`WeakKeyFinding`."""

    BLOCKLIST = "blocklist"
    ALL_ZERO = "all_zero"
    SMALL_ORDER = "small_order"
    REPEATED_BYTE = "repeated_byte"
    MONOTONIC = "monotonic"
    LOW_ENTROPY = "low_entropy"
    UNCLAMPED = "unclamped"
    CONSISTENCY = "consistency"
    FIRMWARE_WINDOW = "firmware_window"
    DUPLICATE = "duplicate"


@dataclass(frozen=True, slots=True)
class WeakKeyFinding:
    """One weak-key audit finding.

    Named ``reason`` rather than ``message`` (the field name
    :class:`~meshprovision.provisioning.plan_warnings.PlanWarning`/
    :class:`~meshprovision.db.verify.DbProblem`/``WriteResult`` use for
    the same descriptive-text role) deliberately: :meth:`as_error` maps
    this field 1:1 onto :class:`~meshprovision.errors.WeakKeyError`'s
    own ``reason`` attribute, its natural conversion target, so the two
    stay named the same rather than matching the other "outcome"
    dataclasses' unrelated convention.

    Attributes:
        check: Which check produced this finding.
        severity: ``"warning"`` or ``"critical"``.
        reason: Human-readable description of the finding.
        detail: Additional detail, when useful. Never key material --
            only derived facts such as Hamming weight or other
            fingerprints.
        fingerprint: Redacted digest of the affected key, when known.
        node_id: Affected node id, in display form, when known.
        key_ref: Affected key reference in the ``Keys`` sheet, when known.
    """

    check: WeakKeyCheck
    severity: WeakKeySeverity
    reason: str
    detail: str | None = None
    fingerprint: str | None = None
    node_id: str | None = None
    key_ref: str | None = None

    def as_error(self) -> WeakKeyError:
        """Convert this finding into a raisable :class:`WeakKeyError`.

        Returns:
            A :class:`WeakKeyError` carrying this finding's fields.
        """
        return WeakKeyError(
            self.reason,
            reason=self.reason,
            node_id=self.node_id,
            key_ref=self.key_ref,
            severity=self.severity,
            fingerprint=self.fingerprint,
        )


@dataclass(frozen=True, slots=True)
class AuditResult:
    """The outcome of running one or more weak-key checks against a key.

    Attributes:
        findings: Every finding raised, sorted critical-first then by
            check name for deterministic output.
        fingerprint: Redacted digest of the primary audited key, when
            known.
        node_id: Affected node id, in display form, when known.
        key_ref: Affected key reference in the ``Keys`` sheet, when known.
    """

    findings: tuple[WeakKeyFinding, ...]
    fingerprint: str | None = None
    node_id: str | None = None
    key_ref: str | None = None

    @property
    def ok(self) -> bool:
        """Whether the audit produced no findings at all.

        Returns:
            ``True`` if :attr:`findings` is empty.
        """
        return not self.findings

    @property
    def compromised(self) -> bool:
        """Whether any finding is critical.

        Returns:
            ``True`` if any finding has ``severity == "critical"``.
        """
        return any(f.severity is WeakKeySeverity.CRITICAL for f in self.findings)

    @property
    def severity(self) -> WeakKeySeverity | None:
        """The highest severity present among the findings.

        Returns:
            ``"critical"`` if any finding is critical, else ``"warning"``
            if any finding is a warning, else ``None``.
        """
        if any(f.severity is WeakKeySeverity.CRITICAL for f in self.findings):
            return WeakKeySeverity.CRITICAL
        if any(f.severity is WeakKeySeverity.WARNING for f in self.findings):
            return WeakKeySeverity.WARNING
        return None

    def summary(self) -> str:
        """Render one already-redacted line per finding.

        Returns:
            A newline-joined summary, safe to log directly.
        """
        lines = []
        for f in self.findings:
            line = f"[{f.severity}] {f.check.value}: {f.reason}"
            if f.detail:
                line += f" ({f.detail})"
            lines.append(line)
        return "\n".join(lines)

    def raise_if_compromised(self) -> None:
        """Raise the first critical finding as a :class:`WeakKeyError`.

        Raises:
            WeakKeyError: If :attr:`compromised` is ``True``.
        """
        for f in self.findings:
            if f.severity is WeakKeySeverity.CRITICAL:
                raise f.as_error()


def _sort_findings(findings: list[WeakKeyFinding]) -> tuple[WeakKeyFinding, ...]:
    """Sort findings critical-first, then by check name, for deterministic output.

    Args:
        findings: The findings to sort.

    Returns:
        An immutable, sorted tuple.
    """
    return tuple(sorted(findings, key=lambda f: (_SEVERITY_RANK[f.severity], f.check.value)))


def parse_firmware_version(raw: str) -> tuple[int, int, int] | None:
    """Parse a Meshtastic firmware version string.

    Tolerates a leading ``v`` and a trailing build hash that Meshtastic
    appends (for example ``"2.6.12.9861e82"``).

    Args:
        raw: The raw firmware version string.

    Returns:
        A ``(major, minor, patch)`` tuple, or ``None`` if ``raw`` does not
        start with a recognizable ``[v]X.Y.Z`` prefix.
    """
    match = _FIRMWARE_VERSION_RE.match(raw)
    if match is None:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def is_vulnerable_firmware(version: str | tuple[int, int, int] | None) -> bool:
    """Check whether a firmware version falls inside the CVE-2025-52464 window.

    Args:
        version: A version string (parsed via :func:`parse_firmware_version`),
            an already-parsed ``(major, minor, patch)`` tuple, or ``None``.

    Returns:
        ``True`` if ``FIRMWARE_VULNERABLE_MIN <= version < FIRMWARE_FIXED_MIN``.
        ``False`` if ``version`` is ``None`` or an unparseable string.
    """
    if version is None:
        return False
    if isinstance(version, str):
        parsed = parse_firmware_version(version)
        if parsed is None:
            return False
        version = parsed
    return FIRMWARE_VULNERABLE_MIN <= version < FIRMWARE_FIXED_MIN


def default_known_bad_keys_path() -> Path | None:
    """Resolve the default location of the on-disk key blocklist.

    Tries, in order: the path in :data:`KNOWN_BAD_KEYS_ENV` (if set);
    ``<package>/data/known_bad_keys.txt`` (in case the file is ever
    vendored into the installed package); ``<repo root>/data/known_bad_keys.txt``
    (a checkout run from source); ``./data/known_bad_keys.txt`` relative
    to the current working directory.

    Returns:
        The first candidate path that exists, or ``None`` if none does
        (this is not an error -- see :func:`load_known_bad_keys`).

    Raises:
        SettingsError: If :data:`KNOWN_BAD_KEYS_ENV` is set to a path
            that does not exist.
    """
    env_value = os.environ.get(KNOWN_BAD_KEYS_ENV)
    if env_value and env_value.strip():
        candidate = Path(env_value.strip()).expanduser()
        if candidate.exists():
            return candidate
        raise SettingsError(
            f"{KNOWN_BAD_KEYS_ENV} is set to a path that does not exist: {candidate}",
            hint=(
                f"Check the path in {KNOWN_BAD_KEYS_ENV}, or unset it to use the bundled blocklist."
            ),
        )

    module_parents = Path(__file__).resolve().parents
    package_root = module_parents[1]
    repo_root_candidate = module_parents[3] if len(module_parents) > 3 else None
    candidates = [package_root / "data" / "known_bad_keys.txt"]
    if repo_root_candidate is not None:
        candidates.append(repo_root_candidate / "data" / "known_bad_keys.txt")
    candidates.append(Path.cwd() / "data" / "known_bad_keys.txt")

    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def parse_known_bad_keys(text: str, *, source: str = "<string>") -> tuple[bytes, ...]:
    """Parse the contents of a known-bad-keys blocklist file.

    Pure: performs no I/O. One base64-encoded 32-byte key per line;
    everything from the first ``#`` to end of line is a comment; blank
    lines are ignored.

    Args:
        text: The file contents to parse.
        source: Identifies the file for error messages (never the
            offending token itself).

    Returns:
        The decoded keys, deduplicated preserving first-seen order.

    Raises:
        KeyMaterialError: If any non-comment, non-blank line fails to
            decode to exactly 32 bytes of canonical base64.
    """
    seen: dict[bytes, None] = {}
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        raw = keys.decode_key(line, field=f"{source}:{lineno}")
        seen.setdefault(raw, None)
    return tuple(seen)


def load_known_bad_keys(path: Path | None = None) -> frozenset[bytes]:
    """Load the effective known-bad-keys blocklist.

    Always includes :data:`SMALL_ORDER_POINTS`, whether or not an
    on-disk file is present -- absence of the file is a supported,
    non-error condition. Results are cached in a module-private dict
    keyed by ``(path, mtime_ns, size)``, so repeated audits do not
    re-read the file, but a rewritten file is picked up on the next call.

    Args:
        path: An explicit blocklist path. When ``None``, resolved via
            :func:`default_known_bad_keys_path`.

    Returns:
        The union of :data:`SMALL_ORDER_POINTS` and everything parsed
        from the resolved file (or just :data:`SMALL_ORDER_POINTS` if no
        file was found).

    Raises:
        KeyMaterialError: If the resolved file exists but cannot be read,
            or contains a malformed entry (via :func:`parse_known_bad_keys`).
        SettingsError: If :data:`KNOWN_BAD_KEYS_ENV` is set to a path that
            does not exist (propagated from :func:`default_known_bad_keys_path`).
    """
    resolved = path if path is not None else default_known_bad_keys_path()
    if resolved is None or not resolved.exists():
        _logger.debug(
            "no known-bad-keys blocklist file found; using only the %d built-in small-order points",
            len(SMALL_ORDER_POINTS),
        )
        return frozenset(SMALL_ORDER_POINTS)

    try:
        stat = resolved.stat()
    except OSError as exc:
        raise KeyMaterialError(
            f"blocklist file could not be read: {resolved}",
            reason="blocklist file could not be read",
        ) from exc

    cache_key = (resolved, stat.st_mtime_ns, stat.st_size)
    cached = _blocklist_cache.get(cache_key)
    if cached is not None:
        return cached

    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        raise KeyMaterialError(
            f"blocklist file could not be read: {resolved}",
            reason="blocklist file could not be read",
        ) from exc

    parsed = parse_known_bad_keys(text, source=str(resolved))
    result = frozenset(parsed) | frozenset(SMALL_ORDER_POINTS)
    _blocklist_cache[cache_key] = result
    return result


def is_all_zero(raw: bytes) -> bool:
    """Check whether every byte of ``raw`` is zero.

    Args:
        raw: The bytes to check.

    Returns:
        ``True`` if ``raw`` is all-zero (including the empty case).
    """
    return raw == bytes(len(raw))


def is_small_order(public: bytes) -> bool:
    """Check whether ``public`` is one of :data:`SMALL_ORDER_POINTS`.

    Every candidate is compared in constant time, and every comparison
    always runs (no early exit), so the result does not leak *which*
    point matched via timing.

    Args:
        public: The candidate public key.

    Returns:
        ``True`` if ``public`` matches any entry in
        :data:`SMALL_ORDER_POINTS`. Always ``False`` for a length other
        than :data:`meshprovision.crypto.keys.X25519_KEY_SIZE`.
    """
    if len(public) != keys.X25519_KEY_SIZE:
        return False
    hit = False
    for point in SMALL_ORDER_POINTS:
        hit |= hmac.compare_digest(public, point)
    return hit


def is_repeated_byte(raw: bytes) -> bool:
    """Check whether ``raw`` consists of a single repeated byte value.

    Args:
        raw: The bytes to check.

    Returns:
        ``True`` if ``len(raw) >= 2`` and every byte has the same value.
    """
    if len(raw) < 2:
        return False
    return len(set(raw)) == 1


def is_monotonic_run(raw: bytes) -> bool:
    """Check whether ``raw`` is a monotonic run (each byte +1 or -1 from the last).

    A delta of 0 (a repeated byte) is reported separately by
    :func:`is_repeated_byte`, not here.

    Args:
        raw: The bytes to check.

    Returns:
        ``True`` if ``len(raw) >= 2`` and every consecutive byte-to-byte
        delta (mod 256) is the same and equal to 1 or 255.
    """
    if len(raw) < 2:
        return False
    deltas = {(raw[i + 1] - raw[i]) % 256 for i in range(len(raw) - 1)}
    return len(deltas) == 1 and deltas.pop() in (1, 255)


def hamming_weight(raw: bytes) -> int:
    """Count the total number of set bits across all bytes of ``raw``.

    Args:
        raw: The bytes to measure.

    Returns:
        The total Hamming weight.
    """
    return sum(byte.bit_count() for byte in raw)


def is_low_entropy(raw: bytes) -> bool:
    """Check whether ``raw`` has abnormally low or high bit/byte diversity.

    Args:
        raw: The bytes to check.

    Returns:
        ``True`` if the Hamming weight is below :data:`LOW_HAMMING_MIN`,
        above :data:`LOW_HAMMING_MAX`, or the number of distinct byte
        values is below :data:`MIN_DISTINCT_BYTES`.
    """
    weight = hamming_weight(raw)
    return (
        weight < LOW_HAMMING_MIN or weight > LOW_HAMMING_MAX or len(set(raw)) < MIN_DISTINCT_BYTES
    )


def find_duplicate_public_keys(keys: Mapping[str, bytes]) -> dict[str, tuple[str, ...]]:
    """Find every key reference whose public key is shared with another.

    Pure: performs no I/O.

    Args:
        keys: A mapping of key reference to raw public key bytes.

    Returns:
        A mapping from each key reference involved in a duplicate to the
        sorted tuple of *other* references sharing its public key. A
        reference with no duplicate is absent from the result.
    """
    groups: dict[bytes, list[str]] = {}
    for ref, public in keys.items():
        groups.setdefault(bytes(public), []).append(ref)

    result: dict[str, tuple[str, ...]] = {}
    for refs in groups.values():
        if len(refs) > 1:
            for ref in refs:
                result[ref] = tuple(sorted(r for r in refs if r != ref))
    return result


def _in_blocklist(raw: bytes, bad_set: Collection[bytes]) -> bool:
    """Check ``raw`` against a blocklist in constant time.

    Args:
        raw: The candidate key bytes.
        bad_set: The blocklist to check against.

    Returns:
        ``True`` if ``raw`` matches any entry, comparing every entry
        (no early exit).
    """
    hit = False
    for candidate in bad_set:
        hit |= hmac.compare_digest(raw, bytes(candidate))
    return hit


def _structural_findings(
    raw: bytes,
    *,
    include_small_order: bool,
    fp: str,
    node_id: str | None,
    key_ref: str | None,
    material: str,
) -> list[WeakKeyFinding]:
    """Run the structural weak-key battery shared by public and private audits.

    Args:
        raw: The 32-byte key material to inspect.
        include_small_order: Whether to also run the small-order-point
            check (only meaningful for public keys).
        fp: Pre-computed redacted fingerprint of ``raw``.
        node_id: Affected node id, in display form, when known.
        key_ref: Affected key reference in the ``Keys`` sheet, when known.
        material: ``"public"`` or ``"private"``, used to phrase findings.

    Returns:
        The findings raised, unsorted.
    """
    findings: list[WeakKeyFinding] = []

    if is_all_zero(raw):
        findings.append(
            WeakKeyFinding(
                check=WeakKeyCheck.ALL_ZERO,
                severity=WeakKeySeverity.CRITICAL,
                reason=f"{material} key is all-zero",
                fingerprint=fp,
                node_id=node_id,
                key_ref=key_ref,
            )
        )
    if include_small_order and is_small_order(raw):
        findings.append(
            WeakKeyFinding(
                check=WeakKeyCheck.SMALL_ORDER,
                severity=WeakKeySeverity.CRITICAL,
                reason=f"{material} key is a degenerate small-order curve point",
                fingerprint=fp,
                node_id=node_id,
                key_ref=key_ref,
            )
        )
    if is_repeated_byte(raw):
        findings.append(
            WeakKeyFinding(
                check=WeakKeyCheck.REPEATED_BYTE,
                severity=WeakKeySeverity.CRITICAL,
                reason=f"{material} key consists of a single repeated byte value",
                fingerprint=fp,
                node_id=node_id,
                key_ref=key_ref,
            )
        )
    if is_monotonic_run(raw):
        findings.append(
            WeakKeyFinding(
                check=WeakKeyCheck.MONOTONIC,
                severity=WeakKeySeverity.CRITICAL,
                reason=f"{material} key bytes form a monotonic run",
                fingerprint=fp,
                node_id=node_id,
                key_ref=key_ref,
            )
        )
    if is_low_entropy(raw):
        weight = hamming_weight(raw)
        # LOW_HAMMING_MIN/MAX are a symmetric bound (see their docstrings) --
        # a weight abnormally high is exactly as suspect as one abnormally
        # low, so both sides are critical. A merely low distinct-byte count
        # with an otherwise-normal weight stays warning: distinct.
        low_or_high_weight = weight < LOW_HAMMING_MIN or weight > LOW_HAMMING_MAX
        severity = WeakKeySeverity.CRITICAL if low_or_high_weight else WeakKeySeverity.WARNING
        findings.append(
            WeakKeyFinding(
                check=WeakKeyCheck.LOW_ENTROPY,
                severity=severity,
                reason=f"{material} key has abnormally low entropy",
                detail=f"hamming_weight={weight}, distinct_bytes={len(set(raw))}",
                fingerprint=fp,
                node_id=node_id,
                key_ref=key_ref,
            )
        )
    return findings


def audit_public_key(
    public: bytes,
    *,
    node_id: str | None = None,
    key_ref: str | None = None,
    known_bad: Collection[bytes] | None = None,
) -> AuditResult:
    """Run the structural + blocklist weak-key battery against a public key.

    Args:
        public: The raw 32-byte public key to audit.
        node_id: Affected node id, in display form, when known.
        key_ref: Affected key reference in the ``Keys`` sheet, when known.
        known_bad: The blocklist to check against. When ``None``, loaded
            via :func:`load_known_bad_keys`.

    Returns:
        The audit result, with findings sorted critical-first.

    Raises:
        KeyMaterialError: If ``public`` is not exactly
            :data:`meshprovision.crypto.keys.X25519_KEY_SIZE` bytes.
    """
    if not isinstance(public, bytes | bytearray) or len(public) != keys.X25519_KEY_SIZE:
        raise KeyMaterialError(
            f"public key must be exactly {keys.X25519_KEY_SIZE} bytes",
            reason="invalid public key length",
            expected_length=keys.X25519_KEY_SIZE,
            actual_length=len(public) if isinstance(public, bytes | bytearray) else None,
        )
    raw = bytes(public)
    bad_set = known_bad if known_bad is not None else load_known_bad_keys()
    fp = fingerprint(raw)

    findings: list[WeakKeyFinding] = []
    if _in_blocklist(raw, bad_set):
        findings.append(
            WeakKeyFinding(
                check=WeakKeyCheck.BLOCKLIST,
                severity=WeakKeySeverity.CRITICAL,
                reason="public key matches an entry in the known-bad key blocklist",
                fingerprint=fp,
                node_id=node_id,
                key_ref=key_ref,
            )
        )
    findings.extend(
        _structural_findings(
            raw,
            include_small_order=True,
            fp=fp,
            node_id=node_id,
            key_ref=key_ref,
            material="public",
        )
    )

    return AuditResult(
        findings=_sort_findings(findings), fingerprint=fp, node_id=node_id, key_ref=key_ref
    )


def audit_private_key(
    private: bytes | SecretBytes,
    *,
    node_id: str | None = None,
    key_ref: str | None = None,
    known_bad: Collection[bytes] | None = None,
    check_clamping: bool = False,
) -> AuditResult:
    """Run the structural + blocklist weak-key battery against a private key.

    Does not run the small-order-point check (meaningless for a private
    scalar), but does check the blocklist -- a private key equal to a
    published bad *public* key is itself a red flag worth reporting.

    Args:
        private: Raw private key bytes, or a :class:`SecretBytes`
            wrapping them.
        node_id: Affected node id, in display form, when known.
        key_ref: Affected key reference in the ``Keys`` sheet, when known.
        known_bad: The blocklist to check against. When ``None``, loaded
            via :func:`load_known_bad_keys`.
        check_clamping: Whether to also check X25519 clamping. Defaults
            to ``False`` because an unclamped private key is normal for
            some backends (see the module docstring); when ``True``, an
            unclamped scalar is reported at severity ``"warning"``, never
            ``"critical"``.

    Returns:
        The audit result, with findings sorted critical-first.

    Raises:
        KeyMaterialError: If ``private`` is not exactly
            :data:`meshprovision.crypto.keys.X25519_KEY_SIZE` bytes.
    """
    unwrapped = reveal(private) if isinstance(private, SecretBytes) else private
    if not isinstance(unwrapped, bytes | bytearray) or len(unwrapped) != keys.X25519_KEY_SIZE:
        raise KeyMaterialError(
            f"private key must be exactly {keys.X25519_KEY_SIZE} bytes",
            reason="invalid private key length",
            expected_length=keys.X25519_KEY_SIZE,
            actual_length=len(unwrapped) if isinstance(unwrapped, bytes | bytearray) else None,
        )
    raw = bytes(unwrapped)
    bad_set = known_bad if known_bad is not None else load_known_bad_keys()
    fp = fingerprint(raw)

    findings: list[WeakKeyFinding] = []
    if _in_blocklist(raw, bad_set):
        findings.append(
            WeakKeyFinding(
                check=WeakKeyCheck.BLOCKLIST,
                severity=WeakKeySeverity.CRITICAL,
                reason="private key matches an entry in the known-bad key blocklist",
                fingerprint=fp,
                node_id=node_id,
                key_ref=key_ref,
            )
        )
    findings.extend(
        _structural_findings(
            raw,
            include_small_order=False,
            fp=fp,
            node_id=node_id,
            key_ref=key_ref,
            material="private",
        )
    )
    if check_clamping and not keys.is_clamped(raw):
        findings.append(
            WeakKeyFinding(
                check=WeakKeyCheck.UNCLAMPED,
                severity=WeakKeySeverity.WARNING,
                reason=(
                    "private key is not X25519-clamped; this is normal for some "
                    "OpenSSL-family backends, which can store the unclamped scalar and "
                    "clamp only at use time, so this is never treated as evidence of "
                    "compromise"
                ),
                fingerprint=fp,
                node_id=node_id,
                key_ref=key_ref,
            )
        )

    return AuditResult(
        findings=_sort_findings(findings), fingerprint=fp, node_id=node_id, key_ref=key_ref
    )


def audit_keypair(
    private: bytes | SecretBytes,
    public: bytes,
    *,
    node_id: str | None = None,
    key_ref: str | None = None,
    known_bad: Collection[bytes] | None = None,
    check_clamping: bool = False,
) -> AuditResult:
    """Audit a private/public key pair, including cross-key consistency.

    Runs :func:`audit_private_key` and :func:`audit_public_key`, then
    additionally verifies that the public key derived from the private
    key matches the reported ``public`` (per firmware issue #7449, a
    mismatch means corruption or a partial restore).

    Args:
        private: Raw private key bytes, or a :class:`SecretBytes`
            wrapping them.
        public: The raw 32-byte public key reported alongside ``private``.
        node_id: Affected node id, in display form, when known.
        key_ref: Affected key reference in the ``Keys`` sheet, when known.
        known_bad: The blocklist to check against. When ``None``, loaded
            once via :func:`load_known_bad_keys` and shared between the
            private and public sub-audits.
        check_clamping: Passed through to :func:`audit_private_key`.

    Returns:
        A single merged audit result, with findings sorted critical-first.

    Raises:
        KeyMaterialError: If either key is not exactly
            :data:`meshprovision.crypto.keys.X25519_KEY_SIZE` bytes.
    """
    bad_set = known_bad if known_bad is not None else load_known_bad_keys()
    private_result = audit_private_key(
        private,
        node_id=node_id,
        key_ref=key_ref,
        known_bad=bad_set,
        check_clamping=check_clamping,
    )
    public_result = audit_public_key(public, node_id=node_id, key_ref=key_ref, known_bad=bad_set)

    findings = [*private_result.findings, *public_result.findings]

    derived = keys.public_from_private(private)
    if not hmac.compare_digest(derived, bytes(public)):
        findings.append(
            WeakKeyFinding(
                check=WeakKeyCheck.CONSISTENCY,
                severity=WeakKeySeverity.CRITICAL,
                reason=(
                    "public key does not match the public key derived from the private "
                    "key (corruption or partial restore; see firmware issue #7449)"
                ),
                detail=f"derived={fingerprint(derived)}, reported={fingerprint(public)}",
                fingerprint=private_result.fingerprint,
                node_id=node_id,
                key_ref=key_ref,
            )
        )

    return AuditResult(
        findings=_sort_findings(findings),
        fingerprint=private_result.fingerprint,
        node_id=node_id,
        key_ref=key_ref,
    )


def audit_node(
    *,
    public: bytes | None = None,
    private: bytes | SecretBytes | None = None,
    node_id: str | None = None,
    key_ref: str | None = None,
    firmware_version: str | None = None,
    known_public_keys: Mapping[str, bytes] | None = None,
    known_bad: Collection[bytes] | None = None,
    check_clamping: bool = False,
) -> AuditResult:
    """The layered, top-level weak-key audit entry point for one node.

    Resolves the blocklist once and passes it down, so the on-disk file
    is read at most once per call. Runs the appropriate key-level audit,
    then layers on the firmware-version-window check and the cross-fleet
    duplicate check.

    Args:
        public: The node's raw 32-byte public key, when known.
        private: The node's private key (raw bytes or
            :class:`SecretBytes`), when known/held in custody.
        node_id: The node id, in display form, when known.
        key_ref: The key reference in the ``Keys`` sheet, when known.
        firmware_version: The node's reported firmware version string,
            when known.
        known_public_keys: Every other public key in the fleet, keyed by
            key reference, for cross-node duplicate detection. Entries
            whose ref equals ``key_ref`` are skipped (a node is not a
            duplicate of itself).
        known_bad: An explicit blocklist. When ``None``, loaded once via
            :func:`load_known_bad_keys`.
        check_clamping: Passed through to the private-key audit path.

    Returns:
        A single merged :class:`AuditResult`.

    Raises:
        KeyMaterialError: If neither ``public`` nor ``private`` is
            supplied, or if a supplied key is the wrong length.
    """
    if public is None and private is None:
        raise KeyMaterialError(
            "audit_node requires at least a public or a private key",
            reason="no key material supplied",
        )

    bad_set = known_bad if known_bad is not None else load_known_bad_keys()

    if public is not None and private is not None:
        result = audit_keypair(
            private,
            public,
            node_id=node_id,
            key_ref=key_ref,
            known_bad=bad_set,
            check_clamping=check_clamping,
        )
    elif public is not None:
        result = audit_public_key(public, node_id=node_id, key_ref=key_ref, known_bad=bad_set)
    elif private is not None:
        result = audit_private_key(
            private,
            node_id=node_id,
            key_ref=key_ref,
            known_bad=bad_set,
            check_clamping=check_clamping,
        )
    else:  # pragma: no cover - unreachable, guarded above
        raise KeyMaterialError(
            "audit_node requires at least a public or a private key",
            reason="no key material supplied",
        )

    findings = list(result.findings)

    if firmware_version is not None and firmware_version.strip():
        parsed = parse_firmware_version(firmware_version)
        if parsed is None:
            findings.append(
                WeakKeyFinding(
                    check=WeakKeyCheck.FIRMWARE_WINDOW,
                    severity=WeakKeySeverity.WARNING,
                    reason=(
                        "firmware version could not be parsed; the CVE-2025-52464 window "
                        "could not be evaluated"
                    ),
                    detail=f"firmware_version={firmware_version!r}",
                    fingerprint=result.fingerprint,
                    node_id=node_id,
                    key_ref=key_ref,
                )
            )
        elif is_vulnerable_firmware(parsed):
            findings.append(
                WeakKeyFinding(
                    check=WeakKeyCheck.FIRMWARE_WINDOW,
                    severity=WeakKeySeverity.CRITICAL,
                    reason=(
                        f"firmware {firmware_version} is inside the CVE-2025-52464 window "
                        "[2.5.0, 2.6.11); the key is presumptively compromised regardless "
                        "of its contents"
                    ),
                    fingerprint=result.fingerprint,
                    node_id=node_id,
                    key_ref=key_ref,
                )
            )

    if known_public_keys and public is not None:
        raw_public = bytes(public)
        matches = sorted(
            ref
            for ref, candidate in known_public_keys.items()
            if ref != key_ref and hmac.compare_digest(raw_public, bytes(candidate))
        )
        if matches:
            findings.append(
                WeakKeyFinding(
                    check=WeakKeyCheck.DUPLICATE,
                    severity=WeakKeySeverity.CRITICAL,
                    reason=(
                        "public key is shared with another node in this fleet -- the "
                        "CVE-2025-52464 vendor key-cloning failure mode"
                    ),
                    detail=f"matching_refs={', '.join(matches)}",
                    fingerprint=result.fingerprint,
                    node_id=node_id,
                    key_ref=key_ref,
                )
            )

    return AuditResult(
        findings=_sort_findings(findings),
        fingerprint=result.fingerprint,
        node_id=node_id,
        key_ref=key_ref,
    )
