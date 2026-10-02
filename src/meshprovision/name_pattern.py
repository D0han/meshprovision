"""The ``{n}``-placeholder node-naming and capacity-planning engine.

:class:`PatternSpec` compiles a ``{n}``-placeholder pattern into
literal/slot segments without ever using ``str.format`` (an
operator-supplied pattern is not a trusted format string), computes the
namespace's capacity, and renders or parses names against it. Because
the Meshtastic firmware *silently truncates* an over-length name rather
than rejecting it, the byte-length limits below are enforced as hard
validation errors at template-load time, not a runtime surprise.

This module is a leaf: it depends only on :mod:`meshprovision.errors`
and the stdlib, so :mod:`meshprovision.db.nodes` (a ``db/`` module) can
import it without forming an upward ``db -> config`` dependency.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from meshprovision.errors import NamespaceExhaustedError, TemplateValidationError

__all__ = [
    "BASE36_ALPHABET",
    "DEFAULT_MIN_CAPACITY",
    "DEFAULT_WARN_UTILIZATION",
    "LONG_NAME_MAX_BYTES",
    "SHORT_NAME_MAX_BYTES",
    "SUFFIX_TOKEN",
    "PatternSpec",
    "TemplateWarning",
    "check_capacity_utilization",
    "ensure_capacity_available",
]

SHORT_NAME_MAX_BYTES: Final[int] = 4
"""Firmware limit on ``short_name``, in UTF-8 bytes. Silently truncated
past this length rather than rejected."""

LONG_NAME_MAX_BYTES: Final[int] = 25
"""Firmware limit on ``long_name``, in UTF-8 bytes. Silently truncated
past this length rather than rejected. Firmware 2.8 lowered this from
the earlier 39-byte limit; 25 is safe for both 2.7.x and 2.8+ devices,
since a name that fits in 25 bytes always fit in 39 too."""

BASE36_ALPHABET: Final[str] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"""Default ``name_suffix_alphabet``: the 36 upper-case base36 digits."""

SUFFIX_TOKEN: Final[str] = "{n}"  # noqa: S105 -- a placeholder token, not a password
"""The only placeholder token a name pattern may contain."""

DEFAULT_MIN_CAPACITY: Final[int] = 100
"""Default floor for :attr:`~meshprovision.config.template.TemplateConfig.name_min_capacity`."""

DEFAULT_WARN_UTILIZATION: Final[float] = 0.9
"""Default namespace-utilization ratio at which a warning is raised."""


@dataclass(frozen=True, slots=True)
class TemplateWarning:
    """A non-fatal finding surfaced by ``TemplateConfig.collect_warnings``.

    Attributes:
        code: Machine-readable warning code, one of
            ``"capacity_below_floor"``, ``"capacity_near_exhaustion"``,
            ``"unknown_option"``, or ``"long_name_near_limit"``.
        message: Human-readable description of the finding.
        field: Name of the associated template field, when known.
    """

    code: str
    message: str
    field: str | None = None


@dataclass(frozen=True, slots=True)
class PatternSpec:
    """A compiled ``{n}``-placeholder name pattern.

    Never uses ``str.format``/``str.format_map`` -- an operator-supplied
    pattern is treated as untrusted input, not a trusted format string --
    so compilation hand-scans the pattern instead.

    Attributes:
        pattern: The original, uncompiled pattern string.
        alphabet: The suffix alphabet; each character is one possible
            digit for a ``{n}`` slot.
        literals: The literal text segments surrounding each slot.
            Length is always ``slot_count + 1``: ``literals[i]`` precedes
            slot ``i``, and ``literals[-1]`` trails the final slot.
        field: Name of the template field this pattern came from, used
            to make error messages actionable.
    """

    pattern: str
    alphabet: str
    literals: tuple[str, ...]
    field: str

    @property
    def slot_count(self) -> int:
        """Return the number of ``{n}`` slots in the pattern.

        Returns:
            ``len(literals) - 1``.
        """
        return len(self.literals) - 1

    @property
    def capacity(self) -> int:
        """Return the total number of distinct names this pattern can render.

        Exact because :func:`_validate_alphabet` refuses an alphabet whose
        characters collide case-insensitively: names are compared by
        ``casefold()`` (see :func:`~meshprovision.db.nodes.find_next_free_name`),
        so ``"aA"`` would otherwise count two digits that only ever yield
        one usable name per slot value.

        Returns:
            ``len(alphabet) ** slot_count``.
        """
        return int(len(self.alphabet) ** self.slot_count)

    def render(self, index: int) -> str:
        """Render the name at the given index.

        Args:
            index: A zero-based index into the pattern's namespace.

        Returns:
            The rendered name: each ``{n}`` slot replaced by the
            base-``len(alphabet)`` digits of ``index``, most-significant
            first, zero-padded (with ``alphabet[0]``) to ``slot_count``
            digits.

        Raises:
            NamespaceExhaustedError: If ``index`` is negative or
                ``>= capacity``.
        """
        capacity = self.capacity
        if index < 0 or index >= capacity:
            raise NamespaceExhaustedError(
                f"Index {index} is out of range for pattern {self.pattern!r} "
                f"(capacity {capacity}).",
                pattern=self.pattern,
                capacity=capacity,
            )
        base = len(self.alphabet)
        digits: list[str] = []
        remaining = index
        for _ in range(self.slot_count):
            remaining, digit_index = divmod(remaining, base)
            digits.append(self.alphabet[digit_index])
        digits.reverse()
        parts: list[str] = [self.literals[0]]
        for slot_index, digit in enumerate(digits):
            parts.append(digit)
            parts.append(self.literals[slot_index + 1])
        return "".join(parts)

    def render_widest(self) -> str:
        """Render the widest-possible name (in UTF-8 bytes) this pattern can produce.

        Every slot is filled with whichever alphabet character encodes
        to the most UTF-8 bytes -- not necessarily the last character in
        the alphabet.

        Returns:
            The widest rendering.
        """
        widest_char = max(self.alphabet, key=lambda c: len(c.encode("utf-8")))
        parts: list[str] = [self.literals[0]]
        for slot_index in range(self.slot_count):
            parts.append(widest_char)
            parts.append(self.literals[slot_index + 1])
        return "".join(parts)

    def widest_byte_length(self) -> int:
        """Return the UTF-8 byte length of :meth:`render_widest`.

        Returns:
            The byte length of the widest possible rendering.
        """
        return len(self.render_widest().encode("utf-8"))

    def parse_index(self, name: str) -> int | None:
        """Recover the index that would render as ``name``, if any.

        The exact inverse of :meth:`render`: for every ``i`` in
        ``range(capacity)``, ``parse_index(render(i)) == i``.

        Args:
            name: A candidate rendered name.

        Returns:
            The recovered index, or ``None`` if ``name`` does not fit
            this pattern (wrong prefix, unknown alphabet character, or
            leftover text). Never raises.
        """
        pos = 0
        digits: list[int] = []
        for slot_index in range(self.slot_count):
            prefix = self.literals[slot_index]
            if not name.startswith(prefix, pos):
                return None
            pos += len(prefix)
            if pos >= len(name):
                return None
            digit_index = self.alphabet.find(name[pos])
            if digit_index == -1:
                return None
            digits.append(digit_index)
            pos += 1
        trailing = self.literals[-1]
        if not name.startswith(trailing, pos) or pos + len(trailing) != len(name):
            return None
        base = len(self.alphabet)
        value = 0
        for digit in digits:
            value = value * base + digit
        return value

    @classmethod
    def compile(cls, pattern: str, alphabet: str, *, field: str) -> PatternSpec:
        """Compile a ``{n}``-placeholder pattern against a suffix alphabet.

        Args:
            pattern: The pattern string. ``{n}`` is the only supported
                placeholder; a literal brace is written ``{{`` or ``}}``.
            alphabet: The suffix alphabet: non-empty, no duplicate
                characters (case-insensitively), no whitespace, and no
                ``{``/``}``.
            field: Name of the template field this pattern came from,
                used to make error messages actionable.

        Returns:
            The compiled :class:`PatternSpec`.

        Raises:
            TemplateValidationError: If ``pattern`` is empty, contains
                an unsupported placeholder or an unmatched brace, or if
                ``alphabet`` violates any of its rules.
        """
        _validate_alphabet(alphabet)
        if not pattern:
            raise TemplateValidationError(f"{field} must not be empty.", field=field)

        i = 0
        literal: list[str] = []
        literals: list[str] = []
        while i < len(pattern):
            if pattern.startswith("{{", i):
                literal.append("{")
                i += 2
            elif pattern.startswith("}}", i):
                literal.append("}")
                i += 2
            elif pattern.startswith(SUFFIX_TOKEN, i):
                literals.append("".join(literal))
                literal.clear()
                i += len(SUFFIX_TOKEN)
            elif pattern[i] == "{":
                raise TemplateValidationError(
                    f"Unsupported placeholder in {field}: {pattern!r}. The only "
                    "supported placeholder is '{n}'; write a literal brace as "
                    "'{{' or '}}'.",
                    field=field,
                )
            elif pattern[i] == "}":
                raise TemplateValidationError(
                    f"Unmatched '}}' in {field}: {pattern!r}.",
                    field=field,
                )
            else:
                literal.append(pattern[i])
                i += 1
        literals.append("".join(literal))

        return cls(pattern=pattern, alphabet=alphabet, literals=tuple(literals), field=field)


def _validate_alphabet(alphabet: str) -> None:
    """Validate a ``name_suffix_alphabet`` value.

    Args:
        alphabet: The candidate alphabet string.

    Raises:
        TemplateValidationError: If the alphabet is empty, contains
            duplicate characters, contains whitespace, contains
            ``{``/``}``, or fails :func:`_validate_alphabet_case_folding`.
    """
    if not alphabet:
        raise TemplateValidationError(
            "name_suffix_alphabet must not be empty.", field="name_suffix_alphabet"
        )
    seen: set[str] = set()
    duplicates: set[str] = set()
    for ch in alphabet:
        if ch in seen:
            duplicates.add(ch)
        seen.add(ch)
    if duplicates:
        dup_str = ", ".join(repr(c) for c in sorted(duplicates))
        raise TemplateValidationError(
            f"name_suffix_alphabet contains duplicate character(s): {dup_str}.",
            field="name_suffix_alphabet",
        )
    if any(ch.isspace() for ch in alphabet):
        raise TemplateValidationError(
            "name_suffix_alphabet must not contain whitespace.",
            field="name_suffix_alphabet",
        )
    if "{" in alphabet or "}" in alphabet:
        raise TemplateValidationError(
            "name_suffix_alphabet must not contain '{' or '}'.",
            field="name_suffix_alphabet",
        )
    _validate_alphabet_case_folding(alphabet)


def _validate_alphabet_case_folding(alphabet: str) -> None:
    """Refuse an alphabet whose characters are not distinct case-insensitively.

    Rendered names are compared by ``casefold()``
    (:func:`~meshprovision.db.nodes.find_next_free_name`), so two digits
    that fold to the same character render names that count as one, and
    :attr:`PatternSpec.capacity` would overstate the namespace. A
    character that folds to *several* characters (``"ß"`` -> ``"ss"``,
    the ligature ``"ﬁ"`` -> ``"fi"``) is refused too: its folded form can
    collide with a run of other digits across slot boundaries (``"ßs"``
    and ``"sß"`` both fold to ``"sss"``).

    Args:
        alphabet: The candidate alphabet, already free of exact duplicates.

    Raises:
        TemplateValidationError: If a character folds to more than one
            character, or two characters fold to the same one.
    """
    multi = [ch for ch in alphabet if len(ch.casefold()) != 1]
    if multi:
        listed = ", ".join(f"{ch!r} (-> {ch.casefold()!r})" for ch in multi)
        raise TemplateValidationError(
            "name_suffix_alphabet contains character(s) that case-fold to more than "
            f"one character: {listed}. Names are compared case-insensitively, so such "
            "a character can make two different suffixes collide.",
            field="name_suffix_alphabet",
        )
    first_by_fold: dict[str, str] = {}
    pairs: list[str] = []
    for ch in alphabet:
        first = first_by_fold.setdefault(ch.casefold(), ch)
        if first != ch:
            pairs.append(f"{first!r}/{ch!r}")
    if pairs:
        raise TemplateValidationError(
            "name_suffix_alphabet contains characters that differ only in case: "
            f"{', '.join(pairs)}. Names are compared case-insensitively, so each "
            "pair counts as a single suffix digit; keep one of each.",
            field="name_suffix_alphabet",
        )


def check_capacity_utilization(
    spec: PatternSpec, used: int, *, warn_at: float = DEFAULT_WARN_UTILIZATION
) -> TemplateWarning | None:
    """Check a pattern's namespace utilization against a warning threshold.

    Args:
        spec: The pattern to check.
        used: The number of names from ``spec``'s namespace currently in
            use (looked up in the database; not known at template-load
            time).
        warn_at: Utilization ratio (``used / spec.capacity``) at or above
            which a warning is returned.

    Returns:
        A ``"capacity_near_exhaustion"`` :class:`TemplateWarning` when
        utilization is at or above ``warn_at``; otherwise ``None``.

    Raises:
        ValueError: If ``used`` is negative.
    """
    if used < 0:
        raise ValueError("used must not be negative")
    ratio = used / spec.capacity
    if ratio >= warn_at:
        return TemplateWarning(
            "capacity_near_exhaustion",
            f"{used} of {spec.capacity} names used ({ratio:.0%}) for pattern {spec.pattern!r}.",
            field=spec.field,
        )
    return None


def ensure_capacity_available(spec: PatternSpec, used: int) -> None:
    """Raise if a pattern's namespace has no unused names left.

    Args:
        spec: The pattern to check.
        used: The number of names from ``spec``'s namespace currently in
            use.

    Raises:
        NamespaceExhaustedError: If ``used >= spec.capacity``.
    """
    if used >= spec.capacity:
        raise NamespaceExhaustedError(
            f"Name pattern {spec.pattern!r} is exhausted: all {spec.capacity} names "
            f"over the {len(spec.alphabet)}-character alphabet are in use.",
            pattern=spec.pattern,
            capacity=spec.capacity,
            hint=(
                "Widen name_suffix_alphabet or add another {n} slot to the pattern "
                "(mind the 4-byte short_name limit)."
            ),
        )
