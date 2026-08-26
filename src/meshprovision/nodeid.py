"""Canonical Meshtastic node-id value object.

Meshtastic node ids appear in the wild in four distinct forms:

- ``"!a0cb5cc4"`` -- the display form used by the Meshtastic apps and CLI.
- ``"a0cb5cc4"`` -- bare lowercase hex, the form lorastats.pl's ``NodeId``
  field uses and the exact form this project stores as the ``Nodes``
  sheet primary key.
- ``"2697256388"`` -- decimal, the form loranet.pl uses as the JSON key
  in its node dump.
- ``2697256388`` -- a plain Python ``int``, the form the ``meshtastic``
  protobufs use (including, from some JSON encoders, signed 32-bit
  negatives that are really an unsigned value in two's-complement).

:class:`NodeId` normalizes all four into one immutable, hashable,
orderable value object with round-trip-safe conversions between them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, TypeAlias

from meshprovision.errors import NodeIdError

__all__ = [
    "BROADCAST",
    "BROADCAST_NUM",
    "NODE_ID_HEX_WIDTH",
    "NODE_ID_MAX",
    "NodeId",
    "NodeIdLike",
]

NodeIdLike: TypeAlias = "str | int | NodeId"
"""Any value :meth:`NodeId.parse` can accept."""

NODE_ID_MAX: Final[int] = 0xFFFFFFFF
"""Largest value a 32-bit Meshtastic node id can hold."""

NODE_ID_HEX_WIDTH: Final[int] = 8
"""Width, in hex digits, of the zero-padded hex form of a node id."""

BROADCAST_NUM: Final[int] = 0xFFFFFFFF
"""The reserved broadcast node number (``!ffffffff``)."""

_HEX_DIGITS: Final[frozenset[str]] = frozenset("0123456789abcdef")

_FOUR_FORMS_HINT: Final = (
    "Accepted forms: '!a0cb5cc4' (display), 'a0cb5cc4' (bare hex), "
    "'2697256388' (decimal), or a plain int."
)


@dataclass(frozen=True, slots=True, order=True, repr=False)
class NodeId:
    """A canonical, normalized Meshtastic node id.

    Instances are immutable and hashable, and compare/order by their
    numeric value only -- this is what lets datasource code use
    ``dict[NodeId, NodeObservation]`` and sort status tables
    deterministically.

    Equality is defined by the dataclass against ``num`` only, and
    returns ``NotImplemented`` for any non-``NodeId`` operand, so
    ``NodeId(1) == 1`` is ``False``. Compare numeric values explicitly
    with ``int(node_id) == 1`` instead.

    Attributes:
        num: The node id as an unsigned 32-bit integer in
            ``[0, NODE_ID_MAX]``.
    """

    num: int

    def __post_init__(self) -> None:
        """Validate that ``num`` is a plain, in-range ``int``.

        Raises:
            NodeIdError: If ``num`` is not an ``int`` (booleans are
                explicitly rejected, since ``isinstance(True, int)`` is
                ``True``), or is outside ``[0, NODE_ID_MAX]``. Use
                :meth:`from_int` instead of the constructor to accept
                wrapping/masking of signed or out-of-range values.
        """
        if isinstance(self.num, bool) or not isinstance(self.num, int):
            raise NodeIdError(
                f"NodeId.num must be an int, got {type(self.num).__name__}", raw=self.num
            )
        if not (0 <= self.num <= NODE_ID_MAX):
            raise NodeIdError(
                f"NodeId.num out of range [0, {NODE_ID_MAX}]: {self.num}", raw=self.num
            )

    @property
    def hex(self) -> str:
        """Bare lowercase hex form, zero-padded to 8 digits, no prefix.

        Returns:
            For example ``"a0cb5cc4"``.
        """
        return f"{self.num:0{NODE_ID_HEX_WIDTH}x}"

    @property
    def display(self) -> str:
        """Display form used by the Meshtastic apps and CLI.

        Returns:
            For example ``"!a0cb5cc4"``.
        """
        return f"!{self.hex}"

    @property
    def decimal(self) -> str:
        """Decimal string form, the loranet.pl dump key form.

        Returns:
            For example ``"2697256388"``.
        """
        return str(self.num)

    @property
    def db_value(self) -> str:
        """The exact form stored as the ``Nodes`` sheet primary key.

        Returns:
            An alias of :attr:`hex`.
        """
        return self.hex

    @property
    def is_broadcast(self) -> bool:
        """Whether this id is the reserved broadcast address.

        Returns:
            ``True`` if ``num == BROADCAST_NUM``.
        """
        return self.num == BROADCAST_NUM

    @property
    def is_unset(self) -> bool:
        """Whether this id is the unset/zero id.

        Returns:
            ``True`` if ``num == 0``.
        """
        return self.num == 0

    @classmethod
    def from_int(cls, value: int) -> NodeId:
        """Build a :class:`NodeId` from a protobuf-style integer.

        Accepts signed 32-bit negatives as seen from some JSON encoders,
        converting them via two's complement.

        Args:
            value: An ``int`` in ``[-2**31, NODE_ID_MAX]``.

        Returns:
            The corresponding :class:`NodeId`.

        Raises:
            NodeIdError: If ``value`` is a ``bool``, is not an ``int``, or
                is outside the accepted range.
        """
        if isinstance(value, bool) or not isinstance(value, int):
            raise NodeIdError(
                f"NodeId.from_int expects an int, got {type(value).__name__}", raw=value
            )
        if -(2**31) <= value < 0:
            return cls(value & NODE_ID_MAX)
        if 0 <= value <= NODE_ID_MAX:
            return cls(value)
        raise NodeIdError(f"NodeId.from_int value out of range: {value}", raw=value)

    @classmethod
    def from_hex(cls, value: str) -> NodeId:
        """Build a :class:`NodeId` from a hex string.

        Tolerates a leading ``!``, a leading ``0x``/``0X``, surrounding
        whitespace, and any case; the token need not be zero-padded.

        Args:
            value: A hex string such as ``"!a0cb5cc4"``, ``"a0cb5cc4"``,
                ``"0xA0CB5CC4"``, or a short form like ``"5cc4"``.

        Returns:
            The corresponding :class:`NodeId`.

        Raises:
            NodeIdError: If the token is empty, non-ASCII, longer than 8
                hex digits, or contains a non-hex character.
        """
        if not isinstance(value, str):
            raise NodeIdError(
                f"NodeId.from_hex expects a str, got {type(value).__name__}", raw=value
            )
        token = value.strip()
        if token.startswith("!"):
            token = token[1:]
        if token[:2] in ("0x", "0X"):
            token = token[2:]
        token = token.lower()
        if not token or not token.isascii() or len(token) > NODE_ID_HEX_WIDTH:
            raise NodeIdError(f"Invalid hex node id: {value!r}", raw=value, hint=_FOUR_FORMS_HINT)
        if not set(token) <= _HEX_DIGITS:
            raise NodeIdError(f"Invalid hex node id: {value!r}", raw=value, hint=_FOUR_FORMS_HINT)
        return cls(int(token, 16))

    @classmethod
    def from_decimal(cls, value: str | int) -> NodeId:
        """Build a :class:`NodeId` from a decimal value.

        Args:
            value: An ``int`` (delegated to :meth:`from_int`) or a decimal
                string such as ``"2697256388"``.

        Returns:
            The corresponding :class:`NodeId`.

        Raises:
            NodeIdError: If ``value`` is a ``str`` that is empty,
                non-ASCII, contains non-digit characters (this rejects
                signs, underscores, decimal points, and non-ASCII digit
                characters such as Arabic-Indic numerals), or encodes a
                value outside ``[0, NODE_ID_MAX]``; or if ``value`` is
                neither ``int`` nor ``str``.
        """
        if isinstance(value, bool):
            raise NodeIdError(
                f"NodeId.from_decimal expects int or str, got {type(value).__name__}", raw=value
            )
        if isinstance(value, int):
            return cls.from_int(value)
        if not isinstance(value, str):
            raise NodeIdError(
                f"NodeId.from_decimal expects int or str, got {type(value).__name__}", raw=value
            )
        token = value.strip()
        if not token or not token.isascii() or not token.isdigit():
            raise NodeIdError(
                f"Invalid decimal node id: {value!r}", raw=value, hint=_FOUR_FORMS_HINT
            )
        num = int(token, 10)
        if not (0 <= num <= NODE_ID_MAX):
            raise NodeIdError(f"Decimal node id out of range: {value!r}", raw=value)
        return cls(num)

    @classmethod
    def from_display(cls, value: str) -> NodeId:
        """Build a :class:`NodeId` from the ``"!"``-prefixed display form.

        Args:
            value: A display-form string such as ``"!a0cb5cc4"``.

        Returns:
            The corresponding :class:`NodeId`.

        Raises:
            NodeIdError: If ``value`` (after stripping whitespace) does
                not start with ``"!"``, or the remainder is not valid hex.
        """
        if not isinstance(value, str):
            raise NodeIdError(
                f"NodeId.from_display expects a str, got {type(value).__name__}", raw=value
            )
        token = value.strip()
        if not token.startswith("!"):
            raise NodeIdError(
                f"Display-form node id must start with '!': {value!r}",
                raw=value,
                hint=_FOUR_FORMS_HINT,
            )
        return cls.from_hex(token)

    @classmethod
    def parse(cls, raw: NodeIdLike) -> NodeId:
        """Heuristically parse any of the four accepted node-id forms.

        This is the only heuristic entry point in this module; call sites
        that already know the source form (loranet decimal keys,
        lorastats bare hex, protobuf ints) should use the explicit
        constructor instead, since heuristics can be ambiguous.

        Resolution order:

        1. A :class:`NodeId` is returned unchanged.
        2. An ``int`` (not ``bool``) goes through :meth:`from_int`.
        3. A ``str`` is stripped and classified:

           a. A leading ``!`` -> :meth:`from_display`.
           b. A leading ``0x``/``0X`` -> :meth:`from_hex`.
           c. Exactly 8 characters, all hex digits -> :meth:`from_hex`.
              This deliberately wins over the decimal interpretation:
              an 8-character all-hex token is always treated as hex,
              because that is exactly the lorastats ``NodeId`` form,
              whereas decimal node numbers are 9-10 digits. This means
              ``"12345678"`` parses as hex ``0x12345678``
              (received as ``305419896``), *not* as decimal
              ``12,345,678`` -- a deliberate ambiguity call sites must
              be aware of.
           d. All ASCII digits -> :meth:`from_decimal`.
           e. 1-7 characters, all hex digits -> :meth:`from_hex`.
           f. Anything else raises :class:`NodeIdError`.

        4. Any other type raises :class:`NodeIdError`.

        Args:
            raw: A :class:`NodeId`, ``int``, or ``str`` in one of the
                four accepted forms.

        Returns:
            The corresponding :class:`NodeId`.

        Raises:
            NodeIdError: If ``raw`` cannot be classified into any of the
                accepted forms.
        """
        if isinstance(raw, NodeId):
            return raw
        if isinstance(raw, bool):
            raise NodeIdError(
                f"Cannot parse node id from {type(raw).__name__}", raw=raw, hint=_FOUR_FORMS_HINT
            )
        if isinstance(raw, int):
            return cls.from_int(raw)
        if isinstance(raw, str):
            token = raw.strip()
            if not token:
                raise NodeIdError("Cannot parse node id from empty string", raw=raw)
            if token.startswith("!"):
                return cls.from_display(token)
            if token[:2] in ("0x", "0X"):
                return cls.from_hex(token)
            if len(token) == NODE_ID_HEX_WIDTH and set(token.lower()) <= _HEX_DIGITS:
                return cls.from_hex(token)
            if token.isascii() and token.isdigit():
                return cls.from_decimal(token)
            if 1 <= len(token) < NODE_ID_HEX_WIDTH and set(token.lower()) <= _HEX_DIGITS:
                return cls.from_hex(token)
            raise NodeIdError(f"Cannot parse node id: {raw!r}", raw=raw, hint=_FOUR_FORMS_HINT)
        raise NodeIdError(
            f"Cannot parse node id from {type(raw).__name__}", raw=raw, hint=_FOUR_FORMS_HINT
        )

    @classmethod
    def try_parse(cls, raw: object) -> NodeId | None:
        """Parse ``raw`` like :meth:`parse`, returning ``None`` on failure.

        Accepts ``object`` so datasource code can feed untrusted JSON
        values (which may be of any type) directly.

        Args:
            raw: A candidate node-id value of any type.

        Returns:
            The parsed :class:`NodeId`, or ``None`` if ``raw`` could not
            be parsed.
        """
        try:
            return cls.parse(raw)  # type: ignore[arg-type]
        except NodeIdError:
            return None

    def __int__(self) -> int:
        """Return the numeric value.

        Returns:
            ``self.num``.
        """
        return self.num

    def __str__(self) -> str:
        """Return the display form.

        Returns:
            ``self.display``.
        """
        return self.display

    def __repr__(self) -> str:
        """Return an unambiguous, evaluable-looking representation.

        Returns:
            For example ``"NodeId('!a0cb5cc4')"``.
        """
        return f"NodeId({self.display!r})"


BROADCAST: Final[NodeId] = NodeId(BROADCAST_NUM)
"""The reserved broadcast :class:`NodeId` (``!ffffffff``)."""
